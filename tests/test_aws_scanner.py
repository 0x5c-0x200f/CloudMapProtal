"""Runs the real AWS collectors against moto (a fake AWS): no credentials, no network."""
import io
import json
import os
import zipfile

import pytest

pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")
from moto import mock_aws  # noqa: E402

from cloudmap_portal.scanners import aws  # noqa: E402
from cloudmap_portal.scanners.base import Emitter  # noqa: E402
from cloudmap_portal.schema import Inventory  # noqa: E402

REGION = "eu-west-1"


@pytest.fixture(autouse=True)
def fake_creds(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def build_account():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc], Tags=[{"Key": "Name", "Value": "main"}, {"Key": "env", "Value": "prod"}])
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    sub2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone=f"{REGION}b")["Subnet"]["SubnetId"]
    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    db = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": web}]}])
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    inst = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", SubnetId=sub,
                             SecurityGroupIds=[web],
                             UserData="SECRET_TOKEN=hunter2",
                             TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "api-1"}]}]
                             )["Instances"][0]["InstanceId"]

    iam = boto3.client("iam")
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    role_arn = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=trust, Path="/team/")["Role"]["Arn"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c): return 1")
    lam = boto3.client("lambda", region_name=REGION)
    lam.create_function(FunctionName="thumb", Runtime="python3.12", Role=role_arn, Handler="index.handler",
                        Code={"ZipFile": buf.getvalue()}, MemorySize=256,
                        Environment={"Variables": {"DB_PASSWORD": "hunter2"}},
                        VpcConfig={"SubnetIds": [sub], "SecurityGroupIds": [web]})

    boto3.client("s3", region_name=REGION).create_bucket(
        Bucket="acme-assets", CreateBucketConfiguration={"LocationConstraint": REGION})

    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_subnet_group(DBSubnetGroupName="g", DBSubnetGroupDescription="g", SubnetIds=[sub, sub2])
    rds.create_db_instance(DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="u", MasterUserPassword="password123", AllocatedStorage=20,
                           DBSubnetGroupName="g", VpcSecurityGroupIds=[db], MultiAZ=False)

    elb = boto3.client("elbv2", region_name=REGION)
    lb = elb.create_load_balancer(Name="public-alb", Subnets=[sub, sub2], SecurityGroups=[web], Scheme="internet-facing")["LoadBalancers"][0]
    tg = elb.create_target_group(Name="web-tg", Protocol="HTTP", Port=80, VpcId=vpc, TargetType="instance")["TargetGroups"][0]
    elb.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": inst}])
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    return dict(vpc=vpc, sub=sub, web=web, db=db, inst=inst)


def run_scan():
    em = Emitter("aws", "moto1", scanned_at="2026-10-06T09:00:00Z")
    aws.scan(em, regions=[REGION])
    return em, Inventory.load(json.dumps(r) for r in em.records())


@mock_aws
def test_scan_builds_structure_and_references():
    ids = build_account()
    em, inv = run_scan()
    assert not inv.errors, inv.errors
    assert not inv.warnings, inv.warnings            # no dangling parents or edges
    kinds = {n["kind"] for n in inv.nodes.values()}
    assert {"account", "region", "network.vpc", "network.subnet", "network.security_group",
            "compute.instance", "compute.function", "data.database", "storage.bucket",
            "iam.role", "network.load_balancer"} <= kinds

    inst = inv.nodes[f"aws:ec2:{ids['inst']}"]
    assert inst["name"] == "api-1" and inst["parent"] == f"aws:subnet:{ids['sub']}"
    edges = {(e["from"], e["to"], e["rel"]) for e in inv.edges}
    assert (inst["id"], f"aws:sg:{ids['web']}", "uses") in edges
    assert ("aws:lambda:thumb", "aws:iam:role/fn-role", "assumes") in edges   # role with a path
    assert ("aws:lambda:thumb", f"aws:subnet:{ids['sub']}", "attached_to") in edges
    assert ("aws:rds:orders", f"aws:sg:{ids['db']}", "uses") in edges
    assert (f"aws:sg:{ids['web']}", f"aws:sg:{ids['db']}", "allows_traffic_to") in edges
    assert ("aws:elb:public-alb", inst["id"], "routes_to") in edges
    assert inv.nodes["aws:rds:orders"]["parent"] == f"aws:vpc:{ids['vpc']}"
    assert inv.nodes[f"aws:vpc:{ids['vpc']}"]["tags"]["env"] == "prod"


@mock_aws
def test_scan_never_collects_secrets():
    build_account()
    em, _ = run_scan()
    blob = "\n".join(json.dumps(r) for r in em.records())
    assert "hunter2" not in blob and "SECRET_TOKEN" not in blob and "password123" not in blob


@mock_aws
def test_world_open_ports_are_recorded():
    ids = build_account()
    _, inv = run_scan()
    assert inv.nodes[f"aws:sg:{ids['web']}"]["props"]["world_open_ports"] == ["22", "443"]
    assert "world_open_ports" not in inv.nodes[f"aws:sg:{ids['db']}"].get("props", {})


@mock_aws
def test_failing_collector_becomes_an_error_record(monkeypatch):
    build_account()
    def boom(*a, **k):
        raise RuntimeError("AccessDenied: not allowed")
    monkeypatch.setattr(aws, "REGIONAL", tuple(boom if c.__name__ == "collect_rds" else c for c in aws.REGIONAL))
    em, inv = run_scan()
    assert any("AccessDenied" in e["message"] for e in inv.errors)
    assert "compute.instance" in {n["kind"] for n in inv.nodes.values()}   # the rest still scanned


@mock_aws
def test_cli_scan_end_to_end(tmp_path, capsys):
    from cloudmap_portal import cli
    build_account()
    rc = cli.main(["scan", "--provider", "aws", "--regions", REGION, "--out", str(tmp_path), "--scan-id", "e2e"])
    out = capsys.readouterr()
    assert rc == 0 and "wrote" in out.out and "orders" not in out.out
    assert "global: s3" in out.err and f"{REGION}: rds" in out.err        # progress goes to stderr
    f = next(tmp_path.glob("aws-e2e-*.jsonci"))
    inv = Inventory.load_path(f)
    from cloudmap_portal.insights import analyze
    ids = {x["id"] for x in analyze(inv)["findings"]}
    assert "exposed-ports" in ids and "single-az" in ids                   # real scan feeds real insights


def test_policy_command_prints_valid_json(capsys):
    from cloudmap_portal import cli
    assert cli.main(["policy", "aws"]) == 0
    pol = json.loads(capsys.readouterr().out)
    actions = pol["Statement"][0]["Action"]
    assert "ec2:DescribeInstances" in actions and not any(a.endswith("*") for a in actions)
    assert all(a.split(":")[1].startswith(("Describe", "List")) for a in actions)   # read-only
    for provider in ("azure", "gcp"):                                   # role-based clouds print guidance
        assert cli.main(["policy", provider]) == 0
        g = json.loads(capsys.readouterr().out)
        assert g["provider"] == provider and g["role"] in ("Reader", "roles/cloudasset.viewer")


def test_missing_credentials_gives_a_clear_message(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    with pytest.raises(SystemExit) as e:
        aws.scan(Emitter("aws", "x"), regions=[REGION])
    assert "Could not authenticate" in str(e.value)
