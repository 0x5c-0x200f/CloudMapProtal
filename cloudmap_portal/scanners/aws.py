"""AWS scanner (read-only). One collector per service; a failing collector is
recorded as an `error` record and never kills the scan.

Needs: pip install boto3
Permissions needed: `cloudmap-portal policy aws` prints a minimal read-only IAM policy.
Secrets are never collected: no Lambda env vars, no EC2 user-data.
"""
from __future__ import annotations

from .base import Emitter, sort_ports


def _tags(items) -> dict:
    return {t["Key"]: t["Value"] for t in (items or [])}


def _name(tags: dict, default: str) -> str:
    return tags.get("Name") or default


def _paginate(client, op: str, key: str, **kw):
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key, [])


def _world_open_ports(permissions) -> list[str]:
    """Ports reachable from 0.0.0.0/0 or ::/0, e.g. ['22', '443'] or ['all']."""
    ports = set()
    for p in permissions:
        world = (any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
                 or any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", [])))
        if not world:
            continue
        lo, hi = p.get("FromPort"), p.get("ToPort")
        if p.get("IpProtocol") == "-1" or lo is None:
            ports.add("all")
        else:
            ports.add(str(lo) if lo == hi else f"{lo}-{hi}")
    return sort_ports(ports)


# ---- global collectors ---------------------------------------------------
def collect_s3(session, em, acct):
    for b in session.client("s3").list_buckets().get("Buckets", []):
        em.node(f"aws:s3:{b['Name']}", "storage.bucket", b["Name"], acct,
                native_type="AWS::S3::Bucket",
                props={"created": b["CreationDate"].isoformat()})


def collect_iam_roles(session, em, acct):
    for r in _paginate(session.client("iam"), "list_roles", "Roles"):
        if r["Path"].startswith("/aws-service-role/"):
            continue  # service-linked roles are noise
        em.node(f"aws:iam:role/{r['RoleName']}", "iam.role", r["RoleName"], acct,
                native_type="AWS::IAM::Role", props={"arn": r["Arn"]})


# ---- regional collectors -------------------------------------------------
def collect_vpcs(session, em, region, region_id):
    for v in _paginate(session.client("ec2", region_name=region), "describe_vpcs", "Vpcs"):
        t = _tags(v.get("Tags"))
        em.node(f"aws:vpc:{v['VpcId']}", "network.vpc", _name(t, v["VpcId"]), region_id,
                native_type="AWS::EC2::VPC", region=region,
                props={"cidr": v["CidrBlock"]}, tags=t)


def collect_subnets(session, em, region, region_id):
    for s in _paginate(session.client("ec2", region_name=region), "describe_subnets", "Subnets"):
        t = _tags(s.get("Tags"))
        em.node(f"aws:subnet:{s['SubnetId']}", "network.subnet", _name(t, s["SubnetId"]),
                f"aws:vpc:{s['VpcId']}", native_type="AWS::EC2::Subnet", region=region,
                props={"cidr": s["CidrBlock"], "az": s["AvailabilityZone"]}, tags=t)


def collect_security_groups(session, em, region, region_id):
    for g in _paginate(session.client("ec2", region_name=region), "describe_security_groups",
                       "SecurityGroups"):
        t = _tags(g.get("Tags"))
        gid = f"aws:sg:{g['GroupId']}"
        props = {"inbound_rules": len(g["IpPermissions"])}
        world = _world_open_ports(g["IpPermissions"])
        if world:
            props["world_open_ports"] = world
        em.node(gid, "network.security_group", g["GroupName"], f"aws:vpc:{g['VpcId']}",
                native_type="AWS::EC2::SecurityGroup", region=region, props=props, tags=t)
        for perm in g["IpPermissions"]:  # sg -> sg references ("allows traffic from")
            for pair in perm.get("UserIdGroupPairs", []):
                em.edge(f"aws:sg:{pair['GroupId']}", gid, "allows_traffic_to")


def collect_instances(session, em, region, region_id):
    ec2 = session.client("ec2", region_name=region)
    for res in _paginate(ec2, "describe_instances", "Reservations"):
        for i in res["Instances"]:
            if i["State"]["Name"] == "terminated":
                continue
            t = _tags(i.get("Tags"))
            iid = f"aws:ec2:{i['InstanceId']}"
            em.node(iid, "compute.instance", _name(t, i["InstanceId"]),
                    f"aws:subnet:{i['SubnetId']}" if i.get("SubnetId") else region_id,
                    native_type="AWS::EC2::Instance", region=region,
                    props={"size": i["InstanceType"], "state": i["State"]["Name"],
                           "private_ip": i.get("PrivateIpAddress")}, tags=t)
            for g in i.get("SecurityGroups", []):
                em.edge(iid, f"aws:sg:{g['GroupId']}", "uses", "security group")


def collect_rds(session, em, region, region_id):
    for d in _paginate(session.client("rds", region_name=region), "describe_db_instances",
                       "DBInstances"):
        vpc = d.get("DBSubnetGroup", {}).get("VpcId")
        did = f"aws:rds:{d['DBInstanceIdentifier']}"
        em.node(did, "data.database", d["DBInstanceIdentifier"],
                f"aws:vpc:{vpc}" if vpc else region_id, native_type="AWS::RDS::DBInstance",
                region=region, props={"engine": d["Engine"], "class": d["DBInstanceClass"],
                                      "multi_az": d.get("MultiAZ", False)})
        for g in d.get("VpcSecurityGroups", []):
            em.edge(did, f"aws:sg:{g['VpcSecurityGroupId']}", "uses", "security group")


def collect_lambdas(session, em, region, region_id):
    for fn in _paginate(session.client("lambda", region_name=region), "list_functions",
                        "Functions"):
        fid = f"aws:lambda:{fn['FunctionName']}"
        vpc_cfg = fn.get("VpcConfig") or {}
        subnets = vpc_cfg.get("SubnetIds", [])
        # Parent = the VPC of a subnet we actually collected; fall back to the region.
        first = em.get(f"aws:subnet:{subnets[0]}") if subnets else None
        parent = first["parent"] if first else region_id
        em.node(fid, "compute.function", fn["FunctionName"], parent,
                native_type="AWS::Lambda::Function", region=region,
                props={"runtime": fn.get("Runtime"), "memory_mb": fn["MemorySize"]})
        em.edge(fid, f"aws:iam:role/{fn['Role'].split('/')[-1]}", "assumes", "execution role")
        for s in subnets:
            em.edge(fid, f"aws:subnet:{s}", "attached_to")
        for g in vpc_cfg.get("SecurityGroupIds", []):
            em.edge(fid, f"aws:sg:{g}", "uses", "security group")


def collect_load_balancers(session, em, region, region_id):
    elb = session.client("elbv2", region_name=region)
    for lb in _paginate(elb, "describe_load_balancers", "LoadBalancers"):
        lid = f"aws:elb:{lb['LoadBalancerName']}"
        vpc = f"aws:vpc:{lb['VpcId']}" if lb.get("VpcId") else None
        em.node(lid, "network.load_balancer", lb["LoadBalancerName"],
                vpc if vpc and em.get(vpc) else region_id,
                native_type="AWS::ElasticLoadBalancingV2::LoadBalancer", region=region,
                props={"scheme": lb.get("Scheme"), "type": lb.get("Type")})
        for g in lb.get("SecurityGroups", []):
            em.edge(lid, f"aws:sg:{g}", "uses", "security group")
        for tg in elb.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"]).get("TargetGroups", []):
            health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            for t in health.get("TargetHealthDescriptions", []):
                if t["Target"]["Id"].startswith("i-"):   # instance targets; IP/Lambda targets: later
                    em.edge(lid, f"aws:ec2:{t['Target']['Id']}", "routes_to")


GLOBAL = (collect_s3, collect_iam_roles)
REGIONAL = (collect_vpcs, collect_subnets, collect_security_groups, collect_instances,
            collect_rds, collect_lambdas, collect_load_balancers)


def scan(em: Emitter, profile: str | None = None, regions: list[str] | None = None,
         progress=None) -> None:
    say = progress or (lambda _msg: None)
    try:
        import boto3
    except ImportError as e:
        raise SystemExit('boto3 is required: pip install boto3') from e

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    try:
        acct_num = session.client("sts").get_caller_identity()["Account"]
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"Could not authenticate to AWS ({type(e).__name__}). Pass --profile NAME "
                         "or set AWS_PROFILE / AWS credentials, then try again.") from e
    acct = em.node(f"aws:acct:{acct_num}", "account", acct_num, None,
                   native_type="AWS::Account")
    regions = regions or [session.region_name or "us-east-1"]
    em.scope.update({"accounts": [acct_num], "regions": regions})
    say(f"Account {acct_num}; scanning {', '.join(regions)}")

    for collector in GLOBAL:
        say(f"  global: {collector.__name__[8:]}")
        try:
            collector(session, em, acct)
        except Exception as e:  # noqa: BLE001 - partial scans are a feature
            em.error(f"global/{collector.__name__}", f"{type(e).__name__}: {e}")
    for region in regions:
        region_id = em.node(f"aws:region:{acct_num}:{region}", "region", region, acct,
                            region=region)
        for collector in REGIONAL:
            say(f"  {region}: {collector.__name__[8:]}")
            try:
                collector(session, em, region, region_id)
            except Exception as e:  # noqa: BLE001
                em.error(f"{region}/{collector.__name__}", f"{type(e).__name__}: {e}")
