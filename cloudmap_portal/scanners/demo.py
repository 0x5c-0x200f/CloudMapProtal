"""Synthetic AWS-shaped inventory so you can try the portal without credentials."""
from __future__ import annotations

import random

from .base import Emitter


def scan(em: Emitter, seed: int = 7) -> None:
    rnd = random.Random(seed)
    acct_num = "123456789012"
    em.scope.update({"accounts": [acct_num], "regions": ["eu-west-1", "us-east-1"], "demo": True})
    acct = em.node(f"aws:acct:{acct_num}", "account", "prod-main", None,
                   native_type="AWS::Account")

    roles = {n: em.node(f"aws:iam:role/{n}", "iam.role", n, acct, native_type="AWS::IAM::Role")
             for n in ("api-role", "worker-role", "etl-role")}
    buckets = [em.node(f"aws:s3:acme-{n}", "storage.bucket", f"acme-{n}", acct,
                       native_type="AWS::S3::Bucket") for n in ("assets", "logs", "backups")]

    for region in em.scope["regions"]:
        rid = em.node(f"aws:region:{acct_num}:{region}", "region", region, acct, region=region)
        p = region[:2]
        vpc = em.node(f"aws:vpc:vpc-{p}01", "network.vpc", f"main-{p}", rid, region=region,
                      native_type="AWS::EC2::VPC", props={"cidr": "10.0.0.0/16"},
                      tags={"env": "prod"})
        sg = {n: em.node(f"aws:sg:sg-{p}-{n}", "network.security_group", f"{n}-sg", vpc,
                         region=region, native_type="AWS::EC2::SecurityGroup",
                         props={"world_open_ports": ["443"]} if n == "web" else None)
              for n in ("web", "app", "db")}
        if region == "eu-west-1":  # a leftover group nothing uses
            em.node(f"aws:sg:sg-{p}-legacy", "network.security_group", "legacy-sg", vpc,
                    region=region, native_type="AWS::EC2::SecurityGroup")
        em.edge(sg["web"], sg["app"], "allows_traffic_to")
        em.edge(sg["app"], sg["db"], "allows_traffic_to")

        pub = [em.node(f"aws:subnet:subnet-{p}-pub{i}", "network.subnet", f"public-{i}", vpc,
                       region=region, native_type="AWS::EC2::Subnet",
                       props={"cidr": f"10.0.{i}.0/24"}) for i in (1, 2)]
        priv = [em.node(f"aws:subnet:subnet-{p}-prv{i}", "network.subnet", f"private-{i}", vpc,
                        region=region, native_type="AWS::EC2::Subnet",
                        props={"cidr": f"10.0.{i + 10}.0/24"}) for i in (1, 2)]

        web = []
        for i in range(4):
            iid = em.node(f"aws:ec2:i-{p}web{i}", "compute.instance", f"web-{i}",
                          pub[i % 2], region=region, native_type="AWS::EC2::Instance",
                          props={"size": rnd.choice(["t3.medium", "t3.large"]), "state": "running"},
                          tags={"env": "prod", "tier": "web"})
            em.edge(iid, sg["web"], "uses", "security group")
            em.edge(iid, roles["api-role"], "assumes")
            web.append(iid)
        for i in range(3):
            iid = em.node(f"aws:ec2:i-{p}app{i}", "compute.instance", f"app-{i}",
                          priv[i % 2], region=region, native_type="AWS::EC2::Instance",
                          props={"size": "m5.large", "state": "running"}, tags={"tier": "app"})
            em.edge(iid, sg["app"], "uses", "security group")
            em.edge(iid, roles["worker-role"], "assumes")

        if region == "eu-west-1":  # remote login open to the world on a jump host
            bsg = em.node(f"aws:sg:sg-{p}-bastion", "network.security_group", "bastion-sg", vpc,
                          region=region, native_type="AWS::EC2::SecurityGroup",
                          props={"world_open_ports": ["22"]}, tags={"env": "prod"})
            bi = em.node(f"aws:ec2:i-{p}bastion", "compute.instance", "bastion", pub[0], region=region,
                         native_type="AWS::EC2::Instance", props={"size": "t3.micro", "state": "running"},
                         tags={"env": "prod", "tier": "ops"})
            em.edge(bi, bsg, "uses", "security group")
            em.edge(bi, roles["worker-role"], "assumes")
        lb = em.node(f"aws:elb:alb-{p}", "network.load_balancer", f"public-alb-{p}", vpc,
                     region=region, native_type="AWS::ElasticLoadBalancingV2::LoadBalancer")
        for w in web:
            em.edge(lb, w, "routes_to")

        db = em.node(f"aws:rds:orders-{p}", "data.database", f"orders-{p}", vpc, region=region,
                     native_type="AWS::RDS::DBInstance",
                     props={"engine": "postgres", "class": "db.r5.large", "multi_az": region == "eu-west-1"})
        em.edge(db, sg["db"], "uses", "security group")

        for n in ("thumbnailer", "etl-nightly"):
            fid = em.node(f"aws:lambda:{n}-{p}", "compute.function", f"{n}-{p}", rid,
                          region=region, native_type="AWS::Lambda::Function",
                          props={"runtime": "python3.12", "memory_mb": 512})
            em.edge(fid, roles["etl-role" if "etl" in n else "worker-role"], "assumes",
                    "execution role")
            em.edge(fid, rnd.choice(buckets), "reads_from")
        em.error(f"{region}/collect_elasticache", "AccessDenied (demo of a partial scan)")


def scan_azure(em: Emitter) -> None:
    from . import azure, demo_rows
    from datetime import datetime
    now = datetime.fromisoformat(em.meta["scanned_at"].replace("Z", "+00:00"))
    containers, rows, kv = demo_rows.azure_data(now)
    azure.build(em, containers, rows, kv)
    em.scope["demo"] = True


def scan_gcp(em: Emitter) -> None:
    from . import demo_rows, gcp
    gcp.build(em, demo_rows.gcp_assets())
    em.scope["demo"] = True


def scan_provider(provider: str, em: Emitter) -> None:
    {"aws": scan, "azure": scan_azure, "gcp": scan_gcp}[provider](em)
