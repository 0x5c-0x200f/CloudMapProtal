"""Rule packs. Every rule is a function (ctx) -> list[Hit]; the registry knows its metadata.

Honesty rules: a rule only fires on evidence present in the scan, and says how sure it is.
`confidence` is high when the scan shows the fact directly, medium when it is inferred from
relationships (which may miss data-plane links), low when it is a prompt to go and look.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .ctx import (ADMIN_PORTS, DB_PORTS, WORKLOAD_KINDS, WRITE_PERMS, covers, norm_env, rg_of)

RULES: list = []


@dataclass
class Hit:
    resources: list
    detail: str = ""                 # one line of evidence, shown under the finding
    items: list = field(default_factory=list)
    cli: list = field(default_factory=list)
    severity: str | None = None      # overrides the rule default when the evidence warrants it


def rule(rid, category, severity, title, skills, confidence="high", providers=None, why="", fix="", refs=()):
    def deco(fn):
        RULES.append({"id": rid, "category": category, "severity": severity, "title": title,
                      "skills": list(skills), "confidence": confidence, "providers": providers,
                      "why": why, "fix": fix, "refs": list(refs), "fn": fn})
        return fn
    return deco


def _now():
    return datetime.now(timezone.utc)


def _when(v):
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def ids(nodes):
    return [n["id"] for n in nodes]


# =====================================================================================
# UNUSED
# =====================================================================================
@rule("unused-network-group", "unused", "low", "Network access group that nothing uses", ["devsec", "aws", "azure", "gcp"],
      confidence="medium",
      why="Nothing in the scan is attached to or references it. Unused groups clutter audits and are often left with permissive rules.",
      fix="Confirm it is not referenced by something the scan can't see (a template, another account), then delete it.")
def _orphan_sg(c):
    hits = [n for n in c.kinds("network.security_group") if c.provider != "gcp" and c.degree(n["id"]) == 0]
    if not hits:
        return []
    cli = []
    for n in hits[:5]:
        if c.provider == "aws":
            cli.append(f"aws ec2 delete-security-group --group-id {n['name']}")
        else:
            cli.append(f"az network nsg delete -g {rg_of(n) or '<rg>'} -n {n['name']}")
    return [Hit(ids(hits), cli=cli)]


@rule("unused-public-ip", "unused", "medium", "Public IP address not attached to anything", ["azure", "aws", "devsec"],
      why="An unattached public IP is billed, can be hijacked by dangling DNS records, and signals leftover infrastructure.",
      fix="Release it if nothing needs it.")
def _free_ip(c):
    hits = [n for n in c.kinds("network.public_ip") if c.degree(n["id"]) == 0]
    return [Hit(ids(hits), cli=[f"az network public-ip delete -g {rg_of(n) or '<rg>'} -n {n['name']}" for n in hits[:5]])] if hits else []


@rule("unused-nic", "unused", "low", "Network interface not attached to a machine", ["azure", "aws"],
      confidence="medium", why="Detached interfaces keep private IPs and NSG associations alive for nothing.",
      fix="Delete the interface or re-attach it.")
def _free_nic(c):
    hits = [n for n in c.kinds("network.interface")
            if not [e for e in c.inn(n["id"]) if c.nodes[e["from"]]["kind"] in WORKLOAD_KINDS]
            and not [e for e in c.out(n["id"]) if c.nodes[e["to"]]["kind"] in WORKLOAD_KINDS]]
    return [Hit(ids(hits))] if hits else []


@rule("unused-plan", "unused", "medium", "App hosting plan with no apps", ["azure", "integration"],
      why="You pay for the plan's compute whether or not any app runs on it.",
      fix="Delete the plan, or scale it to the free tier.")
def _empty_plan(c):
    hits = [n for n in c.kinds("compute.plan") if not c.inn(n["id"], "runs_on")]
    return [Hit(ids(hits), cli=[f"az appservice plan delete -g {rg_of(n) or '<rg>'} -n {n['name']}" for n in hits[:5]])] if hits else []


@rule("unused-lb-no-backends", "unused", "medium", "Load balancer without backends", ["aws", "azure", "gcp", "integration"],
      confidence="medium", why="It routes to nothing the scan can see. It still costs money and holds a public endpoint.",
      fix="Remove it, or attach the intended targets.")
def _lb_empty(c):
    hits = [n for n in c.kinds("network.load_balancer") if not c.out(n["id"], "routes_to")]
    return [Hit(ids(hits))] if hits else []


@rule("unused-stopped-compute", "unused", "low", "Machines that are stopped but still exist", ["aws", "azure", "gcp"],
      why="Stopped machines still bill for disks and addresses, and are forgotten until someone patches them back on.",
      fix="Snapshot and delete anything not needed; schedule the rest.")
def _stopped(c):
    bad = {"stopped", "deallocated", "terminated", "suspended", "stopping", "shutdown"}
    hits = [n for n in c.kinds("compute.instance") if str(c.p(n, "state", c.p(n, "status", ""))).lower() in bad]
    return [Hit(ids(hits))] if hits else []


@rule("unused-identity", "unused", "medium", "Identities that no workload uses", ["devsec", "aws", "azure", "gcp"],
      confidence="medium",
      why="Nothing in the scan assumes them. Idle identities keep their permissions and are prime targets for takeover.",
      fix="Check last-used data (IAM credential report / sign-in logs / SA key age), then delete or disable.")
def _idle_identity(c):
    hits = [n for n in c.kinds("iam.role", "iam.identity") if not c.inn(n["id"], "assumes")]
    return [Hit(ids(hits))] if hits else []


@rule("unused-empty-subnet", "unused", "low", "Subnets with nothing in them", ["aws", "azure", "gcp"],
      confidence="medium", why="Empty subnets use address space and may carry stale route or firewall associations.",
      fix="Remove them, or keep one intentionally for growth and tag it.")
def _empty_subnet(c):
    hits = [n for n in c.kinds("network.subnet")
            if not c.inv.children.get(n["id"])
            and not [e for e in c.inn(n["id"]) if c.nodes[e["from"]]["kind"] != "network.security_group"]]
    return [Hit(ids(hits))] if hits else []


@rule("unused-vault", "unused", "low", "Key vault nobody reads from", ["azure", "integration"], confidence="medium",
      providers=["azure"], why="No workload references a secret or key in it and nothing is encrypted with it.",
      fix="Review whether it is still needed; empty vaults can be deleted (mind purge protection).")
def _idle_vault(c):
    hits = []
    for v in c.kinds("iam.vault"):
        items = [x for x in c.inv.children.get(v["id"], []) if x in c.nodes]
        used = c.inn(v["id"], "reads_secret", "encrypted_with", "uses") or any(
            c.inn(i, "reads_secret", "encrypted_with", "uses") for i in items)
        if not used:
            hits.append(v)
    return [Hit(ids(hits))] if hits else []


@rule("unused-secret-stale", "unused", "low", "Expired or disabled secrets and keys", ["azure", "devsec"],
      why="Dead credentials add noise and sometimes still work. Anything that still references them is already failing.",
      fix="Delete them once nothing references them (see the integration findings).")
def _dead_items(c):
    now, hits = _now(), []
    for n in c.kinds("iam.secret", "iam.key", "iam.certificate"):
        exp = _when(c.p(n, "expires"))
        if c.p(n, "enabled") is False or (exp and exp < now):
            if not c.inn(n["id"], "reads_secret", "encrypted_with"):
                hits.append(n)
    return [Hit(ids(hits))] if hits else []


@rule("unused-isolated", "unused", "note", "Resources with no relationships at all", ["devsec", "integration"],
      confidence="low",
      why="Nothing references them and they reference nothing. Often leftovers, but data-plane use (DNS, app config) is invisible to the scan.",
      fix="Check last activity (metrics, flow logs) before deleting.")
def _isolated(c):
    skip = {"network.vpc", "network.subnet", "network.security_group", "network.public_ip", "network.interface",
            "compute.plan", "iam.secret", "iam.key", "iam.certificate", "iam.role", "iam.identity", "iam.vault",
            "network.load_balancer"}
    hits = [n for n in c.things if n["kind"] not in skip and c.degree(n["id"]) == 0
            and n["kind"].split(".")[0] in ("compute", "data", "storage")]
    return [Hit(ids(hits))] if hits else []


# =====================================================================================
# SECURITY
# =====================================================================================
def _open_ports_rule(c, ports, label, severity_ports):
    hits, items = [], []
    for n in c.things:
        ranges = c.world_open(n)
        if not ranges:
            continue
        found = covers(ranges, severity_ports)
        if found:
            hits.append(n)
            items.append(f"{n['name']}: {', '.join(map(str, found)) or 'all ports'}")
    return hits, items


def _fix_open(c, n, port):
    if c.provider == "aws":
        return f"aws ec2 revoke-security-group-ingress --group-id {n['name']} --protocol tcp --port {port} --cidr 0.0.0.0/0"
    if c.provider == "azure":
        return f"az network nsg rule update -g {rg_of(n) or '<rg>'} --nsg-name {n['name']} -n <rule> --source-address-prefixes <your-office-cidr>"
    if c.provider == "gcp" and n["kind"] == "data.database":
        return f"gcloud sql instances patch {n['name']} --clear-authorized-networks"
    return f"gcloud compute firewall-rules update {n['name']} --source-ranges=<your-office-cidr>"


@rule("sec-admin-ports-world", "security", "high", "SSH/RDP open to the whole internet", ["devsec", "aws", "azure", "gcp"],
      why="Remote-admin ports reachable from anywhere are scanned and brute-forced within minutes of exposure.",
      fix="Restrict the source to a VPN/office range, or remove public access and use a bastion (SSM Session Manager, Azure Bastion/JIT, IAP).",
      refs=["CIS AWS 5.2", "CIS Azure 6.1/6.2", "CIS GCP 3.6/3.7"])
def _admin_world(c):
    hits, items = _open_ports_rule(c, ADMIN_PORTS, "admin", ADMIN_PORTS)
    return [Hit(ids(hits), items=items, cli=[_fix_open(c, n, 22) for n in hits[:5]])] if hits else []


@rule("sec-db-ports-world", "security", "high", "Database ports open to the whole internet", ["devsec", "aws", "azure", "gcp"],
      why="Databases should never accept connections from 0.0.0.0/0. A leaked password or an unpatched engine becomes a breach.",
      fix="Remove the public rule; connect through private endpoints, peering or a proxy with IAM auth.",
      refs=["CIS AWS 5.2", "CIS GCP 6.5"])
def _db_world(c):
    hits, items = _open_ports_rule(c, DB_PORTS, "db", DB_PORTS)
    hits = [h for h in hits if not covers(c.world_open(h), ADMIN_PORTS) or covers(c.world_open(h), DB_PORTS)]
    return [Hit(ids(hits), items=items, cli=[_fix_open(c, n, 5432) for n in hits[:5]])] if hits else []


@rule("sec-other-ports-world", "security", "medium", "Other ports open to the whole internet", ["devsec", "aws", "azure", "gcp"],
      confidence="high", why="Only ports that must serve the public (usually 80/443) should be open to everyone.",
      fix="Narrow each rule to the required source ranges. Keep 80/443 only on load balancers or gateways.")
def _other_world(c):
    hits, items = [], []
    sensitive = ADMIN_PORTS | DB_PORTS
    for n in c.things:
        ranges = c.world_open(n)
        if not ranges or covers(ranges, sensitive) or any(a == 0 and b == 65535 for a, b in ranges):
            continue
        odd = [p for p in {x for a, b in ranges for x in (a, b)} if p not in (80, 443, 8080, 8443)]
        if odd:
            hits.append(n)
            items.append(f"{n['name']}: {', '.join(str(p) for p in sorted(odd))}")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("sec-all-ports-world", "security", "high", "Every port open to the internet", ["devsec", "aws", "azure", "gcp"],
      why="An any/any inbound rule removes the network as a defence entirely.",
      fix="Delete the rule and add back only the ports that need it, from the ranges that need it.")
def _all_world(c):
    hits = [n for n in c.things if any(a == 0 and b == 65535 for a, b in c.world_open(n))]
    return [Hit(ids(hits), cli=[_fix_open(c, n, "0-65535") for n in hits[:5]])] if hits else []


@rule("sec-public-storage", "security", "high", "Storage that allows anonymous public access", ["devsec", "azure", "aws", "gcp"],
      why="Anyone on the internet can read blobs/objects in an exposed container or bucket without credentials.",
      fix="Disable public access at the account level, then re-enable per container only where publishing is intended.",
      refs=["CIS Azure 3.7", "CIS AWS 2.1.4", "CIS GCP 5.1"])
def _public_storage(c):
    hits = [n for n in c.things if c.p(n, "allows_public_blobs") is True or c.p(n, "public_access") is True]
    cli = []
    for n in hits[:5]:
        if c.provider == "azure":
            cli.append(f"az storage account update -g {rg_of(n) or '<rg>'} -n {n['name']} --allow-blob-public-access false")
        elif c.provider == "aws":
            cli.append(f"aws s3api put-public-access-block --bucket {n['name']} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
        else:
            cli.append(f"gcloud storage buckets update gs://{n['name']} --public-access-prevention")
    return [Hit(ids(hits), cli=cli)] if hits else []


@rule("sec-no-https", "security", "high", "Plain HTTP still allowed", ["devsec", "azure"],
      providers=["azure"], why="Traffic (and tokens in it) can be read or altered in transit.",
      fix="Enforce HTTPS-only / secure transfer.")
def _no_https(c):
    hits = [n for n in c.things if c.p(n, "https_only") is False]
    cli = []
    for n in hits[:5]:
        if n["kind"] == "storage.account":
            cli.append(f"az storage account update -g {rg_of(n) or '<rg>'} -n {n['name']} --https-only true")
        else:
            cli.append(f"az webapp update -g {rg_of(n) or '<rg>'} -n {n['name']} --https-only true")
    return [Hit(ids(hits), cli=cli)] if hits else []


@rule("sec-public-data-plane", "security", "high", "Data services reachable over the public network", ["devsec", "azure", "gcp"],
      confidence="high", why="Databases, vaults and storage with public network access on rely on credentials alone.",
      fix="Switch to private endpoints / private IP and disable public network access.")
def _public_data(c):
    hits = [n for n in c.things if str(c.p(n, "public_network", "")).lower() in ("enabled", "true")
            and (n["kind"].startswith(("data.", "storage")) or n["kind"] == "iam.vault")]
    cli = []
    for n in hits[:5]:
        if n["kind"] == "iam.vault":
            cli.append(f"az keyvault update -n {n['name']} --public-network-access Disabled")
        elif n["kind"] == "data.server":
            cli.append(f"az sql server update -g {rg_of(n) or '<rg>'} -n {n['name']} --enable-public-network false")
    return [Hit(ids(hits), cli=cli)] if hits else []


@rule("sec-external-ip", "security", "medium", "Machines with public IP addresses", ["gcp", "aws", "devsec"],
      confidence="high", why="Every directly addressable machine is attack surface. Most should sit behind a load balancer or NAT.",
      fix="Remove the external address and use Cloud NAT / NAT gateway for egress and IAP / SSM for admin.")
def _ext_ip(c):
    hits = [n for n in c.kinds("compute.instance") if c.p(n, "external_ip") is True]
    cli = [f"gcloud compute instances delete-access-config {n['name']} --access-config-name=\"External NAT\" --zone {c.p(n, 'zone') or '<zone>'}"
           for n in hits[:5]] if c.provider == "gcp" else []
    return [Hit(ids(hits), cli=cli)] if hits else []


@rule("sec-open-ingress-app", "security", "medium", "Serverless apps open to all ingress", ["gcp", "devsec"],
      providers=["gcp"], why="Cloud Run services with ingress=all are reachable from anywhere unless authentication is enforced.",
      fix="Set ingress to internal / load-balancer only, and require IAM authentication.")
def _ingress(c):
    hits = [n for n in c.kinds("compute.app") if str(c.p(n, "ingress", "")).lower() == "all"]
    return [Hit(ids(hits), cli=[f"gcloud run services update {n['name']} --ingress internal-and-cloud-load-balancing" for n in hits[:5]])] if hits else []


@rule("sec-shared-identity", "security", "medium", "One identity shared by many workloads", ["devsec", "aws", "azure", "gcp"],
      confidence="medium",
      why="If any one workload is compromised, the attacker holds the permissions of all of them. Rotation and audit are also harder.",
      fix="Give each workload its own identity with only the permissions it needs.")
def _shared_identity(c):
    hits, items = [], []
    for n in c.kinds("iam.role", "iam.identity"):
        users = {e["from"] for e in c.inn(n["id"], "assumes")}
        if len(users) >= 4:
            hits.append(n)
            items.append(f"{n['name']}: {len(users)} workloads")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("sec-exposed-writer", "security", "high", "Internet-facing workload can change secrets or keys", ["devsec", "azure", "integration"],
      confidence="medium", providers=["azure"],
      why="An identity attached to a workload that faces the internet has write/delete rights on a vault. A remote-code bug there becomes secret tampering.",
      fix="Split read and write identities; give public workloads read-only (get/list) access.")
def _exposed_writer(c):
    exposed, hits, items = c.exposed_workloads(), [], []
    for ident in c.kinds("iam.identity", "iam.role"):
        for e in c.out(ident["id"], "can_access"):
            perms = {str(a).split(":")[-1].lower() for a in (e.get("access") or [])}
            if not (perms & WRITE_PERMS):
                continue
            users = [u["from"] for u in c.inn(ident["id"], "assumes") if u["from"] in exposed]
            if users:
                hits.append(ident)
                items.append(f"{ident['name']} → {c.name(e['to'])} ({', '.join(sorted(perms & WRITE_PERMS))}) used by {', '.join(c.name(u) for u in users)}")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("sec-vault-no-purge", "security", "medium", "Key vault without purge protection", ["azure", "devsec"],
      providers=["azure"], why="Anyone with delete rights can permanently destroy keys and secrets, including the keys encrypting your data.",
      fix="Enable purge protection (irreversible by design).", refs=["CIS Azure 8.5"])
def _no_purge(c):
    hits = [n for n in c.kinds("iam.vault") if c.p(n, "purge_protection") is False]
    return [Hit(ids(hits), cli=[f"az keyvault update -n {n['name']} --enable-purge-protection true" for n in hits[:5]])] if hits else []


@rule("sec-vault-legacy-policies", "security", "low", "Key vault uses access policies instead of RBAC", ["azure", "devsec"],
      providers=["azure"], why="Access policies are vault-wide, can't be scoped per secret, and sit outside PIM and Azure Policy.",
      fix="Move to Azure RBAC authorization and scope roles to the vault or the single secret.", refs=["CIS Azure 8.6"])
def _legacy_kv(c):
    hits = [n for n in c.kinds("iam.vault") if c.p(n, "rbac_authorization") is False]
    return [Hit(ids(hits), cli=[f"az keyvault update -n {n['name']} --enable-rbac-authorization true" for n in hits[:5]])] if hits else []


@rule("sec-cred-no-expiry", "security", "low", "Secrets and keys that never expire", ["azure", "devsec"],
      providers=["azure"], why="Credentials without an expiry are rarely rotated, so a leak stays useful forever.",
      fix="Set an expiry on every secret and key and rotate on a schedule (Key Vault rotation policy / Event Grid).",
      refs=["CIS Azure 8.3/8.4"])
def _no_expiry(c):
    hits = [n for n in c.kinds("iam.secret", "iam.key") if c.p(n, "enabled") is not False and not c.p(n, "expires")]
    return [Hit(ids(hits))] if hits else []


# =====================================================================================
# MISCONFIGURATION
# =====================================================================================
PY_EOL = re.compile(r"python[-_]?(2\.\d|3\.[0-8]\b|3[0-8]\b)")
NODE_EOL = re.compile(r"node(?:js)?[-_]?(\d+)")
DOTNET_EOL = re.compile(r"dotnet(?:core)?[-_]?(1\.|2\.|3\.|5\.0|6\.0|7\.0|\d\b)")


def _eol_runtime(rt: str) -> bool:
    s = rt.lower().replace("|", "").replace(" ", "")
    if PY_EOL.search(s):
        return True
    m = NODE_EOL.search(s)
    if m and int(m.group(1)) < 20:
        return True
    return bool(re.search(r"java(8|11)\b|java[-_]?(7|8)\b|php[-_]?7|ruby[-_]?2|go1\.1[0-9]\b", s))


@rule("misconf-eol-runtime", "misconfig", "medium", "Functions or apps on end-of-life runtimes", ["aws", "azure", "gcp", "devsec"],
      confidence="medium", why="Out-of-support runtimes no longer get security fixes. Cloud providers also block new deployments on them.",
      fix="Move to a currently supported runtime and test (check the provider's deprecation page for exact dates).")
def _eol(c):
    hits, items = [], []
    for n in c.kinds("compute.function", "compute.app"):
        rt = str(c.p(n, "runtime", "") or "")
        if rt and _eol_runtime(rt):
            hits.append(n)
            items.append(f"{n['name']}: {rt}")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("misconf-old-kubernetes", "misconfig", "medium", "Kubernetes clusters on old versions", ["azure", "gcp", "aws", "devsec"],
      confidence="medium", why="Kubernetes supports roughly the last three minor versions. Older control planes miss security patches and may be force-upgraded.",
      fix="Plan an upgrade one minor version at a time; check the provider's support calendar for your version.")
def _old_k8s(c):
    hits, items = [], []
    for n in c.kinds("compute.cluster"):
        m = re.match(r"v?1\.(\d+)", str(c.p(n, "kubernetes_version", "")))
        if m and int(m.group(1)) < 32:
            hits.append(n)
            items.append(f"{n['name']}: {c.p(n, 'kubernetes_version')}")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("misconf-single-az-db", "misconfig", "medium", "Databases without multi-zone failover", ["aws", "azure", "gcp", "integration"],
      why="A single zone outage takes the database, and everything that depends on it, down.",
      fix="Enable Multi-AZ / zone-redundant / regional HA, at least for production.")
def _single_az(c):
    hits = [n for n in c.kinds("data.database") if c.p(n, "multi_az") is False]
    items = []
    for n in hits:
        deps = len({e["from"] for e in c.inn(n["id"])})
        items.append(f"{n['name']}: {deps} dependent resource(s)" + (", tagged prod" if c.is_prod(n) else ""))
    if not hits:
        return []
    sev = "medium" if any(c.is_prod(n) or c.inn(n["id"]) for n in hits) else "low"
    return [Hit(ids(hits), items=items, severity=sev)]


@rule("misconf-missing-tags", "misconfig", "low", "Resources without owner or environment tags", ["devsec", "integration", "aws", "azure", "gcp"],
      why="Without tags nobody knows who owns a resource, whether it is production, or who to call when it breaks.",
      fix="Enforce required tags with a policy (AWS tag policies / Azure Policy 'require tag' / GCP org policy labels).")
def _tags(c):
    hits = []
    for n in c.things:
        if n["kind"].split(".")[0] in ("compute", "data", "storage") or n["kind"] == "network.load_balancer":
            if not c.tag(n, "owner", "team", "contact") or not c.tag(n, "env", "environment", "stage"):
                hits.append(n)
    return [Hit(ids(hits))] if hits else []


@rule("misconf-tag-drift", "misconfig", "note", "Inconsistent tag key spelling", ["devsec", "integration"],
      why="Keys like Env, env and Environment split reporting and defeat tag-based policies.",
      fix="Pick one spelling per key and fix the outliers.")
def _tag_drift(c):
    seen = {}
    for n in c.things:
        for k in c.tags(n):
            seen.setdefault(re.sub(r"[^a-z0-9]", "", k.lower()), {}).setdefault(k, []).append(n["id"])
    hits, items = set(), []
    for norm, variants in seen.items():
        if len(variants) > 1:
            items.append("/".join(sorted(variants)))
            for ids_ in variants.values():
                hits.update(ids_)
    return [Hit(sorted(hits), items=items)] if items else []


@rule("misconf-cross-env", "misconfig", "high", "Production linked to non-production", ["devsec", "integration"],
      confidence="medium",
      why="A production workload reaching a dev/test dependency (or the reverse) breaks isolation: test data leaks into prod, and a dev mistake can take prod down.",
      fix="Separate environments by account/subscription/project and remove the cross-link, or re-tag if the tag is wrong.")
def _cross_env(c):
    hits, items = set(), []
    for e in c.inv.edges:
        if e["rel"] in ("allows_traffic_to",):
            continue
        a, b = c.nodes[e["from"]], c.nodes[e["to"]]
        ea, eb = c.env(a), c.env(b)
        if ea and eb and ea != eb and "prod" in (ea, eb):
            hits.update((a["id"], b["id"]))
            items.append(f"{a['name']} [{ea}] → {b['name']} [{eb}] ({e['rel']})")
    return [Hit(sorted(hits), items=items[:20])] if hits else []


# =====================================================================================
# INTEGRATION
# =====================================================================================
@rule("integ-broken-reference", "misconfig", "high", "References that point at things that don't exist", ["integration", "azure"],
      why="A setting references a Key Vault secret the vault does not have. The workload fails at startup or on first use.",
      fix="Create the secret, or correct the reference in the app setting.")
def _broken(c):
    hits, items = set(), []
    for e in c.inv.edges:
        if e.get("status") in ("SecretNotFound", "SecretDisabled", "NotFound"):
            hits.update((e["from"], e["to"]))
            items.append(f"{c.name(e['from'])} → {c.name(e['to'])}: {e['status']}" + (f" ({e['label']})" if e.get("label") else ""))
    return [Hit(sorted(hits), items=items)] if hits else []


@rule("integ-unverifiable-reference", "misconfig", "medium", "References the scanner couldn't verify", ["integration", "azure"],
      confidence="low", why="The vault firewall or permissions blocked the check, so a runtime failure can't be ruled out.",
      fix="Allow the scanner identity through the vault firewall/RBAC (read-only) and re-scan.")
def _unverifiable(c):
    hits, items = set(), []
    for e in c.inv.edges:
        st = e.get("status")
        if st and st not in ("Resolved", "SecretNotFound", "SecretDisabled", "NotFound"):
            hits.update((e["from"], e["to"]))
            items.append(f"{c.name(e['from'])} → {c.name(e['to'])}: {st}")
    return [Hit(sorted(hits), items=items)] if hits else []


@rule("integ-expiry-outage", "misconfig", "high", "Credentials expiring (or expired) while workloads depend on them", ["integration", "devsec", "azure"],
      why="When a secret, key or certificate expires, everything that reads it starts failing, usually at 3 a.m.",
      fix="Rotate before the date and update dependants; automate with rotation policies.")
def _expiry(c):
    now, hits, items = _now(), [], []
    for n in c.kinds("iam.secret", "iam.key", "iam.certificate"):
        exp = _when(c.p(n, "expires"))
        if not exp or exp > now + timedelta(days=30):
            continue
        users = {e["from"] for e in c.inn(n["id"], "reads_secret", "encrypted_with")}
        state = "expired" if exp < now else f"expires in {(exp - now).days} day(s)"
        if users:
            hits.append(n)
            hits.extend(c.nodes[u] for u in users)
            items.append(f"{n['name']} {state}; used by {', '.join(sorted(c.name(u) for u in users))}")
        elif state == "expired":
            continue
    return [Hit(ids(hits), items=items)] if hits else []


@rule("integ-spof-lb", "misconfig", "medium", "Load balancer fronting a single backend", ["integration", "aws", "azure", "gcp"],
      confidence="medium", why="One backend means any restart, deploy or zone failure is an outage; the load balancer adds no resilience.",
      fix="Run at least two backends in different zones.")
def _spof_lb(c):
    hits = [n for n in c.kinds("network.load_balancer") if len(c.out(n["id"], "routes_to")) == 1]
    return [Hit(ids(hits))] if hits else []


@rule("integ-secret-fanout", "misconfig", "low", "Secrets read by many workloads", ["integration", "devsec"],
      confidence="medium", why="Rotating or revoking one of these touches every dependant at once; a leak exposes all of them.",
      fix="Split per workload where possible and keep a rotation runbook listing dependants (see the map).")
def _fanout(c):
    hits, items = [], []
    for n in c.kinds("iam.secret", "iam.key"):
        users = {e["from"] for e in c.inn(n["id"], "reads_secret")}
        if len(users) >= 3:
            hits.append(n)
            items.append(f"{n['name']}: {len(users)} readers")
    return [Hit(ids(hits), items=items)] if hits else []


@rule("integ-cross-region", "misconfig", "note", "Dependencies that cross regions", ["integration", "aws", "azure", "gcp"],
      confidence="medium", why="Cross-region calls add latency, egress cost and a second failure domain.",
      fix="Co-locate where possible; document the ones that are intentional.")
def _xregion(c):
    hits, items = set(), []
    for e in c.inv.edges:
        if e["rel"] in ("allows_traffic_to", "encrypted_with"):
            continue
        a, b = c.nodes[e["from"]], c.nodes[e["to"]]
        ra, rb = a.get("region"), b.get("region")
        if ra and rb and ra != rb and not a["kind"].startswith("iam") and not b["kind"].startswith("iam"):
            hits.update((a["id"], b["id"]))
            items.append(f"{a['name']} ({ra}) → {b['name']} ({rb})")
    return [Hit(sorted(hits), items=items[:20])] if hits else []
