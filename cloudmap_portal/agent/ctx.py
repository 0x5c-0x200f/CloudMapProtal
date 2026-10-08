"""Read-only view over an Inventory with the helpers every rule needs."""
from __future__ import annotations

import re
from collections import defaultdict

from ..schema import SCOPE_KINDS

NET_KINDS = {"network.vpc", "network.subnet", "network.security_group", "network.interface",
             "network.public_ip", "network.backend_service", "network.route_table"}
ADMIN_PORTS = {22, 3389, 5985, 5986}
DB_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 2379, 27017}
WRITE_PERMS = {"set", "delete", "purge", "create", "update", "import", "rotate", "backup",
               "restore", "recover", "all", "*", "write", "owner", "contributor"}
WORKLOAD_KINDS = {"compute.instance", "compute.function", "compute.app", "compute.cluster"}
CROWN_KINDS_PREFIX = ("data.", "storage.")
CROWN_KINDS = {"iam.secret", "iam.key", "iam.certificate", "iam.vault"}


def parse_ports(value) -> list[tuple[int, int]]:
    """'22', '80-90', 'all', '*', 0-65535 -> inclusive ranges."""
    out = []
    for raw in value or []:
        s = str(raw).strip().lower()
        if s in ("*", "all", "any", "-1"):
            out.append((0, 65535))
        elif re.fullmatch(r"\d+", s):
            out.append((int(s), int(s)))
        elif re.fullmatch(r"\d+\s*-\s*\d+", s):
            a, b = (int(x) for x in re.split(r"\s*-\s*", s))
            out.append((min(a, b), max(a, b)))
    return out


def covers(ranges, ports) -> list[int]:
    return sorted(p for p in ports if any(a <= p <= b for a, b in ranges))


def rg_of(node) -> str | None:
    m = re.search(r"/resourcegroups/([^/]+)", node["id"], re.I)
    return m.group(1) if m else None


def norm_env(v) -> str | None:
    s = str(v or "").strip().lower()
    if not s:
        return None
    for key, names in (("prod", ("prod", "production", "prd", "live")),
                       ("dev", ("dev", "development", "develop", "sandbox", "sbx")),
                       ("test", ("test", "qa", "uat", "stage", "staging", "stg", "preprod"))):
        if s in names:
            return key
    return s


class Ctx:
    def __init__(self, inv):
        self.inv = inv
        self.provider = inv.meta.get("provider", "aws")
        self.nodes = inv.nodes
        self.things = [n for n in inv.nodes.values() if n["kind"] not in SCOPE_KINDS]
        self.by_kind = defaultdict(list)
        for n in self.things:
            self.by_kind[n["kind"]].append(n)
        self._exposed = None

    # -- accessors ---------------------------------------------------------
    def kinds(self, *kinds):
        return [n for k in kinds for n in self.by_kind.get(k, [])]

    def prefix(self, *prefixes):
        return [n for n in self.things if n["kind"].startswith(prefixes)]

    def p(self, n, key, default=None):
        return (n.get("props") or {}).get(key, default)

    def tags(self, n):
        return {str(k): v for k, v in (n.get("tags") or {}).items()}

    def tag(self, n, *names):
        t = {k.lower(): v for k, v in self.tags(n).items()}
        for name in names:
            if t.get(name):
                return t[name]
        return None

    def env(self, n):
        return norm_env(self.tag(n, "env", "environment", "stage"))

    def out(self, nid, *rels):
        return [e for e in self.inv._out.get(nid, []) if not rels or e["rel"] in rels]

    def inn(self, nid, *rels):
        return [e for e in self.inv._in.get(nid, []) if not rels or e["rel"] in rels]

    def degree(self, nid):
        return len(self.inv._out.get(nid, [])) + len(self.inv._in.get(nid, []))

    def name(self, nid):
        n = self.nodes.get(nid)
        return n["name"] if n else nid

    def label(self, n):
        return f"{n['name']} ({n['kind']})"

    def region(self, n):
        return n.get("region")

    def is_prod(self, n):
        return self.env(n) == "prod"

    # -- exposure ------------------------------------------------------------
    def world_open(self, n):
        return parse_ports(self.p(n, "world_open_ports"))

    def exposed_workloads(self) -> dict:
        """node id -> list of reasons it faces the internet (computed once)."""
        if self._exposed is not None:
            return self._exposed
        reasons = defaultdict(list)
        for n in self.kinds("network.load_balancer"):
            if str(self.p(n, "scheme", "")).startswith("internet"):
                reasons[n["id"]].append("internet-facing load balancer")
                for e in self.out(n["id"], "routes_to"):
                    reasons[e["to"]].append(f"behind internet-facing {n['name']}")
        for n in self.kinds("network.public_ip"):
            for e in self.out(n["id"]) + self.inn(n["id"]):
                other = e["to"] if e["from"] == n["id"] else e["from"]
                reasons[other].append(f"has public IP {n['name']}")
        for n in self.things:
            if self.p(n, "external_ip") is True:
                reasons[n["id"]].append("has an external IP")
            if str(self.p(n, "ingress", "")).lower() == "all" and n["kind"] == "compute.app":
                reasons[n["id"]].append("accepts traffic from the internet (ingress: all)")
            if str(self.p(n, "public_network", "")).lower() in ("enabled", "true") and n["kind"].startswith(("data.", "iam.vault", "storage")):
                reasons[n["id"]].append("public network access enabled")
            if self.p(n, "allows_public_blobs") is True:
                reasons[n["id"]].append("allows anonymous blob access")
        for sg in self.kinds("network.security_group"):
            if self.world_open(sg):
                for nid in self.members_of(sg["id"]):
                    reasons[nid].append(f"{sg['name']} allows the whole internet in")
        for n in self.things:
            if n["kind"].startswith("data.") and self.world_open(n):
                reasons[n["id"]].append("firewall allows the whole internet in")
        self._exposed = {k: list(dict.fromkeys(v)) for k, v in reasons.items() if k in self.nodes}
        return self._exposed

    def members_of(self, sg_id, depth=3):
        """Workloads/data associated with a network group, following attach/use edges both ways."""
        seen, frontier, found = {sg_id}, [sg_id], []
        for _ in range(depth):
            nxt = []
            for cur in frontier:
                for e in self.out(cur, "uses", "attached_to") + self.inn(cur, "uses", "attached_to"):
                    other = e["to"] if e["from"] == cur else e["from"]
                    if other in seen:
                        continue
                    seen.add(other)
                    node = self.nodes[other]
                    if node["kind"] in WORKLOAD_KINDS or node["kind"].startswith("data."):
                        found.append(other)
                    elif node["kind"] in ("network.interface", "network.subnet"):
                        nxt.append(other)
            frontier = nxt
        return found
