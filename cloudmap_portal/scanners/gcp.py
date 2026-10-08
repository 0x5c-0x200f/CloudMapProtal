"""GCP scanner (read-only).

Everything is read through Cloud Asset Inventory (one API, any scope: project, folder or
organization), and relationships are resolved from the resource URLs inside each asset.

Layout of this module:
  fetch()  - the only code that talks to Google (needs: pip install google-cloud-asset)
  build()  - pure function: asset dicts -> inventory records (fully testable offline)

Secrets: handlers copy only fields they name. Instance metadata (startup scripts, keys),
function environment variables and similar never enter the file.
Permissions: roles/cloudasset.viewer on the scope, and the Cloud Asset API enabled.
See `cloudmap-portal policy gcp`.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .base import Emitter, sort_ports

ASSET_TYPES = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/InstanceGroup",
    "compute.googleapis.com/BackendService",
    "compute.googleapis.com/ForwardingRule",
    "sqladmin.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "cloudfunctions.googleapis.com/CloudFunction",
    "cloudfunctions.googleapis.com/Function",
    "run.googleapis.com/Service",
    "container.googleapis.com/Cluster",
]
SQL_PORTS = {"MYSQL": "3306", "POSTGRES": "5432", "SQLSERVER": "1433"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def norm(u):
    """Canonical lowercase path for asset names and resource URLs, so they can be matched:
    '//compute.googleapis.com/projects/p/zones/z/instances/i' and
    'https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i' both become
    'projects/p/zones/z/instances/i'."""
    if not u:
        return None
    u = re.sub(r"^//[^/]+/", "", str(u))
    u = re.sub(r"^https?://[^/]+/(?:compute/[^/]+/)?", "", u)
    return u.strip("/").lower()


def region_of(loc):
    """'europe-west1-b' (a zone) -> 'europe-west1'; regions and multi-regions pass through."""
    if not loc or loc == "global":
        return None
    return re.sub(r"^([a-z]+-[a-z]+\d+)-[a-z]$", r"\1", str(loc))


def last(u):
    return str(u).rsplit("/", 1)[-1] if u else None


def firewall_open_ports(data: dict) -> list[str]:
    """Ports an enabled INGRESS allow rule opens to 0.0.0.0/0 or ::/0."""
    if data.get("disabled") or data.get("direction", "INGRESS") != "INGRESS":
        return []
    if not {"0.0.0.0/0", "::/0"} & set(data.get("sourceRanges", [])):
        return []
    ports = set()
    for a in data.get("allowed", []):
        proto = str(a.get("IPProtocol", "")).lower()
        if proto in ("all", ""):
            ports.add("all")
        elif proto in ("tcp", "udp", "sctp"):
            ports.update(str(p) for p in a.get("ports") or ["all"])
        # icmp, esp, ah...: no ports to expose
    return sort_ports(ports)


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
class _Builder:
    def __init__(self, em: Emitter, assets: list[dict]):
        self.em = em
        self.path: dict[str, str] = {}           # normalised path -> node id
        self.sa_by_email: dict[str, str] = {}
        self.edges: list[tuple] = []
        self.firewalls: list[dict] = []
        self.instances: list[dict] = []
        self.scope_names: dict[str, str] = {}    # 'folders/4' -> display name
        self.projects: dict[str, dict] = {}      # project id -> info
        self.by_number: dict[str, str] = {}      # project number -> project id
        self.fallback: dict[str, str] = {}       # node id -> project node id
        self.assets = assets
        self._collect_scope()

    # -- hierarchy --------------------------------------------------------
    def _collect_scope(self):
        for a in self.assets:
            d = (a.get("resource") or {}).get("data") or {}
            t = a.get("assetType", "")
            if t.endswith("/Organization"):
                self.scope_names[norm(a["name"])] = d.get("displayName") or last(a["name"])
            elif t.endswith("/Folder"):
                self.scope_names[norm(a["name"])] = d.get("displayName") or last(a["name"])
            elif t.endswith("/Project"):
                pid = d.get("projectId") or last(a["name"])
                self.projects[pid] = {"name": d.get("name") or pid, "number": str(d.get("projectNumber") or last(a["name"])),
                                      "labels": d.get("labels"), "ancestors": a.get("ancestors", [])}
                self.by_number[self.projects[pid]["number"]] = pid
        for a in self.assets:          # resource paths carry the project id, ancestors the number
            m = re.match(r"projects/([^/]+)/", norm(a.get("name")) or "")
            num = next((e.split("/", 1)[1] for e in a.get("ancestors", []) if e.startswith("projects/")), None)
            if m and num and m.group(1) != num:
                self.by_number.setdefault(num, m.group(1))

    def _scope_node(self, entry: str, parent):
        kind, num = entry.split("/", 1)
        nid = f"gcp:{'org' if kind == 'organizations' else 'folder'}:{num}"
        if not self.em.get(nid):
            self.em.node(nid, "organization" if kind == "organizations" else "folder",
                         self.scope_names.get(entry, num), parent,
                         native_type=f"cloudresourcemanager.googleapis.com/{'Organization' if kind == 'organizations' else 'Folder'}")
        return nid

    def project(self, pid: str, ancestors=()) -> str:
        nid = f"gcp:project:{pid}"
        if self.em.get(nid):
            return nid
        info = self.projects.get(pid, {"name": pid, "number": None, "labels": None, "ancestors": []})
        chain = [x for x in (ancestors or info["ancestors"]) if not x.startswith("projects/")]
        parent = None
        for entry in reversed(chain):                       # ancestors are nearest-first; build root-down
            parent = self._scope_node(entry, parent)
        self.em.node(nid, "account", info["name"], parent, native_type="cloudresourcemanager.googleapis.com/Project",
                     props={"project_id": pid, "project_number": info["number"]},
                     tags={k: str(v) for k, v in (info["labels"] or {}).items()})
        return nid

    def project_of(self, asset: dict, path: str | None) -> str | None:
        for entry in asset.get("ancestors", []):
            if entry.startswith("projects/"):
                pid = self.by_number.get(entry.split("/", 1)[1])
                if pid:
                    return self.project(pid, asset.get("ancestors"))
                num = entry.split("/", 1)[1]
                return self.project(num, asset.get("ancestors"))   # unseen project: number is all we know
        m = re.match(r"projects/([^/]+)/", path or "")
        return self.project(m.group(1), asset.get("ancestors")) if m else None

    # -- nodes / links ----------------------------------------------------
    def add(self, asset, kind, short, name, *, parent=None, props=None, tags=None, native=None, region=None, key=None):
        p = norm(asset["name"])
        nid = f"gcp:{short}:{key or p}"
        self.path[p] = nid
        proj = self.project_of(asset, p)
        loc = region_of(region or (asset.get("resource") or {}).get("location"))
        self.em.node(nid, kind, name, parent or proj, native_type=native or asset.get("assetType"),
                     region=loc, props=props,
                     tags={k: str(v) for k, v in (tags or {}).items()})
        self.fallback[nid] = proj
        return nid

    def link(self, src, dst_url, rel, label=None):
        if dst_url:
            self.edges.append((src, norm(dst_url), rel, label))


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------
def _network(b, a, d):
    b.add(a, "network.vpc", "network", d["name"], props={"mode": "auto" if d.get("autoCreateSubnetworks") else "custom"})


def _subnet(b, a, d):
    nid = b.add(a, "network.subnet", "subnet", d["name"], parent=None,
                props={"cidr": d.get("ipCidrRange"), "private_google_access": d.get("privateIpGoogleAccess")},
                region=last(d.get("region")))
    net = norm(d.get("network"))
    b.edges.append((nid, net, "__parent__", None))      # containment, resolved after all nodes exist


def _firewall(b, a, d):
    ports = firewall_open_ports(d)
    nid = b.add(a, "network.security_group", "firewall", d["name"],
                props={"direction": d.get("direction"), "priority": d.get("priority"), "disabled": d.get("disabled") or None,
                       "world_open_ports": ports or None})
    b.edges.append((nid, norm(d.get("network")), "__parent__", None))
    if not d.get("disabled"):
        b.firewalls.append({"id": nid, "network": norm(d.get("network")), "tags": set(d.get("targetTags", [])),
                            "sas": set(d.get("targetServiceAccounts", []))})


def _instance(b, a, d):
    nics = d.get("networkInterfaces", [])
    tags = set((d.get("tags") or {}).get("items", []))
    sas = [s.get("email") for s in d.get("serviceAccounts", []) if s.get("email")]
    nid = b.add(a, "compute.instance", "instance", d["name"], tags=d.get("labels"),
                props={"machine_type": last(d.get("machineType")), "status": d.get("status"), "zone": last(d.get("zone")),
                       "external_ip": True if any(n.get("accessConfigs") for n in nics) else None})
    for n in nics:
        b.link(nid, n.get("subnetwork"), "attached_to")
    for email in sas:
        b.edges.append((nid, ("sa", email), "assumes", "service account"))
    b.instances.append({"id": nid, "network": norm(nics[0].get("network")) if nics else None, "tags": tags, "sas": set(sas)})


def _instance_group(b, a, d):
    b.add(a, "compute.instance_group", "igroup", d["name"], props={"size": d.get("size")})


def _backend(b, a, d):
    nid = b.add(a, "network.backend_service", "backend", d["name"], props={"protocol": d.get("protocol")})
    for be in d.get("backends", []):
        b.link(nid, be.get("group"), "routes_to")


def _forwarding_rule(b, a, d):
    scheme = d.get("loadBalancingScheme", "")
    nid = b.add(a, "network.load_balancer", "fr", d["name"],
                props={"scheme": "internet-facing" if scheme.startswith("EXTERNAL") else "internal",
                       "ports": ",".join(d.get("ports", [])) or d.get("portRange")})
    b.link(nid, d.get("backendService") or d.get("target"), "routes_to")


def _sql(b, a, d):
    st = d.get("settings", {})
    ipc = st.get("ipConfiguration", {})
    version = str(d.get("databaseVersion", ""))
    engine = next((k for k in SQL_PORTS if version.startswith(k)), version or None)
    world = ipc.get("ipv4Enabled") and any(n.get("value") in ("0.0.0.0/0", "::/0") for n in ipc.get("authorizedNetworks", []))
    nid = b.add(a, "data.database", "sql", d["name"], tags=st.get("userLabels"), region=d.get("region"),
                props={"engine": engine, "version": version, "tier": st.get("tier"),
                       "multi_az": st.get("availabilityType") == "REGIONAL",
                       "world_open_ports": [SQL_PORTS.get(engine, "database")] if world else None})
    b.link(nid, ipc.get("privateNetwork"), "attached_to")


def _bucket(b, a, d):
    b.add(a, "storage.bucket", "bucket", d["name"], tags=d.get("labels"), key=norm(a["name"]),
          props={"location": d.get("location"), "storage_class": d.get("storageClass"),
                 "public_access_prevention": (d.get("iamConfiguration") or {}).get("publicAccessPrevention")})


def _service_account(b, a, d):
    email = d.get("email") or last(a["name"])
    nid = b.add(a, "iam.identity", "sa", email, key=email.lower(), props={"disabled": d.get("disabled") or None})
    b.sa_by_email[email.lower()] = nid


def _function(b, a, d):
    cfg = d.get("serviceConfig", {})
    nid = b.add(a, "compute.function", "function", last(d.get("name")) or last(a["name"]),
                tags=d.get("labels"),
                props={"runtime": d.get("runtime") or d.get("buildConfig", {}).get("runtime"),
                       "state": d.get("status") or d.get("state")})
    sa = d.get("serviceAccountEmail") or cfg.get("serviceAccountEmail")
    if sa:
        b.edges.append((nid, ("sa", sa), "assumes", "service account"))


def _run(b, a, d):
    meta = d.get("metadata", {})
    nid = b.add(a, "compute.app", "run", meta.get("name") or last(a["name"]), tags=meta.get("labels"),
                props={"ingress": (meta.get("annotations") or {}).get("run.googleapis.com/ingress")})
    sa = d.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName")
    if sa:
        b.edges.append((nid, ("sa", sa), "assumes", "service account"))


def _gke(b, a, d):
    nid = b.add(a, "compute.cluster", "gke", d["name"], tags=d.get("resourceLabels"),
                props={"kubernetes_version": d.get("currentMasterVersion"), "nodes": d.get("currentNodeCount")})
    m = re.match(r"projects/([^/]+)/", norm(a["name"]) or "")
    region = re.sub(r"-[a-z]$", "", d.get("location") or "")
    if m and d.get("subnetwork") and region:
        b.link(nid, f"projects/{m.group(1)}/regions/{region}/subnetworks/{d['subnetwork']}", "attached_to")


HANDLERS = {
    "compute.googleapis.com/Network": _network,
    "compute.googleapis.com/Subnetwork": _subnet,
    "compute.googleapis.com/Firewall": _firewall,
    "compute.googleapis.com/Instance": _instance,
    "compute.googleapis.com/InstanceGroup": _instance_group,
    "compute.googleapis.com/BackendService": _backend,
    "compute.googleapis.com/ForwardingRule": _forwarding_rule,
    "sqladmin.googleapis.com/Instance": _sql,
    "storage.googleapis.com/Bucket": _bucket,
    "iam.googleapis.com/ServiceAccount": _service_account,
    "cloudfunctions.googleapis.com/CloudFunction": _function,
    "cloudfunctions.googleapis.com/Function": _function,
    "run.googleapis.com/Service": _run,
    "container.googleapis.com/Cluster": _gke,
}


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def build(em: Emitter, assets: list[dict]) -> None:
    b = _Builder(em, assets)
    failed: dict[str, list] = defaultdict(list)
    for pid in b.projects:                                  # show empty projects too
        b.project(pid)
    for a in assets:
        handler = HANDLERS.get(a.get("assetType"))
        if handler:
            try:
                handler(b, a, (a.get("resource") or {}).get("data") or {})
            except Exception as e:  # noqa: BLE001 - real projects contain shapes nobody planned for
                failed[a.get("assetType")].append(f"{last(a.get('name'))}: {type(e).__name__} {e}")
    for atype, why in failed.items():
        em.error(f"mapping/{atype}", f"{len(why)} asset(s) could not be mapped and are missing from the map (first: {why[0][:160]})")

    for src, dst, rel, label in b.edges:
        if rel == "__parent__":                              # subnet/firewall live inside their VPC
            vpc = b.path.get(dst)
            if vpc:
                em.get(src)["parent"] = vpc
            continue
        if isinstance(dst, tuple):                           # ("sa", email)
            dst = b.sa_by_email.get(dst[1].lower())
        else:
            dst = b.path.get(dst)
        if dst:
            em.edge(src, dst, rel, label)

    for fw in b.firewalls:                                   # which instances does each rule apply to?
        for inst in b.instances:
            if inst["network"] != fw["network"]:
                continue
            if not fw["tags"] and not fw["sas"] or fw["tags"] & inst["tags"] or fw["sas"] & inst["sas"]:
                em.edge(inst["id"], fw["id"], "uses", "firewall rule")

    for rec in em.nodes():
        if rec["parent"] and not em.get(rec["parent"]):
            rec["parent"] = b.fallback.get(rec["id"])
    em.scope.update({"projects": sorted(n["name"] for n in em.nodes() if n["kind"] == "account"),
                     "regions": sorted({n["region"] for n in em.nodes() if n.get("region")})})


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------
def fetch(parent: str, say=lambda _m: None, client=None) -> list[dict]:
    try:
        from google.cloud import asset_v1
        from google.protobuf import json_format
    except ImportError as e:
        raise SystemExit('GCP SDK missing: pip install google-cloud-asset') from e
    try:
        client = client or asset_v1.AssetServiceClient()
        req = asset_v1.ListAssetsRequest(parent=parent, content_type=asset_v1.ContentType.RESOURCE,
                                         asset_types=ASSET_TYPES, page_size=1000)
        out = []
        for a in client.list_assets(request=req):
            out.append(json_format.MessageToDict(asset_v1.Asset.pb(a)))
            if len(out) % 500 == 0:
                say(f"  fetched {len(out)} assets")
        return out
    except Exception as e:  # noqa: BLE001
        why = (str(e).strip().splitlines() or [""])[0]
        raise SystemExit(f"Could not read Cloud Asset Inventory for {parent} ({type(e).__name__}: {why}). "
                         "Run `gcloud auth application-default login`, enable cloudasset.googleapis.com, and "
                         "grant roles/cloudasset.viewer. See: cloudmap-portal policy gcp") from e


def scan(em: Emitter, parent: str, progress=None, client=None) -> None:
    say = progress or (lambda _m: None)
    say(f"Reading Cloud Asset Inventory for {parent}")
    assets = fetch(parent, say, client)
    say(f"Mapping {len(assets)} assets")
    build(em, assets)
