"""Azure scanner (read-only).

Everything is read through Azure Resource Graph, one query surface, so a scan is a handful
of paged calls instead of one API per service. Relationships are then resolved from the
ARM IDs found inside each resource's properties.

Layout of this module:
  fetch() / collect_keyvault() - the only code that talks to Azure
  build()                      - pure function: rows -> inventory records (fully testable offline)

Key Vault: secrets, keys and certificates appear as items inside their vault, by NAME and with
status (enabled, expiry). Secret VALUES AND KEY MATERIAL ARE NEVER READ: the normalisers below
name the fields they take, and `value` is not among them. Relationships shown:
  who can access a vault (access policies and RBAC), which apps read which secret (Key Vault
  references in app settings, via the reference-status API that returns no values), and which
  resources are encrypted with which key (customer-managed keys).

Secrets: handlers copy only fields they name explicitly. Nothing is copied wholesale, so admin
passwords, custom data, connection strings and app settings cannot leak into a file.
Permissions: the built-in Reader role is enough for everything except the app reference status,
which may need more; if it is denied it is reported as an unreadable area. See `cloudmap-portal policy azure`.
"""
from __future__ import annotations

import logging
import os
import re
from collections import Counter, defaultdict

from .base import Emitter, sort_ports

CONTAINERS_QUERY = """ResourceContainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, location, tags, subscriptionId, properties"""

RESOURCES_QUERY = """Resources
| project id, name, type, location, resourceGroup, subscriptionId, tags, kind, sku, zones, identity, properties"""

# Built-in Key Vault data roles: guid -> (display name, what it allows). "x:*" means create, change and delete.
KV_ROLES = {
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": ("Key Vault Administrator", ["secrets:*", "keys:*", "certificates:*"]),
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": ("Key Vault Secrets Officer", ["secrets:*"]),
    "4633458b-17de-408a-b874-0445c86b69e6": ("Key Vault Secrets User", ["secrets:get"]),
    "14b46e9e-c2b7-41b4-b07b-48a6ebf60603": ("Key Vault Crypto Officer", ["keys:*"]),
    "12338af0-0e69-4776-bea7-57ae8d297424": ("Key Vault Crypto User", ["keys:use"]),
    "e147488a-f6f5-4113-8e2d-b22465e65bf6": ("Key Vault Crypto Service Encryption User", ["keys:wrap", "keys:unwrap", "keys:get"]),
    "a4417e6f-fecd-4de8-b567-7b0420556985": ("Key Vault Certificates Officer", ["certificates:*"]),
    "21090545-7ca7-4776-b22c-e363652d74d2": ("Key Vault Reader", ["metadata:read"]),
}
ASSIGNMENTS_QUERY = f"""AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| extend roleDefinitionId = tolower(tostring(properties.roleDefinitionId)), principalId = tostring(properties.principalId), principalType = tostring(properties.principalType), scope = tolower(tostring(properties.scope))
| where roleDefinitionId has_any ({', '.join(repr(g) for g in KV_ROLES)})
| project principalId, principalType, roleDefinitionId, scope"""

KV_URI = re.compile(r"https?://([a-z0-9-]+)\.vault\.azure\.net/(keys|secrets|certificates)/([^/?#]+)", re.I)
CERT_CONTENT_TYPES = ("application/x-pkcs12", "application/x-pem-file")
IGNORED_TYPES = ("microsoft.compute/virtualmachines/extensions",)
_INTERNET = {"*", "internet", "any", "0.0.0.0/0", "::/0"}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _lc(x) -> str:
    return str(x or "").lower()


def _ref(obj):
    """ARM id (lowercased) from a {'id': ...} reference, or None."""
    return _lc(obj.get("id")) if isinstance(obj, dict) and obj.get("id") else None


def _tags(t) -> dict:
    return {str(k): str(v) for k, v in (t or {}).items()}


def _from_internet(rp: dict) -> bool:
    sources = [rp.get("sourceAddressPrefix"), *(rp.get("sourceAddressPrefixes") or [])]
    return any(_lc(s) in _INTERNET for s in sources if s)


def _port_tokens(rp: dict) -> set:
    ranges = [rp.get("destinationPortRange"), *(rp.get("destinationPortRanges") or [])]
    return {"all" if r == "*" else str(r) for r in ranges if r}


def nsg_open_ports(rules: list) -> list[str]:
    """Inbound ports an NSG allows from the internet. A lower-numbered Deny that covers the
    same port (or everything) wins, as in Azure. This is an approximation: it does not
    evaluate subnet-level NSGs, ASGs or service tags other than 'Internet'."""
    allows, denies = [], []
    for r in rules or []:
        rp = r.get("properties", {})
        if _lc(rp.get("direction")) != "inbound" or not _from_internet(rp):
            continue
        (allows if _lc(rp.get("access")) == "allow" else denies).append(
            (rp.get("priority", 65000), _port_tokens(rp)))
    open_ports = set()
    for prio, toks in allows:
        for t in toks:
            if not any(dp < prio and ("all" in dt or t in dt) for dp, dt in denies):
                open_ports.add(t)
    return sort_ports(open_ports)


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
class _Builder:
    def __init__(self, em: Emitter):
        self.em = em
        self.arm: dict[str, str] = {}            # lowercased ARM id -> node id
        self.edges: list[tuple] = []             # (src node id, dst ARM id, rel, label)
        self.vm_by_nic: dict[str, str] = {}
        self.lb_backends: list[tuple] = []       # (lb node id, nic ARM id)
        self.fallback: dict[str, str] = {}       # node id -> resource group node id
        self.unmapped: Counter = Counter()
        self.principals: dict[str, str] = {}     # Entra principal (object) id -> ARM id of the identity's resource
        self.vault_by_name: dict[str, str] = {}  # vault name -> vault ARM id
        self.vault_cfg: dict[str, dict] = {}     # vault ARM id -> {"policies": [...], "rbac": bool}
        self.cmk: list[tuple] = []               # (node id, Key Vault key URI): customer-managed keys

    # -- scope nodes ------------------------------------------------------
    def subscription(self, sub_id: str, name: str | None = None, chain=()) -> str:
        nid = f"azure:sub:{_lc(sub_id)}"
        if self.em.get(nid) and not name:
            return nid
        parent = None
        for mg in reversed(list(chain)):          # chain is nearest-first; build root-down
            mg_id = f"azure:mg:{_lc(mg.get('name'))}"
            if not self.em.get(mg_id):
                self.em.node(mg_id, "management_group", mg.get("displayName") or mg.get("name"), parent,
                             native_type="Microsoft.Management/managementGroups")
            parent = mg_id
        self.em.node(nid, "account", name or sub_id, parent, native_type="Microsoft.Resources/subscriptions")
        return nid

    def resource_group(self, sub_id: str, rg: str, location=None, tags=None) -> str:
        nid = f"azure:rg:/subscriptions/{_lc(sub_id)}/resourcegroups/{_lc(rg)}"
        existing = self.em.get(nid)
        if existing and not location:
            return nid
        self.em.node(nid, "resource_group", rg, self.subscription(sub_id),
                     native_type="Microsoft.Resources/resourceGroups", region=location, tags=_tags(tags))
        return nid

    # -- resource nodes ---------------------------------------------------
    def add(self, row, kind, native, short, *, props=None, parent_arm=None, name=None) -> str:
        arm = _lc(row["id"])
        nid = f"azure:{short}:{arm}"
        self.arm[arm] = nid
        rg = self.resource_group(row.get("subscriptionId") or arm.split("/")[2],
                                 row.get("resourceGroup") or arm.split("/")[4])
        parent = f"azure:{parent_arm[0]}:{_lc(parent_arm[1])}" if parent_arm else rg
        self.fallback[nid] = rg
        self.em.node(nid, kind, name or row["name"], parent, native_type=native,
                     region=row.get("location"), props=props, tags=_tags(row.get("tags")))
        return nid

    def link(self, src: str, dst_arm, rel: str, label: str | None = None) -> None:
        if dst_arm:
            self.edges.append((src, _lc(dst_arm), rel, label))

    def identities(self, nid: str, row: dict) -> None:
        ident = row.get("identity") or {}
        if ident.get("principalId"):                      # system-assigned: the resource is its own principal
            self.principals[_lc(ident["principalId"])] = _lc(row["id"])
        for arm in (ident.get("userAssignedIdentities") or {}):
            self.link(nid, arm, "assumes", "managed identity")


# ---------------------------------------------------------------------------
# handlers: one per Azure resource type. Each copies a whitelist of fields.
# ---------------------------------------------------------------------------
def _vnet(b, row, p):
    nid = b.add(row, "network.vpc", "Microsoft.Network/virtualNetworks", "vnet",
                props={"address_space": ", ".join(p.get("addressSpace", {}).get("addressPrefixes", []))})
    for s in p.get("subnets", []):
        sp = s.get("properties", {})
        sarm = _lc(s["id"])
        sid = f"azure:subnet:{sarm}"
        b.arm[sarm] = sid
        b.fallback[sid] = b.fallback[nid]
        b.em.node(sid, "network.subnet", s["name"], nid, native_type="Microsoft.Network/virtualNetworks/subnets",
                  region=row.get("location"),
                  props={"cidr": sp.get("addressPrefix") or ", ".join(sp.get("addressPrefixes", []))})
        b.link(sid, _ref(sp.get("networkSecurityGroup")), "uses", "network security group")
        b.link(sid, _ref(sp.get("routeTable")), "uses", "route table")


def _nsg(b, row, p):
    ports = nsg_open_ports(p.get("securityRules", []))
    b.add(row, "network.security_group", "Microsoft.Network/networkSecurityGroups", "nsg",
          props={"inbound_rules": len(p.get("securityRules", [])), "world_open_ports": ports or None})


def _nic(b, row, p):
    nid = b.add(row, "network.interface", "Microsoft.Network/networkInterfaces", "nic")
    for ipc in p.get("ipConfigurations", []):
        ip = ipc.get("properties", {})
        b.link(nid, _ref(ip.get("subnet")), "attached_to")
        b.link(nid, _ref(ip.get("publicIPAddress")), "uses", "public IP")
    b.link(nid, _ref(p.get("networkSecurityGroup")), "uses", "network security group")


def _public_ip(b, row, p):
    b.add(row, "network.public_ip", "Microsoft.Network/publicIPAddresses", "pip",
          props={"ip_address": p.get("ipAddress"), "sku": (row.get("sku") or {}).get("name")})


def _lb(b, row, p):
    frontends = [f.get("properties", {}) for f in p.get("frontendIPConfigurations", [])]
    public = any(f.get("publicIPAddress") for f in frontends)
    nid = b.add(row, "network.load_balancer", "Microsoft.Network/loadBalancers", "lb",
                props={"scheme": "internet-facing" if public else "internal",
                       "sku": (row.get("sku") or {}).get("name")})
    for f in frontends:
        b.link(nid, _ref(f.get("publicIPAddress")), "uses", "public IP")
    for pool in p.get("backendAddressPools", []):
        for cfg in pool.get("properties", {}).get("backendIPConfigurations", []):
            b.lb_backends.append((nid, _lc(cfg.get("id")).split("/ipconfigurations/")[0]))


def _vm(b, row, p):
    nid = b.add(row, "compute.instance", "Microsoft.Compute/virtualMachines", "vm",
                props={"size": p.get("hardwareProfile", {}).get("vmSize"),
                       "os": p.get("storageProfile", {}).get("osDisk", {}).get("osType"),
                       "zone": ",".join(row.get("zones") or []) or None})
    for n in p.get("networkProfile", {}).get("networkInterfaces", []):
        arm = _ref(n)
        b.link(nid, arm, "uses", "network interface")
        if arm:
            b.vm_by_nic[arm] = nid
    b.identities(nid, row)


def _identity(b, row, p):
    b.add(row, "iam.identity", "Microsoft.ManagedIdentity/userAssignedIdentities", "identity")
    if p.get("principalId"):
        b.principals[_lc(p["principalId"])] = _lc(row["id"])


def _cmk(b, nid, uri):
    if uri:
        b.cmk.append((nid, uri))


def _storage(b, row, p):
    nid = b.add(row, "storage.account", "Microsoft.Storage/storageAccounts", "storage",
                props={"sku": (row.get("sku") or {}).get("name"), "https_only": p.get("supportsHttpsTrafficOnly"),
                       "allows_public_blobs": True if p.get("allowBlobPublicAccess") is True else None})
    kv = (p.get("encryption") or {}).get("keyvaultproperties") or {}
    if kv.get("keyvaulturi") and kv.get("keyname"):
        _cmk(b, nid, f"{kv['keyvaulturi'].rstrip('/')}/keys/{kv['keyname']}")


def _sql_server(b, row, p):
    b.add(row, "data.server", "Microsoft.Sql/servers", "sqlserver",
          props={"version": p.get("version"), "public_network": p.get("publicNetworkAccess")})


def _sql_db(b, row, p):
    arm = _lc(row["id"])
    if _lc(row["name"]) == "master":
        return
    props = {"sku": (row.get("sku") or {}).get("name"), "engine": "sqlserver"}
    if "zoneRedundant" in p:
        props["multi_az"] = bool(p["zoneRedundant"])
    b.add(row, "data.database", "Microsoft.Sql/servers/databases", "sqldb", props=props,
          parent_arm=("sqlserver", arm.rsplit("/databases/", 1)[0]))


def _flex(engine, native):
    def handler(b, row, p):
        nid = b.add(row, "data.database", native, "flexdb",
                    props={"engine": engine, "version": p.get("version"),
                           "multi_az": p.get("highAvailability", {}).get("mode") == "ZoneRedundant",
                           "public_network": p.get("network", {}).get("publicNetworkAccess")})
        b.link(nid, p.get("network", {}).get("delegatedSubnetResourceId"), "attached_to")
        _cmk(b, nid, (p.get("dataEncryption") or {}).get("primaryKeyURI"))
    return handler


def _plan(b, row, p):
    sku = row.get("sku") or {}
    b.add(row, "compute.plan", "Microsoft.Web/serverFarms", "plan", props={"sku": sku.get("name"), "tier": sku.get("tier")})


def _site(b, row, p):
    is_fn = "functionapp" in _lc(row.get("kind"))
    nid = b.add(row, "compute.function" if is_fn else "compute.app", "Microsoft.Web/sites", "site",
                props={"state": p.get("state"), "https_only": p.get("httpsOnly")})
    b.link(nid, p.get("serverFarmId"), "runs_on", "app service plan")
    b.link(nid, p.get("virtualNetworkSubnetId"), "attached_to")
    b.identities(nid, row)


def _vault(b, row, p):
    acls = p.get("networkAcls") or {}
    public = p.get("publicNetworkAccess") or ("Disabled" if acls.get("defaultAction") == "Deny" else "Enabled")
    b.add(row, "iam.vault", "Microsoft.KeyVault/vaults", "vault",
          props={"sku": p.get("sku", {}).get("name"), "purge_protection": bool(p.get("enablePurgeProtection")),
                 "rbac_authorization": bool(p.get("enableRbacAuthorization")), "public_network": public})
    arm = _lc(row["id"])
    b.vault_by_name[_lc(row["name"])] = arm
    b.vault_cfg[arm] = {"policies": p.get("accessPolicies") or [], "rbac": bool(p.get("enableRbacAuthorization"))}


def _des(b, row, p):
    nid = b.add(row, "iam.encryption_set", "Microsoft.Compute/diskEncryptionSets", "des",
                props={"encryption_type": p.get("encryptionType")})
    _cmk(b, nid, (p.get("activeKey") or {}).get("keyUrl"))
    b.identities(nid, row)


def _aks(b, row, p):
    pools = p.get("agentPoolProfiles", [])
    nid = b.add(row, "compute.cluster", "Microsoft.ContainerService/managedClusters", "aks",
                props={"kubernetes_version": p.get("kubernetesVersion"), "nodes": sum(x.get("count", 0) for x in pools)})
    for pool in pools:
        b.link(nid, pool.get("vnetSubnetID"), "attached_to")
    kms = (p.get("securityProfile") or {}).get("azureKeyVaultKms") or {}
    if kms.get("enabled"):
        _cmk(b, nid, kms.get("keyId"))
    b.identities(nid, row)


HANDLERS = {
    "microsoft.network/virtualnetworks": _vnet,
    "microsoft.network/networksecuritygroups": _nsg,
    "microsoft.network/networkinterfaces": _nic,
    "microsoft.network/publicipaddresses": _public_ip,
    "microsoft.network/loadbalancers": _lb,
    "microsoft.compute/virtualmachines": _vm,
    "microsoft.compute/diskencryptionsets": _des,
    "microsoft.managedidentity/userassignedidentities": _identity,
    "microsoft.storage/storageaccounts": _storage,
    "microsoft.sql/servers": _sql_server,
    "microsoft.sql/servers/databases": _sql_db,
    "microsoft.dbforpostgresql/flexibleservers": _flex("postgres", "Microsoft.DBforPostgreSQL/flexibleServers"),
    "microsoft.dbformysql/flexibleservers": _flex("mysql", "Microsoft.DBforMySQL/flexibleServers"),
    "microsoft.web/serverfarms": _plan,
    "microsoft.web/sites": _site,
    "microsoft.keyvault/vaults": _vault,
    "microsoft.containerservice/managedclusters": _aks,
}


# ---------------------------------------------------------------------------
# Key Vault: items, access and usage. `kv` is the normalised data collect_keyvault() returns:
#   {"listed_secrets": [vault ARM id], "listed_keys": [...], "items": [...], "refs": [...], "assignments": [...]}
# ---------------------------------------------------------------------------
def _kv_target(b, uri):
    m = KV_URI.match(uri or "")
    return (b.vault_by_name.get(m.group(1).lower()), m.group(2).lower(), m.group(3)) if m else (None, None, None)


def _kv_item_node(b, vault_arm, folder, name, *, display=None, props=None, tags=None, kind=None) -> str:
    vault_nid = b.arm[vault_arm]
    is_key = folder == "keys"
    arm = f"{vault_arm}/{folder}/{_lc(name)}"
    nid = f"azure:kv{'key' if is_key else 'secret'}:{arm}"
    b.arm[arm] = nid
    b.fallback[nid] = b.fallback.get(vault_nid)
    b.em.node(nid, kind or ("iam.key" if is_key else "iam.secret"), display or name, vault_nid,
              native_type=f"Microsoft.KeyVault/vaults/{folder}", region=b.em.get(vault_nid).get("region"),
              props=props, tags=tags)
    return nid


def _kv_target_node(b, listed: set, vault_arm, folder, name, display):
    """The node for a secret/key someone points at. If we listed that vault and it is not there,
    it really does not exist: show it as missing instead of silently dropping the relationship."""
    nid = b.arm.get(f"{vault_arm}/{folder}/{_lc(name)}")
    if nid:
        return nid
    if vault_arm in listed:
        return _kv_item_node(b, vault_arm, folder, name, display=display, props={"missing": True})
    return None


def _keyvault(b: _Builder, kv: dict) -> None:
    em = b.em
    listed_s, listed_k = {_lc(x) for x in kv.get("listed_secrets", [])}, {_lc(x) for x in kv.get("listed_keys", [])}

    for it in kv.get("items", []):                                       # the items themselves: names and status only
        vault_arm = _lc(it["vault_id"])
        if vault_arm not in b.arm:
            continue
        is_key = it["type"] == "key"
        cert = not is_key and _lc(it.get("content_type")) in CERT_CONTENT_TYPES
        _kv_item_node(b, vault_arm, "keys" if is_key else "secrets", it["name"],
                      kind="iam.key" if is_key else "iam.certificate" if cert else "iam.secret",
                      props={"enabled": it.get("enabled"), "expires": it.get("expires"), "not_before": it.get("not_before"),
                             "created": it.get("created"), "updated": it.get("updated"),
                             "content_type": None if is_key else it.get("content_type"),
                             "key_type": it.get("key_type"), "key_size": it.get("key_size"), "curve": it.get("curve"),
                             "stored_as": "secret" if cert else None},
                      tags=_tags(it.get("tags")))

    for r in kv.get("refs", []):                                         # app -> secret (Key Vault references)
        app, vault_arm = b.arm.get(_lc(r.get("app_id"))), b.vault_by_name.get(_lc(r.get("vault")))
        if not app or not vault_arm:
            continue
        tgt = _kv_target_node(b, listed_s, vault_arm, "secrets", r["secret"], r["secret"])
        if tgt:
            em.edge(app, tgt, "reads_secret", r.get("setting"), status=r.get("status"))
        else:                                                            # vault known, secrets not listed
            em.edge(app, b.arm[vault_arm], "uses", f"secret {r['secret']}", status=r.get("status"))

    for src, uri in b.cmk:                                               # resource -> key (customer-managed keys)
        vault_arm, folder, name = _kv_target(b, uri)
        if not vault_arm:
            continue
        tgt = _kv_target_node(b, listed_k, vault_arm, folder, name, name)
        em.edge(src, tgt or b.arm[vault_arm], "encrypted_with" if tgt else "uses", "customer-managed key")

    others: dict[str, set] = defaultdict(set)

    def grant(principal_id, vault_arm, label, access):
        arm = b.principals.get(_lc(principal_id))
        nid = b.arm.get(arm) if arm else None
        if nid:
            em.edge(nid, b.arm[vault_arm], "can_access", label, access=access)
        else:
            others[vault_arm].add(_lc(principal_id))                     # a person, group or app outside this scan

    for vault_arm, cfg in b.vault_cfg.items():                           # access policies
        for pol in cfg["policies"]:
            perms = pol.get("permissions") or {}
            areas = [a for a in ("keys", "secrets", "certificates") if perms.get(a)]
            grant(pol.get("objectId"), vault_arm,
                  "; ".join(f"{a}: {', '.join(str(x).lower() for x in perms[a])}" for a in areas) or "no permissions",
                  [f"{a}:{str(x).lower()}" for a in areas for x in perms[a]])
    for a in kv.get("assignments", []):                                  # RBAC role assignments
        role = KV_ROLES.get(_lc(a.get("roleDefinitionId")).rsplit("/", 1)[-1])
        scope = _lc(a.get("scope")).rstrip("/")
        if not role or not scope:
            continue
        for vault_arm, cfg in b.vault_cfg.items():
            if cfg["rbac"] and (vault_arm == scope or vault_arm.startswith(scope + "/")):
                grant(a.get("principalId"), vault_arm, role[0], role[1])
    for vault_arm, who in others.items():
        em.get(b.arm[vault_arm]).setdefault("props", {})["other_principals"] = len(who)


# ---------------------------------------------------------------------------
# build: rows -> records
# ---------------------------------------------------------------------------
def build(em: Emitter, containers: list[dict], rows: list[dict], kv: dict | None = None) -> None:
    b = _Builder(em)
    failed: dict[str, list] = defaultdict(list)

    for c in containers:
        t = _lc(c.get("type"))
        if t == "microsoft.resources/subscriptions":
            chain = c.get("properties", {}).get("managementGroupAncestorsChain", [])
            b.subscription(c["subscriptionId"], c.get("name"), chain)
    for c in containers:
        if _lc(c.get("type")) == "microsoft.resources/subscriptions/resourcegroups":
            b.resource_group(c["subscriptionId"], c["name"], c.get("location"), c.get("tags"))

    for row in rows:
        t = _lc(row.get("type"))
        if t in IGNORED_TYPES:
            continue
        handler = HANDLERS.get(t)
        if handler is None:
            b.unmapped[row.get("type", "unknown")] += 1
            continue
        try:
            handler(b, row, row.get("properties") or {})
        except Exception as e:  # noqa: BLE001 - real tenants contain shapes nobody planned for
            failed[row.get("type", "unknown")].append(f"{row.get('name', '?')}: {type(e).__name__} {e}")
    for rtype, why in failed.items():
        em.error(f"mapping/{rtype}", f"{len(why)} resource(s) could not be mapped and are missing from the map "
                 f"(first: {why[0][:160]})")

    _keyvault(b, kv or {})                                  # always: access policies live on the vault itself

    for src, dst_arm, rel, label in b.edges:                # relationships, now that every node exists
        dst = b.arm.get(dst_arm)
        if dst:
            em.edge(src, dst, rel, label)
    for lb, nic in b.lb_backends:
        vm = b.vm_by_nic.get(nic)
        if vm:
            em.edge(lb, vm, "routes_to")
    for rec in em.nodes():                                   # never leave a parent pointing at nothing
        if rec["parent"] and not em.get(rec["parent"]):
            rec["parent"] = b.fallback.get(rec["id"])

    subs = sorted({n["name"] for n in em.nodes() if n["kind"] == "account"})
    em.scope.update({"subscriptions": subs,
                     "regions": sorted({n["region"] for n in em.nodes() if n.get("region")})})
    if b.unmapped:
        em.scope["unmapped"] = dict(b.unmapped)


# ---------------------------------------------------------------------------
# SDK layer: the only code that talks to Azure
# ---------------------------------------------------------------------------
KEYVAULT_PACKAGES = {"azure.mgmt.keyvault": "azure-mgmt-keyvault", "azure.mgmt.web": "azure-mgmt-web"}


def _missing_keyvault_sdk() -> list[str]:
    """pip package names Key Vault reading needs that are not installed."""
    import importlib.util
    missing = []
    for module, package in KEYVAULT_PACKAGES.items():
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            found = False
        if not found:
            missing.append(package)
    return missing


def _graph_client(credential=None):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
    except ImportError as e:
        raise SystemExit('Azure SDK missing: pip install azure-identity azure-mgmt-resourcegraph') from e
    if not os.environ.get("AZURE_LOG_LEVEL"):                # the SDK prints a page of credential diagnostics on a failed sign-in
        logging.getLogger("azure").setLevel(logging.CRITICAL)  # our one-line message says what to do; set AZURE_LOG_LEVEL=info for detail
    return ResourceGraphClient(credential or DefaultAzureCredential())


def _query(client, query: str, subscriptions, say) -> list[dict]:
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
    rows, token = [], None
    while True:
        opts = QueryRequestOptions(top=1000, skip_token=token, result_format="objectArray")
        resp = client.resources(QueryRequest(query=query, subscriptions=subscriptions or None, options=opts))
        rows.extend(resp.data)
        token = resp.skip_token
        say(f"  fetched {len(rows)} rows")
        if not token:
            return rows


def fetch(subscriptions: list[str] | None, em: Emitter, say=lambda _m: None, credential=None, client=None):
    client = client or _graph_client(credential)
    try:
        say("Reading resources from Azure Resource Graph")
        rows = _query(client, RESOURCES_QUERY, subscriptions, say)
    except Exception as e:  # noqa: BLE001
        why = (str(e).strip().splitlines() or [""])[0]            # the SDK lists every credential it tried: keep the first line
        raise SystemExit(f"Could not read Azure Resource Graph ({type(e).__name__}: {why}). Sign in with "
                         "`az login` (or set AZURE_* variables) and make sure the identity has the "
                         "Reader role. See: cloudmap-portal policy azure") from e
    try:
        say("Reading subscriptions and resource groups")
        containers = _query(client, CONTAINERS_QUERY, subscriptions, say)
    except Exception as e:  # noqa: BLE001 - names and hierarchy are nice-to-have
        em.error("resourcecontainers", f"{type(e).__name__}: {e}")
        containers = []
    return containers, rows


# --- Key Vault normalisers: whitelist of fields, `value` / key material deliberately absent ---
def _iso(dt):
    return None if dt is None else (dt.isoformat().replace("+00:00", "Z") if hasattr(dt, "isoformat") else str(dt))


def _enum(v):
    return getattr(v, "value", v)


def secret_item(vault_arm: str, s) -> dict:
    p = getattr(s, "properties", None)
    a = getattr(p, "attributes", None)
    return {"vault_id": vault_arm, "type": "secret", "name": s.name, "enabled": getattr(a, "enabled", None),
            "expires": _iso(getattr(a, "expires", None)), "not_before": _iso(getattr(a, "not_before", None)),
            "created": _iso(getattr(a, "created", None)), "updated": _iso(getattr(a, "updated", None)),
            "content_type": getattr(p, "content_type", None), "tags": dict(getattr(s, "tags", None) or {})}


def key_item(vault_arm: str, k) -> dict:
    p = getattr(k, "properties", None)
    a = getattr(p, "attributes", None)
    return {"vault_id": vault_arm, "type": "key", "name": k.name, "enabled": getattr(a, "enabled", None),
            "expires": _iso(getattr(a, "expires", None)), "not_before": _iso(getattr(a, "not_before", None)),
            "created": _iso(getattr(a, "created", None)), "updated": _iso(getattr(a, "updated", None)),
            "key_type": _enum(getattr(p, "kty", None)), "key_size": getattr(p, "key_size", None),
            "curve": _enum(getattr(p, "curve_name", None)), "tags": dict(getattr(k, "tags", None) or {})}


def reference_item(app_arm: str, r) -> dict | None:
    p = getattr(r, "properties", None) or r
    vault, secret = getattr(p, "vault_name", None), getattr(p, "secret_name", None)
    if not vault or not secret:
        return None                                                      # malformed reference: nothing to link
    return {"app_id": app_arm, "setting": r.name, "vault": vault, "secret": secret,
            "version": getattr(p, "secret_version", None), "status": str(_enum(getattr(p, "status", None)) or "Unknown"),
            "identity": _enum(getattr(p, "identity_type", None))}


class SdkKeyVaultSource:
    """Lists vault items and app Key Vault references through the management API (Reader-level, no values)."""

    def __init__(self, credential=None, kv_client=None, web_client=None):
        self._cred, self._kv_factory, self._web_factory = credential, kv_client, web_client
        self._kv, self._web = {}, {}

    def _credential(self):
        if self._cred is None:
            from azure.identity import DefaultAzureCredential
            self._cred = DefaultAzureCredential()
        return self._cred

    def _kv_client(self, sub):
        if sub not in self._kv:
            if self._kv_factory:
                self._kv[sub] = self._kv_factory(sub)
            else:
                from azure.mgmt.keyvault import KeyVaultManagementClient
                self._kv[sub] = KeyVaultManagementClient(self._credential(), sub)
        return self._kv[sub]

    def _web_client(self, sub):
        if sub not in self._web:
            if self._web_factory:
                self._web[sub] = self._web_factory(sub)
            else:
                from azure.mgmt.web import WebSiteManagementClient
                self._web[sub] = WebSiteManagementClient(self._credential(), sub)
        return self._web[sub]

    def secrets(self, sub, rg, vault, vault_arm):
        return [secret_item(vault_arm, s) for s in self._kv_client(sub).secrets.list(rg, vault)]

    def keys(self, sub, rg, vault, vault_arm):
        return [key_item(vault_arm, k) for k in self._kv_client(sub).keys.list(rg, vault)]

    def app_references(self, sub, rg, app, app_arm):
        refs = (reference_item(app_arm, r) for r in self._web_client(sub).web_apps.get_app_settings_key_vault_references(rg, app))
        return [r for r in refs if r]


def collect_keyvault(rows: list[dict], source, em: Emitter, say=lambda _m: None) -> dict:
    """Read vault items and app references. One unreadable vault or app never stops the scan; failures
    are summarised as a single scan error per kind so a permissions gap reads as one clear message."""
    ids = lambda r: (r.get("subscriptionId") or _lc(r["id"]).split("/")[2], r.get("resourceGroup") or _lc(r["id"]).split("/")[4], r["name"], _lc(r["id"]))  # noqa: E731
    vaults = [r for r in rows if _lc(r.get("type")) == "microsoft.keyvault/vaults"]
    sites = [r for r in rows if _lc(r.get("type")) == "microsoft.web/sites"]
    kv = {"listed_secrets": [], "listed_keys": [], "items": [], "refs": [], "assignments": []}
    failed: dict[str, list] = {"secrets": [], "keys": [], "app-references": []}

    for v in vaults:
        sub, rg, name, arm = ids(v)
        say(f"  key vault {name}")
        for what, fn, listed in (("secrets", source.secrets, "listed_secrets"), ("keys", source.keys, "listed_keys")):
            try:
                kv["items"].extend(fn(sub, rg, name, arm))
                kv[listed].append(arm)
            except Exception as e:  # noqa: BLE001
                failed[what].append(f"{name}: {type(e).__name__}")
    for i, s in enumerate(sites, 1):
        sub, rg, name, arm = ids(s)
        if i % 25 == 0 or i == len(sites):
            say(f"  app references: {i} of {len(sites)} apps")
        try:
            kv["refs"].extend(source.app_references(sub, rg, name, arm))
        except Exception as e:  # noqa: BLE001
            failed["app-references"].append(f"{name}: {type(e).__name__}")

    totals = {"secrets": len(vaults), "keys": len(vaults), "app-references": len(sites)}
    for what, fails in failed.items():
        if fails:
            em.error(f"keyvault/{what}", f"{len(fails)} of {totals[what]} could not be read ({fails[0]}"
                     f"{', ...' if len(fails) > 1 else ''}). Those relationships are missing from the map.")
    return kv


def collect_assignments(client, subscriptions, em: Emitter, say=lambda _m: None) -> list[dict]:
    try:
        say("Reading Key Vault role assignments")
        return _query(client, ASSIGNMENTS_QUERY, subscriptions, say)
    except Exception as e:  # noqa: BLE001
        em.error("keyvault/role-assignments", f"{type(e).__name__}: {e}")
        return []


def scan(em: Emitter, subscriptions: list[str] | None = None, progress=None, credential=None, client=None,
         keyvault: bool = True, kv_source=None) -> None:
    say = progress or (lambda _m: None)
    if keyvault and kv_source is None:
        missing = _missing_keyvault_sdk()
        if missing:                                          # not fatal: the rest of the scan is still worth having
            fix, names = f"pip install {' '.join(missing)}", " and ".join(missing)
            verb = "is" if len(missing) == 1 else "are"
            say(f"WARNING: Key Vault details will be skipped because {names} {verb} not installed ({fix}).")
            em.error("keyvault", f"Key Vault secrets, access and references were skipped: {names} {verb} "
                     f"not installed. Run: {fix}   then scan again (or pass --skip-keyvault to silence this).")
            keyvault = False
    client = client or _graph_client(credential)
    containers, rows = fetch(subscriptions, em, say, credential, client)
    kv = None
    if keyvault:
        kv = collect_keyvault(rows, kv_source or SdkKeyVaultSource(credential), em, say)
        kv["assignments"] = collect_assignments(client, subscriptions, em, say)
    say(f"Mapping {len(rows)} resources")
    build(em, containers, rows, kv)
