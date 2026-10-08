"""Plain-language findings and stats derived from an Inventory.

Everything here is inferred only from what the scan could read. Findings that depend
on missing references say so in `why`, so they read as prompts to check, not verdicts.
Wording adapts to the provider (security group / network security group / firewall rule).
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

from .schema import SCOPE_KINDS

LAYER_ORDER = ("network", "compute", "data", "storage", "iam")
TAGGABLE_LAYERS = {"compute", "data", "storage"}
TAGGABLE_KINDS = {"network.load_balancer", "network.vpc"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "note": 3}
IDENTITY_KINDS = {"iam.role", "iam.identity"}
KV_ITEM_KINDS = {"iam.secret", "iam.key", "iam.certificate"}
KV_USE_RELS = ("reads_secret", "encrypted_with")
KV_WRITE = {"set", "delete", "purge", "create", "update", "import", "rotate", "backup", "restore", "recover", "all", "*"}
NOUNS = {   # provider -> (access-group noun, identity noun singular/plural, top-level scope noun)
    "aws":   ("security group", ("IAM role", "IAM roles"), "account"),
    "azure": ("network security group", ("identity", "identities"), "subscription"),
    "gcp":   ("firewall rule", ("identity", "identities"), "project"),
}


def layer_of(kind: str) -> str:
    return "scope" if kind in SCOPE_KINDS else kind.split(".")[0]


def _n(count: int, one: str, many: str | None = None) -> str:
    return f"{count} {one if count == 1 else (many or one + 's')}"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _when(iso):
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def analyze(inv) -> dict:
    nodes = inv.nodes
    provider = inv.meta.get("provider", "aws")
    group, (id_one, id_many), scope_noun = NOUNS.get(provider, NOUNS["aws"])

    def incoming(nid, *rels):
        return [e for e in inv._in.get(nid, []) if e["rel"] in rels]

    findings: list[dict] = []

    def add(fid, severity, title, why, advice, resources=(), details=()):
        resources = sorted(resources)
        findings.append({"id": fid, "severity": severity, "title": title, "why": why,
                         "advice": advice, "resources": resources, "count": len(resources),
                         "details": list(details)})

    # -- the scan itself ---------------------------------------------------
    if inv.errors:
        add("scan-gaps", "medium",
            f"The scan couldn't read {_n(len(inv.errors), 'area')}",
            "Anything in these areas is missing from the map, so findings below may be incomplete.",
            "Grant the scanner read access to these services and run it again.",
            details=[f"{e['scope']}: {e['message']}" for e in inv.errors])

    unmapped = inv.meta.get("scope", {}).get("unmapped") or {}
    if unmapped:
        total = sum(unmapped.values())
        top = sorted(unmapped.items(), key=lambda kv: -kv[1])
        add("unmapped-types", "note",
            f"{_n(total, 'resource')} of {_n(len(unmapped), 'type')} aren't on the map",
            "The scanner found these but doesn't know how to place them yet, so they are not "
            "in any count or finding here.",
            "Most are supporting resources such as disks and monitoring. Ask for a collector if "
            "one of them matters to you.",
            details=[f"{t}: {c}" for t, c in top[:15]])

    # -- exposure ------------------------------------------------------------
    exposed, exposed_notes = [], []
    for n in nodes.values():
        risky = [p for p in n.get("props", {}).get("world_open_ports", []) if p not in ("80", "443")]
        if risky:
            exposed.append(n)
            exposed_notes.append(f"{n['name']}: {', '.join(risky)}")
    if exposed:
        kinds = {group if n["kind"] == "network.security_group" else "database" for n in exposed}
        noun = kinds.pop() if len(kinds) == 1 else "resource"
        users = {e["from"] for n in exposed if n["kind"] == "network.security_group"
                 for e in incoming(n["id"], "uses", "attached_to")}
        add("exposed-ports", "high",
            f"{_n(len(exposed), noun)} {'lets' if len(exposed) == 1 else 'let'} the whole "
            "internet in on sensitive ports",
            "Anyone on the internet can try to connect to these ports, such as remote login or a "
            "database. Resources using the rule are exposed unless something else blocks it.",
            "Limit the source to known addresses or a VPN, or remove the rule.",
            [n["id"] for n in exposed] + sorted(users), exposed_notes)

    public_blobs = [n["id"] for n in nodes.values() if n.get("props", {}).get("allows_public_blobs")]
    if public_blobs:
        add("public-blobs", "medium",
            f"{_n(len(public_blobs), 'storage account')} {'allows' if len(public_blobs) == 1 else 'allow'} "
            "public access to blobs",
            "The account-level switch is on, so any container set to public can be read by anyone. "
            "Individual containers may still be private.",
            "Turn off public blob access unless a site is meant to serve files from here.",
            public_blobs)

    # -- tagging -------------------------------------------------------------
    taggable = [n for n in nodes.values()
                if layer_of(n["kind"]) in TAGGABLE_LAYERS or n["kind"] in TAGGABLE_KINDS]
    untagged = [n["id"] for n in taggable if not n.get("tags")]
    coverage = (round(100 * (len(taggable) - len(untagged)) / len(taggable))
                if taggable else None)
    if untagged:
        label_word = "labels" if provider == "gcp" else "tags"
        add("untagged", "medium" if coverage is not None and coverage < 50 else "low",
            f"{len(untagged)} of {len(taggable)} resources have no {label_word}",
            f"Without {label_word} such as owner or environment it is hard to tell who runs a "
            "resource, what it costs, or whether it is safe to change.",
            f"Agree on a small set (owner, env) and apply it to data and compute resources first.",
            untagged)

    # -- availability --------------------------------------------------------
    single_az = [n["id"] for n in nodes.values()
                 if n["kind"] == "data.database" and n.get("props", {}).get("multi_az") is False]
    if single_az:
        add("single-az", "medium",
            f"{_n(len(single_az), 'database')} {'runs' if len(single_az) == 1 else 'run'} "
            "in a single availability zone",
            "If that zone has an outage, these databases and everything depending on them go down.",
            "Enable zone redundancy or a standby, or confirm the risk is accepted for these databases.",
            single_az)

    # -- identity ------------------------------------------------------------
    shared = []
    for n in nodes.values():
        if n["kind"] in IDENTITY_KINDS:
            users = {e["from"] for e in incoming(n["id"], "assumes")}
            if len(users) >= 3:
                shared.append((len(users), n, users))
    for count, role, users in sorted(shared, key=lambda t: -t[0])[:5]:
        add(f"shared-role-{_slug(role['name'])}", "medium",
            f"{role['name']} is shared by {count} resources",
            "A leaked credential or a permission change on this identity affects all of them at once.",
            "Split it into narrower identities per workload so each gets only what it needs.",
            [role["id"], *users])

    unused_roles = [n["id"] for n in nodes.values()
                    if n["kind"] in IDENTITY_KINDS and not incoming(n["id"], "assumes")]
    if unused_roles:
        add("unused-roles", "low",
            f"{_n(len(unused_roles), id_one, id_many)} {'has' if len(unused_roles) == 1 else 'have'} "
            "no known users",
            "No scanned resource uses them. People or services outside this scan may still do so.",
            "Check last-used information before removing anything.",
            unused_roles)

    # -- network hygiene -----------------------------------------------------
    orphan_sgs = [n["id"] for n in nodes.values()
                  if n["kind"] == "network.security_group" and n["name"] != "default"
                  and not incoming(n["id"], "uses", "attached_to")]
    if orphan_sgs:
        add("orphan-sg", "low",
            f"{_n(len(orphan_sgs), group)} {'isn' if len(orphan_sgs) == 1 else 'aren'}'t attached to anything",
            "Nothing in this scan uses it, so it applies to no resource. Unused rules clutter "
            "reviews and can be reattached by mistake.",
            "Confirm they are unused, then delete them.",
            orphan_sgs)

    # -- storage -------------------------------------------------------------
    loose = [n["id"] for n in nodes.values()
             if n["kind"] in ("storage.bucket", "storage.account") and not inv._in.get(n["id"])]
    if loose:
        add("loose-buckets", "note",
            f"{_n(len(loose), 'storage resource')} {'is' if len(loose) == 1 else 'are'} not referenced "
            "by any scanned resource",
            "The scanner only follows references it knows about, so storage used directly by "
            "applications also shows up here.",
            "Check ownership and access logs before acting.",
            loose)

    # -- Key Vault: secrets, keys and who depends on them. Names and status only, never values. --------------
    items = [n for n in nodes.values() if n["kind"] in KV_ITEM_KINDS]
    vaults = [n for n in nodes.values() if n["kind"] == "iam.vault"]
    now = _when(inv.meta.get("scanned_at")) or datetime.now(timezone.utc)
    vault_name = lambda n: nodes[n["parent"]]["name"] if n.get("parent") in nodes else "?"  # noqa: E731
    users_of = lambda n: sorted({e["from"] for e in inv._in.get(n["id"], []) if e["rel"] in KV_USE_RELS})  # noqa: E731
    names = lambda ids, k=3: ", ".join(nodes[i]["name"] for i in ids[:k]) + (f" and {len(ids) - k} more" if len(ids) > k else "")  # noqa: E731
    days = lambda n: ((_when(n.get("props", {}).get("expires")) - now).total_seconds() / 86400  # noqa: E731
                      if _when(n.get("props", {}).get("expires")) else None)
    live = [n for n in items if not n.get("props", {}).get("missing")]

    expired = [n for n in live if (days(n) is not None and days(n) < 0)]
    if expired:
        used = [n for n in expired if users_of(n)]
        add("kv-expired", "high" if used else "medium",
            f"{_n(len(expired), 'secret or key', 'secrets and keys')} {'has' if len(expired) == 1 else 'have'} expired",
            "Anything still using an expired secret or key can start failing, or keeps working with a credential "
            "that should have been rotated.",
            "Rotate each one and update what uses it. Used ones come first.",
            [n["id"] for n in expired] + sorted({u for n in expired for u in users_of(n)}),
            [f"{n['name']} in {vault_name(n)}: expired {int(-days(n))} days ago"
             + (f", used by {names(users_of(n))}" if users_of(n) else "") for n in sorted(expired, key=lambda n: (not users_of(n), days(n)))])

    expiring = [n for n in live if days(n) is not None and 0 <= days(n) <= 30]
    if expiring:
        add("kv-expiring", "medium",
            f"{_n(len(expiring), 'secret or key', 'secrets and keys')} {'expires' if len(expiring) == 1 else 'expire'} within 30 days",
            "Rotation is easy before the date and an outage after it.",
            "Schedule the rotation now, or enable automatic rotation where the vault supports it.",
            [n["id"] for n in expiring] + sorted({u for n in expiring for u in users_of(n)}),
            [f"{n['name']} in {vault_name(n)}: expires in {int(days(n))} days"
             + (f", used by {names(users_of(n))}" if users_of(n) else "") for n in sorted(expiring, key=days)])

    broken = [e for e in inv.edges if e.get("status") not in (None, "Resolved") and e["rel"] in ("reads_secret", "uses")]
    if broken:
        add("kv-broken-refs", "high",
            f"{_n(len(broken), 'app setting')} can't read {'its' if len(broken) == 1 else 'their'} Key Vault secret",
            "The app asked for this secret and Azure reported a problem, so the setting holds no value and "
            "the app may fail or run misconfigured.",
            "Open the status in the details and fix access, networking or the reference.",
            sorted({e["from"] for e in broken} | {e["to"] for e in broken}),
            [f"{nodes[e['from']]['name']} setting {e.get('label') or '?'}: {e['status']}" for e in broken])

    unusable = [n for n in items if users_of(n) and (n.get("props", {}).get("enabled") is False or n.get("props", {}).get("missing"))]
    if unusable:
        add("kv-unusable", "high",
            f"{_n(len(unusable), 'secret or key', 'secrets and keys')} in use "
            f"{'is' if len(unusable) == 1 else 'are'} disabled or missing",
            "Something depends on it, but it can't be read. Missing means nothing with that name exists in a vault we could list.",
            "Re-enable or create it, or point the dependent at the right one.",
            [n["id"] for n in unusable] + sorted({u for n in unusable for u in users_of(n)}),
            [f"{n['name']} in {vault_name(n)} is {'missing' if n['props'].get('missing') else 'disabled'}, used by {names(users_of(n))}" for n in unusable])

    writers = []
    for e in inv.edges:
        if e["rel"] != "can_access":
            continue
        risky = [a for a in e.get("access", []) if a.endswith(":*") or a.split(":", 1)[-1] in KV_WRITE]
        if risky:
            writers.append((e, risky))
    if writers:
        add("kv-writers", "medium",
            f"{_n(len({e['from'] for e, _ in writers}), 'workload')} can change or delete secrets or keys",
            "Applications normally only need to read. A workload that can write or delete turns a bug or a "
            "compromise into lost or altered secrets.",
            "Give workloads read-only access (get, list) and keep write access for people or a pipeline.",
            sorted({e["from"] for e, _ in writers} | {e["to"] for e, _ in writers}),
            [f"{nodes[e['from']]['name']} on {nodes[e['to']]['name']}: {', '.join(r.replace(':', ' ') for r in risky)}" for e, risky in writers])

    forever = [n for n in live if n["kind"] != "iam.certificate" and days(n) is None and n.get("props", {}).get("enabled") is not False]
    if forever:
        add("kv-no-expiry", "low",
            f"{_n(len(forever), 'secret or key', 'secrets and keys')} never {'expires' if len(forever) == 1 else 'expire'}",
            "Without an expiry date nothing reminds anyone to rotate it, and a leaked one stays valid indefinitely.",
            "Set an expiry that matches your rotation policy.",
            [n["id"] for n in forever],
            [f"{n['name']} in {vault_name(n)}" for n in forever])

    unprotected = [v for v in vaults if not v.get("props", {}).get("purge_protection")]
    if unprotected:
        add("kv-purge", "low",
            f"{_n(len(unprotected), 'key vault')} {'has' if len(unprotected) == 1 else 'have'} purge protection off",
            "A deleted vault or secret can be permanently purged right away, so a mistake or an attacker can't be undone.",
            "Turn on purge protection. It can't be turned off again, which is the point.",
            [v["id"] for v in unprotected])
    open_net = [v for v in vaults if v.get("props", {}).get("public_network") == "Enabled"]
    if open_net:
        add("kv-public", "low",
            f"{_n(len(open_net), 'key vault')} {'accepts' if len(open_net) == 1 else 'accept'} connections from any network",
            "Access still needs credentials, but a leaked credential works from anywhere on the internet.",
            "Restrict to selected networks or use a private endpoint.",
            [v["id"] for v in open_net])

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["count"]))

    # -- stats ---------------------------------------------------------------
    resources = [n for n in nodes.values() if n["kind"] not in SCOPE_KINDS]
    layers = Counter(layer_of(n["kind"]) for n in resources)
    ordered = {k: layers[k] for k in LAYER_ORDER if layers.get(k)}
    ordered.update({k: v for k, v in layers.items() if k not in ordered})

    hubs = []
    for nid, node in nodes.items():
        if inv.children.get(nid) or node["kind"] in SCOPE_KINDS:
            continue
        dependents = len({e["from"] for e in inv._in.get(nid, [])})
        if dependents >= 2:
            hubs.append({"id": nid, "name": node["name"], "kind": node["kind"],
                         "dependents": dependents})
    hubs = sorted(hubs, key=lambda h: -h["dependents"])[:6]

    accounts = [n["name"] for n in nodes.values() if n["kind"] == "account"]
    regions = sorted({n["name"] for n in nodes.values() if n["kind"] == "region"}
                     | {n["region"] for n in nodes.values() if n.get("region")})
    review = sum(1 for f in findings if f["severity"] in ("high", "medium"))

    headline = (f"{_n(len(resources), 'resource')} across {_n(len(accounts), scope_noun)} "
                f"and {_n(len(regions), 'region')}.")
    verdict = (f"{_n(review, 'finding')} to review first." if review
               else "Nothing urgent in what the scan could read.")
    if inv.errors:
        verdict += " The scan was partial, so some areas are missing."

    return {
        "headline": headline,
        "verdict": verdict,
        "stats": {
            "resources": len(resources), "relationships": len(inv.edges),
            "accounts": accounts, "regions": regions, "layers": ordered,
            "tag_coverage": coverage, "scan_errors": len(inv.errors),
        },
        "hubs": hubs,
        "findings": findings,
    }
