"""Attack paths: how something on the internet can reach something worth protecting.

Follows only edges that mean "can reach / can act as / can read": routing, identity
assumption, access grants, secret reads, storage reads. Network plumbing (subnet, NSG
membership) is not a hop. Paths are structural, not proof of exploitability.
"""
from __future__ import annotations

from collections import deque

from .ctx import CROWN_KINDS, CROWN_KINDS_PREFIX, NET_KINDS

HOP_RELS = {"routes_to", "assumes", "can_access", "reads_secret", "reads_from", "encrypted_with", "uses"}
WEIGHT = {"data": 30, "storage": 25, "iam.secret": 30, "iam.key": 30, "iam.certificate": 20, "iam.vault": 20}


def _crown(n):
    k = n["kind"]
    return k in CROWN_KINDS or k.startswith(CROWN_KINDS_PREFIX)


def _weight(n):
    k = n["kind"]
    return WEIGHT.get(k) or WEIGHT.get(k.split(".")[0], 10)


def find(c, limit=10, max_hops=5):
    exposed = c.exposed_workloads()
    seen_pairs, paths = set(), []
    for entry_id, why in exposed.items():
        entry = c.nodes[entry_id]
        if entry["kind"] in NET_KINDS and entry["kind"] != "network.public_ip":
            continue
        prev, q = {entry_id: None}, deque([(entry_id, 0)])
        while q:
            cur, d = q.popleft()
            if d >= max_hops:
                continue
            for e in c.out(cur):
                if e["rel"] not in HOP_RELS:
                    continue
                nxt = e["to"]
                tn = c.nodes[nxt]
                if e["rel"] == "uses" and not _crown(tn):
                    continue                       # network plumbing is not a hop
                if nxt in prev:
                    continue
                prev[nxt] = (cur, e)
                q.append((nxt, d + 1))
        for tgt, link in prev.items():
            if tgt == entry_id or not _crown(c.nodes[tgt]) or (entry_id, tgt) in seen_pairs:
                continue
            seen_pairs.add((entry_id, tgt))
            chain, cur = [], tgt
            while prev[cur]:
                p, e = prev[cur]
                chain.append((p, e, cur))
                cur = p
            chain.reverse()
            hops = [{"id": entry_id, "name": entry["name"], "kind": entry["kind"]}]
            for _, e, nid in chain:
                n = c.nodes[nid]
                hops.append({"id": nid, "name": n["name"], "kind": n["kind"], "via": e["rel"]})
            tn = c.nodes[tgt]
            score = _weight(tn) + (10 if c.is_prod(tn) else 0) - 4 * (len(hops) - 1) + (6 if len(why) > 1 else 0)
            paths.append({"entry": entry_id, "target": tgt, "entry_reasons": why, "hops": hops,
                          "score": score, "severity": "high" if score >= 24 else "medium",
                          "text": " → ".join(h["name"] for h in hops)})
    paths.sort(key=lambda p: -p["score"])
    out, per_target = [], {}
    for p in paths:                                # don't let one crown jewel flood the list
        per_target[p["target"]] = per_target.get(p["target"], 0) + 1
        if per_target[p["target"]] <= 2:
            out.append(p)
    return out[:limit]
