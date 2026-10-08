"""The .jsonci inventory format (JSON Lines, one record per line) and its reader.

Record types:
  meta  - exactly one, must be first: schema, provider, scan_id, scanned_at, scope
  node  - a resource or container. `parent` carries containment (the tree).
  edge  - a reference between two nodes (the graph): from, to, rel
  error - something the scanner could not read (partial scans stay honest)
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

SCHEMA_VERSION = "1.0"
PROVIDERS = ("aws", "azure", "gcp")
# Structure (not resources): everything that only groups other things.
SCOPE_KINDS = frozenset({"organization", "management_group", "folder", "account",
                         "resource_group", "region"})
REQUIRED = {
    "meta": ("schema", "provider", "scan_id", "scanned_at"),
    "node": ("id", "kind", "name"),
    "edge": ("from", "to", "rel"),
    "error": ("scope", "message"),
}


class SchemaError(ValueError):
    pass


def validate_record(rec, lineno: int = 0) -> None:
    where = f"line {lineno}: " if lineno else ""
    if not isinstance(rec, dict):
        raise SchemaError(f"{where}record must be a JSON object")
    rtype = rec.get("type")
    if rtype not in REQUIRED:
        raise SchemaError(f"{where}unknown record type {rtype!r}")
    missing = [k for k in REQUIRED[rtype] if k not in rec]
    if missing:
        raise SchemaError(f"{where}{rtype} record missing {', '.join(missing)}")
    if rtype == "meta":
        if rec["provider"] not in PROVIDERS:
            raise SchemaError(f"{where}unknown provider {rec['provider']!r}")
        if str(rec["schema"]).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise SchemaError(f"{where}unsupported schema version {rec['schema']!r}")


def filename_for(meta: dict) -> str:
    """{cloud_provider}-{scan_id}-{date}.jsonci"""
    return f"{meta['provider']}-{meta['scan_id']}-{str(meta['scanned_at'])[:10]}.jsonci"


@dataclass
class Inventory:
    meta: dict = field(default_factory=dict)
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    children: dict = field(default_factory=dict)
    _out: dict = field(default_factory=dict)
    _in: dict = field(default_factory=dict)

    # ---- loading -------------------------------------------------------
    @classmethod
    def load(cls, lines: Iterable) -> "Inventory":
        """Stream-parse records; never holds more than one raw line at a time."""
        inv = cls()
        for n, raw in enumerate(lines, 1):
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError as e:
                raise SchemaError(f"line {n}: invalid JSON ({e.msg})") from e
            validate_record(rec, n)
            rtype = rec["type"]
            if rtype == "meta":
                if inv.meta:
                    raise SchemaError(f"line {n}: duplicate meta record")
                inv.meta = rec
            elif not inv.meta:
                raise SchemaError(f"line {n}: first record must be 'meta'")
            elif rtype == "node":
                if rec["id"] in inv.nodes:
                    inv.warnings.append(f"duplicate node id ignored: {rec['id']}")
                else:
                    inv.nodes[rec["id"]] = rec
            elif rtype == "edge":
                inv.edges.append(rec)
            else:
                inv.errors.append(rec)
        if not inv.meta:
            raise SchemaError("file is empty")
        inv._finalize()
        return inv

    @classmethod
    def load_path(cls, path) -> "Inventory":
        with open(path, "r", encoding="utf-8") as f:
            return cls.load(f)

    def _finalize(self) -> None:
        for n in self.nodes.values():
            p = n.get("parent")
            if p and p not in self.nodes:
                self.warnings.append(f"{n['id']}: parent {p} not in file; treated as root")
                n["parent"] = None
        kept, seen = [], set()
        for e in self.edges:
            if e["from"] not in self.nodes or e["to"] not in self.nodes:
                self.warnings.append(f"dangling edge dropped: {e['from']} -> {e['to']}")
                continue
            key = (e["from"], e["to"], e["rel"])
            if key not in seen:
                seen.add(key)
                kept.append(e)
        self.edges = kept
        self.children = defaultdict(list)
        self._out, self._in = defaultdict(list), defaultdict(list)
        for n in self.nodes.values():
            self.children[n.get("parent")].append(n["id"])
        for e in self.edges:
            self._out[e["from"]].append(e)
            self._in[e["to"]].append(e)

    # ---- queries -------------------------------------------------------
    def blast(self, node_id: str, hops: int = 2, direction: str = "both") -> dict:
        """Everything `node_id` depends on (out) and everything depending on it (in)."""
        if node_id not in self.nodes:
            raise KeyError(node_id)
        seen, queue = {node_id}, deque([(node_id, 0)])
        while queue:
            cur, d = queue.popleft()
            if d >= hops:
                continue
            nxt = []
            if direction in ("both", "out"):
                nxt += [e["to"] for e in self._out.get(cur, [])]
            if direction in ("both", "in"):
                nxt += [e["from"] for e in self._in.get(cur, [])]
            for nb in nxt:
                if nb not in seen:
                    seen.add(nb)
                    queue.append((nb, d + 1))
        return {"nodes": sorted(seen)}

    def summary(self) -> dict:
        kinds: dict = defaultdict(int)
        for n in self.nodes.values():
            kinds[n["kind"]] += 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "kinds": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        }

    def to_graph(self) -> dict:
        return {
            "meta": self.meta,
            "summary": self.summary(),
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "errors": self.errors,
            "warnings": self.warnings[:50],
        }


def _sig(n: dict):
    return (n.get("name"), n.get("parent"),
            json.dumps(n.get("props", {}), sort_keys=True),
            json.dumps(n.get("tags", {}), sort_keys=True))


def diff(a: Inventory, b: Inventory) -> dict:
    """Compare two scans (a = older, b = newer). Stable global IDs make this cheap."""
    ea = {(e["from"], e["to"], e["rel"]) for e in a.edges}
    eb = {(e["from"], e["to"], e["rel"]) for e in b.edges}
    common = set(a.nodes) & set(b.nodes)
    return {
        "added": sorted(set(b.nodes) - set(a.nodes)),
        "removed": sorted(set(a.nodes) - set(b.nodes)),
        "changed": sorted(i for i in common if _sig(a.nodes[i]) != _sig(b.nodes[i])),
        "edges_added": sorted(eb - ea),
        "edges_removed": sorted(ea - eb),
    }
