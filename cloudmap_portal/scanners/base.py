from __future__ import annotations

from datetime import datetime, timezone

from ..schema import SCHEMA_VERSION


class Emitter:
    """Collects normalized records. Scanners only talk to this, never to the file."""

    def __init__(self, provider: str, scan_id: str, scope: dict | None = None,
                 scanned_at: str | None = None, tool_version: str = "0.1.0"):
        self.meta = {
            "type": "meta", "schema": SCHEMA_VERSION, "provider": provider,
            "scan_id": scan_id,
            "scanned_at": scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope": scope or {}, "tool_version": tool_version,
        }
        self.scope = self.meta["scope"]
        self._nodes: dict = {}
        self._edges: dict = {}
        self._errors: list = []

    def node(self, id: str, kind: str, name: str, parent: str | None = None, *,
             native_type: str | None = None, region: str | None = None,
             props: dict | None = None, tags: dict | None = None) -> str:
        rec = {"type": "node", "id": id, "kind": kind, "name": name, "parent": parent}
        props = {k: v for k, v in (props or {}).items() if v is not None}
        if native_type: rec["native_type"] = native_type
        if region: rec["region"] = region
        if props: rec["props"] = props
        if tags: rec["tags"] = tags
        self._nodes[id] = rec
        return id

    def get(self, id: str) -> dict | None:
        return self._nodes.get(id)

    def nodes(self):
        return self._nodes.values()

    def edge(self, src: str, dst: str, rel: str, label: str | None = None, **extra) -> None:
        """Add a relationship. Repeating the same (src, dst, rel) merges labels and permissions
        instead of replacing them, e.g. one app reading one secret through two settings."""
        rec = {"type": "edge", "from": src, "to": dst, "rel": rel}
        if label: rec["label"] = label
        rec.update({k: v for k, v in extra.items() if v is not None})
        old = self._edges.get((src, dst, rel))
        if old:
            if old.get("label") and label and label not in old["label"]:
                rec["label"] = f"{old['label']}; {label}"
            elif old.get("label") and not label:
                rec["label"] = old["label"]
            if "access" in old and "access" in rec:
                rec["access"] = sorted(set(old["access"]) | set(rec["access"]))
            if old.get("status") not in (None, "Resolved") and rec.get("status") in (None, "Resolved"):
                rec["status"] = old["status"]                      # a failure is never hidden by a later success
        self._edges[(src, dst, rel)] = rec

    def error(self, scope: str, message: str) -> None:
        self._errors.append({"type": "error", "scope": scope, "message": message})

    def records(self):
        yield self.meta
        yield from self._nodes.values()
        yield from self._edges.values()
        yield from self._errors


def sort_ports(ports) -> list[str]:
    """['all'] first, then numeric ports and ranges in order."""
    def key(p):
        head = p.split("-")[0]
        return (p != "all", int(head) if head.isdigit() else 0, p)
    return sorted(set(ports), key=key)
