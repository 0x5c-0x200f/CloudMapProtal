"""Shareable reports: a standalone HTML page and a Markdown file."""
from __future__ import annotations

import html
from collections import Counter

from .insights import SEVERITY_ORDER  # noqa: F401  (re-exported for callers)

SEV_LABEL = {"high": "Urgent", "medium": "Review soon", "low": "Minor", "note": "Good to know"}
MAX_LISTED = 25


def _outline(inv):
    """Yield (depth, node, leaf_kind_counts) for the containment tree."""
    def walk(nid, depth):
        kids = inv.children.get(nid, [])
        containers = [k for k in kids if inv.children.get(k)]
        leaves = Counter(inv.nodes[k]["kind"] for k in kids if k not in containers)
        yield depth, inv.nodes[nid], leaves
        for k in sorted(containers, key=lambda i: inv.nodes[i]["name"]):
            yield from walk(k, depth + 1)
    for root in sorted(inv.children.get(None, []), key=lambda i: inv.nodes[i]["name"]):
        yield from walk(root, 0)


def _leaf_text(leaves: Counter) -> str:
    return ", ".join(f"{c} {k}" for k, c in sorted(leaves.items())) or "no direct resources"


def _title(inv) -> str:
    m = inv.meta
    return f"{m['provider'].upper()} scan {m['scan_id']}, {str(m['scanned_at'])[:10]}"


def render_markdown(inv, ins) -> str:
    L = [f"# CloudMap report", f"{_title(inv)}", "", ins["headline"], ins["verdict"], ""]
    st = ins["stats"]
    L += ["## At a glance",
          f"- Relationships found: {st['relationships']}",
          f"- Regions: {', '.join(st['regions']) or 'none'}",
          f"- Tag coverage: {st['tag_coverage']}%" if st["tag_coverage"] is not None else "- Tag coverage: n/a",
          "- Mix: " + ", ".join(f"{k} {v}" for k, v in st["layers"].items()), ""]
    L += ["## Findings", ""]
    if not ins["findings"]:
        L.append("No findings.\n")
    for f in ins["findings"]:
        L += [f"### {f['title']} ({SEV_LABEL[f['severity']]})", f["why"], f"**What to do:** {f['advice']}"]
        for d in f["details"]:
            L.append(f"- {d}")
        for rid in f["resources"][:MAX_LISTED]:
            L.append(f"- {inv.nodes[rid]['name']} (`{rid}`)")
        if f["count"] > MAX_LISTED:
            L.append(f"- and {f['count'] - MAX_LISTED} more")
        L.append("")
    if ins["hubs"]:
        L += ["## Most depended-on resources", ""]
        L += [f"- {h['name']} ({h['kind']}): {h['dependents']} dependents" for h in ins["hubs"]]
        L.append("")
    L += ["## Structure", ""]
    for depth, node, leaves in _outline(inv):
        L.append(f"{'  ' * depth}- {node['name']} ({node['kind']}): {_leaf_text(leaves)}")
    return "\n".join(L) + "\n"


def render_html(inv, ins) -> str:
    e = html.escape
    st = ins["stats"]
    parts = [f"<h1>CloudMap report</h1><p class='sub'>{e(_title(inv))}</p>",
             f"<p class='lede'>{e(ins['headline'])} {e(ins['verdict'])}</p>"]

    total = sum(st["layers"].values()) or 1
    parts.append("<h2>What's in the cloud</h2><table>")
    for k, v in st["layers"].items():
        parts.append(f"<tr><td>{e(k)}</td><td>{v}</td>"
                     f"<td><span class='bar' style='width:{100 * v / total:.0f}%'></span></td></tr>")
    parts.append("</table>")
    tag = f"{st['tag_coverage']}%" if st["tag_coverage"] is not None else "n/a"
    parts.append(f"<p>{st['relationships']} relationships. Regions: {e(', '.join(st['regions']) or 'none')}. "
                 f"Tag coverage: {tag}.</p>")

    parts.append("<h2>Findings</h2>")
    if not ins["findings"]:
        parts.append("<p>No findings.</p>")
    for f in ins["findings"]:
        parts.append(f"<section class='f {f['severity']}'><h3>{e(f['title'])} "
                     f"<small>{e(SEV_LABEL[f['severity']])}</small></h3>"
                     f"<p>{e(f['why'])}</p><p><b>What to do:</b> {e(f['advice'])}</p>")
        items = [e(d) for d in f["details"]]
        items += [f"{e(inv.nodes[r]['name'])} <code>{e(r)}</code>" for r in f["resources"][:MAX_LISTED]]
        if f["count"] > MAX_LISTED:
            items.append(f"and {f['count'] - MAX_LISTED} more")
        if items:
            parts.append("<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>")
        parts.append("</section>")

    if ins["hubs"]:
        parts.append("<h2>Most depended-on resources</h2><p>Changes here ripple furthest.</p><ul>")
        parts += [f"<li>{e(h['name'])} <small>{e(h['kind'])}</small>: {h['dependents']} dependents</li>"
                  for h in ins["hubs"]]
        parts.append("</ul>")

    parts.append("<h2>Structure</h2><ul class='tree'>")
    for depth, node, leaves in _outline(inv):
        parts.append(f"<li style='margin-left:{depth * 18}px'><b>{e(node['name'])}</b> "
                     f"<small>{e(node['kind'])}</small> {e(_leaf_text(leaves))}</li>")
    parts.append("</ul>")

    css = """body{font:15px/1.55 system-ui,sans-serif;color:#13222c;max-width:820px;margin:40px auto;padding:0 20px}
h1{margin:0}.sub{color:#4a5d6a;margin-top:4px}.lede{font-size:18px}h2{margin-top:36px;border-bottom:1px solid #d8e0e5;padding-bottom:6px}
table{border-collapse:collapse;width:100%}td{padding:4px 8px 4px 0}.bar{display:block;height:8px;background:#2f6fde;border-radius:4px}
.f{border-left:4px solid #5c6f7b;padding:2px 0 2px 14px;margin:18px 0}.f.medium,.f.high{border-color:#c77700}.f.note{border-color:#2f6fde}
.f h3{margin:0 0 6px}small{color:#4a5d6a;font-weight:400}code{font-size:12px;color:#4a5d6a}.tree{list-style:none;padding:0}
@media print{body{margin:0}}"""
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>CloudMap report: {e(_title(inv))}</title><style>{css}</style></head>"
            f"<body>{''.join(parts)}</body></html>")
