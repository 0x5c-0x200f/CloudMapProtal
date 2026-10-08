"""CloudMap Agent: evidence-based analysis and Q&A over a loaded inventory.

`analyze(inv)` is deterministic and offline: same scan, same answers, no data leaves the machine.
`ask(inv, question, ...)` answers from the inventory itself and, only if the operator has
configured a language model, can hand the question (with a compact, secret-free digest) to it.
"""
from __future__ import annotations

import math

from . import hardening, paths, rules
from .ctx import Ctx
from .skills import CATEGORIES, SKILLS

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "note": 3}
WEIGHT = {"high": 12.0, "medium": 5.0, "low": 1.5, "note": 0.0}
CONF_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.5}


def _grade(score):
    return "A" if score >= 90 else "B" if score >= 78 else "C" if score >= 62 else "D" if score >= 45 else "F"


def analyze(inv) -> dict:
    c = Ctx(inv)
    findings = []
    for r in rules.RULES:
        if r["providers"] and c.provider not in r["providers"]:
            continue
        try:
            hits = r["fn"](c)
        except Exception as e:              # a broken rule must never take the agent down
            findings.append({"id": r["id"] + "-error", "rule": r["id"], "category": "misconfig", "severity": "note",
                             "title": f"Rule {r['id']} failed", "why": f"{type(e).__name__}: {e}", "fix": "",
                             "resources": [], "count": 0, "items": [], "cli": [], "skills": [], "confidence": "low",
                             "refs": []})
            continue
        for h in hits:
            res = sorted(dict.fromkeys(h.resources))
            findings.append({
                "id": r["id"], "rule": r["id"], "category": r["category"], "severity": h.severity or r["severity"],
                "title": r["title"], "why": r["why"], "fix": r["fix"], "resources": res, "count": len(res),
                "items": h.items[:25], "evidence": h.detail, "cli": h.cli[:5], "skills": r["skills"] if not r["providers"] else
                [s for s in r["skills"]], "confidence": r["confidence"], "refs": r["refs"]})
    for f in findings:      # skill tags: cloud skills only for the scanned provider
        f["skills"] = [s for s in f["skills"] if s not in ("aws", "azure", "gcp") or s == c.provider]
        if not [s for s in f["skills"] if s == c.provider] and f["category"] != "unused":
            f["skills"].insert(0, c.provider)
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], -f["count"]))

    ap = paths.find(c)
    penalty = sum(WEIGHT[f["severity"]] * CONF_FACTOR[f["confidence"]] * (1 + math.log(max(f["count"], 1), 3))
                  for f in findings if f["category"] in ("security", "misconfig"))
    penalty += min(10, 3 * len([p for p in ap if p["severity"] == "high"]))
    score = max(0, min(100, round(100 * math.exp(-penalty / 70))))
    plan = hardening.plan(c, findings)

    by_cat = {k: [f for f in findings if f["category"] == k] for k in ("unused", "misconfig", "security")}
    by_cat["hardening"] = []     # delivered as `plan`
    by_skill = {}
    for key, s in SKILLS.items():
        mine = [f for f in findings if key in f["skills"]]
        by_skill[key] = {"title": s["title"], "count": len(mine),
                         "high": len([f for f in mine if f["severity"] == "high"]),
                         "top": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in mine[:3]]}
    sev = {s: len([f for f in findings if f["severity"] == s]) for s in SEV_ORDER}
    return {
        "provider": c.provider, "resources": len(c.things), "score": score, "grade": _grade(score),
        "summary": _summary(c, findings, ap, sev, score),
        "severity": sev, "findings": findings, "categories": {k: {"title": CATEGORIES[k], "count": len(v)}
                                                              for k, v in by_cat.items()},
        "attack_paths": ap, "plan": plan, "skills": by_skill,
        "coverage": {"scan_errors": len(inv.errors), "unmapped": sum((inv.meta.get("scope", {}).get("unmapped") or {}).values()),
                     "note": "Findings reflect configuration and relationships visible to the scanner. Runtime traffic, IAM policy "
                             "contents and secret values are not collected."},
    }


def _summary(c, findings, ap, sev, score):
    top = [f for f in findings if f["severity"] == "high"][:3]
    bits = [f"{len(c.things)} resources analysed ({c.provider.upper()}): {sev['high']} high, {sev['medium']} medium, "
            f"{sev['low']} low findings. Posture score {score}/100."]
    if top:
        bits.append("Most urgent: " + "; ".join(f"{f['title']} ({f['count']})" for f in top) + ".")
    if ap:
        bits.append(f"{len(ap)} route(s) from the internet to sensitive data or secrets, e.g. {ap[0]['text']}.")
    unused = [f for f in findings if f["category"] == "unused" and f["severity"] != "note"]
    if unused:
        bits.append(f"{sum(f['count'] for f in unused)} resource(s) look unused.")
    return " ".join(bits)


def chat_events(inv, analysis, messages, **kw):
    from . import qa
    return qa.chat_events(inv, analysis, messages, **kw)


def ask(inv, question, skill=None, use_llm=None, analysis=None):
    from . import qa
    return qa.answer(inv, question, skill=skill, use_llm=use_llm, analysis=analysis or analyze(inv))


def report_markdown(name, a, inv) -> str:
    L = [f"# CloudMap Agent report — {name}", "", a["summary"], "",
         f"**Posture score:** {a['score']}/100 (grade {a['grade']})", ""]
    for cat, label in (("security", "Security issues"), ("misconfig", "Misconfiguration"), ("unused", "Unused resources")):
        fs = [f for f in a["findings"] if f["category"] == cat]
        L.append(f"## {label}")
        if not fs:
            L += ["Nothing found.", ""]
        for f in fs:
            names = ", ".join(inv.nodes[r]["name"] for r in f["resources"][:8])
            L += [f"### [{f['severity'].upper()}] {f['title']} ({f['count']})",
                  f"_Confidence: {f['confidence']}_ — {f['why']}", f"- Resources: {names}"]
            L += [f"- {i}" for i in f["items"][:8]]
            L.append(f"- Fix: {f['fix']}")
            L += [f"  - `{c}`" for c in f["cli"][:3]]
            L.append("")
    if a["attack_paths"]:
        L += ["## Routes from the internet to sensitive resources"] + [f"- [{p['severity']}] `{p['text']}` — {p['entry_reasons'][0]}" for p in a["attack_paths"]] + [""]
    L.append("## Hardening plan")
    for ph in a["plan"]["phases"]:
        if ph["items"]:
            L += [f"### {ph['label']}"] + [f"- {i['title']} ({i['count']})" for i in ph["items"]]
    L += ["### Baseline controls to verify (not visible to the scan)"] + [f"- {b['title']} — {b['why']}" for b in a["plan"]["baseline"]]
    L += ["", f"> {a['coverage']['note']}"]
    return "\n".join(L)
