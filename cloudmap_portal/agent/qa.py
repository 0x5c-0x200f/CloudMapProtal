"""Question answering over one inventory.

Offline mode: a small intent router that answers from the graph and the findings. Deterministic,
cites resource ids, and says "I can't tell from this scan" instead of guessing.
LLM mode (opt-in per question): the same retrieval builds a compact, redacted digest that a
configured language model reasons over.
"""
from __future__ import annotations

import re
from collections import Counter

from . import llm
from ..schema import SCOPE_KINDS
from .skills import SKILLS, system_prompt

NOUNS = [   # (regex, label, kind-prefix tuple)
    (r"\b(public ips?|elastic ips?)\b", "public IPs", ("network.public_ip",)),
    (r"\b(security groups?|nsgs?|firewalls?)\b", "network access groups", ("network.security_group",)),
    (r"\b(load ?balancers?|lbs?|albs?|elbs?)\b", "load balancers", ("network.load_balancer",)),
    (r"\bsubnets?\b", "subnets", ("network.subnet",)),
    (r"\b(vpcs?|vnets?|virtual networks?|networks?)\b", "networks", ("network.vpc",)),
    (r"\b(vms?|virtual machines?|instances?|servers?|machines?|ec2)\b", "machines", ("compute.instance",)),
    (r"\b(functions?|lambdas?)\b", "functions", ("compute.function",)),
    (r"\b(clusters?|k8s|kubernetes|aks|gke|eks)\b", "clusters", ("compute.cluster",)),
    (r"\b(web ?apps?|apps?|services?|app services?|cloud run)\b", "apps", ("compute.app",)),
    (r"\b(databases?|dbs?|sql|rds)\b", "databases", ("data.",)),
    (r"\b(buckets?|storage accounts?|s3|blob)\b", "storage", ("storage.",)),
    (r"\b(vaults?|key ?vaults?)\b", "vaults", ("iam.vault",)),
    (r"\bsecrets?\b", "secrets", ("iam.secret",)),
    (r"\bkeys?\b", "keys", ("iam.key",)),
    (r"\bcertificates?|certs?\b", "certificates", ("iam.certificate",)),
    (r"\b(identit(y|ies)|roles?|service accounts?|principals?)\b", "identities", ("iam.role", "iam.identity")),
]
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[redacted-key]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"), "[redacted-token]"),
    (re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)"), "[redacted-key]"),
    (re.compile(r"(?i)(password|pwd|accountkey|sharedaccesskey|secret|token)\s*[=:]\s*[^\s;,\"']+"), r"\1=[redacted]"),
    (re.compile(r"[A-Za-z0-9+/=_\-]{48,}"), "[redacted-blob]"),
]
STOP = set("the a an of in on to is are what which who how do does can i we my our me and or for with any all show list tell about this that there it be have has".split())


def redact(text: str) -> str:
    for rx, rep in SECRET_PATTERNS:
        text = rx.sub(rep, text)
    return text


def _tokens(s):
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\-_.@]*", s.lower()) if t not in STOP and len(t) > 1]


def _link(n):
    return f"`{n['name']}`"


def _list(inv, ids, limit=12, extra=None):
    rows = []
    for nid in list(ids)[:limit]:
        n = inv.nodes[nid]
        tail = f" — {extra(n)}" if extra and extra(n) else ""
        rows.append(f"- {_link(n)} ({n['kind']}{', ' + n['region'] if n.get('region') else ''}){tail}")
    if len(ids) > limit:
        rows.append(f"- …and {len(ids) - limit} more")
    return "\n".join(rows)


def match_nodes(inv, question):
    q = question.lower()
    exact = [n for n in inv.nodes.values() if len(n["name"]) >= 3 and re.search(
        r"(?<![\w\-])" + re.escape(n["name"].lower()) + r"(?![\w\-])", q)]
    exact.sort(key=lambda n: -len(n["name"]))
    if exact:
        top = len(exact[0]["name"])
        return [n for n in exact if len(n["name"]) >= top * 0.6][:5]
    toks = set(_tokens(question))
    scored = []
    for n in inv.nodes.values():
        parts = set(re.split(r"[\W_]+", n["name"].lower())) - {""}
        hit = len(parts & toks)
        if hit and hit >= max(1, len(parts) // 2):
            scored.append((hit / len(parts), n))
    scored.sort(key=lambda t: -t[0])
    return [n for _, n in scored[:5]]


def findings_for(analysis, nid):
    return [f for f in analysis["findings"] if nid in f["resources"]]


def _fmt_finding(f, inv, n=4):
    names = ", ".join(f"`{inv.nodes[r]['name']}`" for r in f["resources"][:n]) + (f" +{f['count'] - n}" if f["count"] > n else "")
    conf = "" if f["confidence"] == "high" else f" _(confidence: {f['confidence']})_"
    out = f"- **{f['severity'].upper()} · {f['title']}**{conf}: {names}"
    if f["items"]:
        out += "\n  - " + "\n  - ".join(f["items"][:3])
    if f.get("fix"):
        out += f"\n  - Fix: {f['fix']}"
    return out


def _category(inv, analysis, cat, title, empty, limit=8):
    fs = [f for f in analysis["findings"] if f["category"] == cat]
    if not fs:
        return empty, []
    res = list(dict.fromkeys(r for f in fs for r in f["resources"]))
    return f"**{title}** ({len(fs)} finding(s)):\n" + "\n".join(_fmt_finding(f, inv) for f in fs[:limit]), res


def _kind_filter(inv, prefixes):
    return [n for n in inv.nodes.values() if n["kind"].startswith(prefixes)]


def _describe(inv, analysis, n):
    out = [f"**{n['name']}** — {n['kind']}" + (f" in {n['region']}" if n.get("region") else "")]
    if n.get("props"):
        out.append("Properties: " + ", ".join(f"{k}={v}" for k, v in list(n["props"].items())[:10]))
    if n.get("tags"):
        out.append("Tags: " + ", ".join(f"{k}={v}" for k, v in list(n["tags"].items())[:8]))
    ups = [inv.nodes[e["from"]]["name"] + f" ({e['rel']})" for e in inv._in.get(n["id"], [])][:8]
    downs = [inv.nodes[e["to"]]["name"] + f" ({e['rel']})" for e in inv._out.get(n["id"], [])][:8]
    if downs:
        out.append("Depends on: " + ", ".join(downs))
    if ups:
        out.append("Used by: " + ", ".join(ups))
    fs = findings_for(analysis, n["id"])
    if fs:
        out.append("Findings touching it:\n" + "\n".join(f"- {f['severity'].upper()} · {f['title']}" for f in fs))
    else:
        out.append("No findings touch this resource.")
    return "\n".join(out)


def _impact(inv, n):
    b = inv.blast(n["id"], 3, "in")
    return [x for x in b.get("nodes", []) if x != n["id"] and inv.nodes[x]["kind"] not in SCOPE_KINDS]


def offline(inv, analysis, question):
    q = question.lower().strip()
    nodes = match_nodes(inv, question)
    for n in nodes:                                   # a resource's own name must not trigger keyword intents
        q = re.sub(r"(?<![\w\-])" + re.escape(n["name"].lower()) + r"(?![\w\-])", " it ", q)
    follow = ["What are the top risks?", "Which resources look unused?", "Show attack paths from the internet"]

    def done(text, intent, res=(), follow_=None):
        return {"answer": text, "mode": "offline", "intent": intent, "resources": list(res)[:200], "followups": follow_ or follow}

    if re.search(r"\b(who|what) (can|has|have) access|who has access|permission|can access\b", q) and nodes:
        n = nodes[0]
        who = [inv.nodes[e["from"]] for e in inv._in.get(n["id"], []) if e["rel"] in ("can_access", "assumes", "reads_secret")]
        if not who:
            return done(f"No identity in the scan is recorded as having access to {_link(n)}. IAM policies that grant access outside what the scanner reads are not visible.", "access", [n["id"]])
        lines = []
        for e in inv._in.get(n["id"], []):
            if e["rel"] in ("can_access", "assumes", "reads_secret"):
                acc = f" [{', '.join(e['access'])}]" if e.get("access") else ""
                lines.append(f"- `{inv.nodes[e['from']]['name']}` ({e['rel']}){acc}")
        return done(f"Access to {_link(n)}:\n" + "\n".join(lines), "access", [n["id"]] + [w["id"] for w in who])

    if nodes and re.search(r"\b(depend|break|affect|impact|blast|downstream|upstream|relat|connect|uses?|used by|if i (delete|remove|rotate|stop|change|disable))|\\b(rotate|rotating|delete|deleting|remove|removing|decommission)\\b\w*", q):
        n = nodes[0]
        deps = _impact(inv, n)
        outs = [inv.nodes[e["to"]] for e in inv._out.get(n["id"], [])]
        txt = f"**{n['name']}** ({n['kind']})\n"
        txt += (f"- Depends on {len(outs)}: " + ", ".join(f"`{o['name']}`" for o in outs[:10]) + "\n") if outs else "- Depends on nothing the scan can see\n"
        names = [inv.nodes[d]["name"] for d in deps]
        txt += (f"- {len(deps)} resource(s) would be affected if it changed: " + ", ".join(f"`{x}`" for x in names[:12]) + (" …" if len(names) > 12 else "")) if deps else "- Nothing in the scan depends on it"
        return done(txt, "impact", [n["id"]] + deps)

    if re.search(r"\b(expir|rotat|certificate.*(soon|old)|stale (secret|credential))", q):
        fs = [f for f in analysis["findings"] if f["id"] in ("integ-expiry-outage", "unused-secret-stale", "sec-cred-no-expiry")]
        if not fs:
            return done("No secrets, keys or certificates in this scan are expired, expiring within 30 days, or missing an expiry.", "expiry")
        return done("\n".join(_fmt_finding(f, inv) for f in fs), "expiry", [r for f in fs for r in f["resources"]])

    if re.search(r"attack path|reach(able)? from the internet|from the internet|internet.*(reach|expos)|blast.*internet", q) or re.search(r"\bhow (could|can) an attacker", q):
        ps = analysis["attack_paths"]
        if not ps:
            return done("I found no route from an internet-facing resource to data, storage, or secrets in this scan. "
                        "That doesn't prove there are none: routes through traffic rules or policies the scan can't read won't show.", "paths")
        lines = [f"**{len(ps)} route(s) from the internet to sensitive resources:**"]
        for p in ps[:6]:
            lines.append(f"- **{p['severity'].upper()}** `{p['text']}` — entry: {p['entry_reasons'][0]}")
        return done("\n".join(lines), "paths", [h["id"] for p in ps for h in p["hops"]])

    if re.search(r"\b(unused|orphan|idle|waste|clean ?up|not (being )?used|can (i|we) (delete|remove)|dead)\b", q):
        text, res = _category(inv, analysis, "unused", "Likely unused", "Nothing in this scan looks unused.")
        return done(text + ("\n\n_Unused here means 'no relationships in the scan'. Check metrics before deleting._" if res else ""), "unused", res)

    if re.search(r"\b(harden|baseline|best practice|improve|strengthen|recommend)\w*\b", q):
        ph = analysis["plan"]["phases"]
        lines = []
        for p in ph:
            if p["items"]:
                lines.append(f"**{p['label']}**\n" + "\n".join(f"- {i['title']} ({i['count']})" for i in p["items"][:6]))
        lines.append("**Baseline controls to verify** (not visible to the scan):\n" + "\n".join(
            f"- {b['title']}" for b in analysis["plan"]["baseline"][:6]))
        return done("\n\n".join(lines), "hardening")

    if re.search(r"\b(misconfig|mis-config|wrong|broken|reliab|single point|spof|outage)\w*\b", q):
        text, res = _category(inv, analysis, "misconfig", "Misconfigurations", "No misconfigurations found.")
        return done(text, "misconfig", res)

    if re.search(r"\b(vulnerab|insecure|exposed|public|internet|security|risky|risk|threat)\w*\b", q) and not re.search(r"\b(top|biggest|worst|most)\b", q):
        text, res = _category(inv, analysis, "security", "Security issues", "No security issues found in the data this scan collected.")
        return done(text, "security", res)

    if re.search(r"\b(top|biggest|worst|most (urgent|important|critical)|priorit|summary|summar|overview|posture|how (secure|safe|healthy|bad)|what should (i|we) (fix|do))\w*", q):
        fs = [f for f in analysis["findings"] if f["category"] != "unused"][:6]
        txt = f"**{analysis['summary']}**\n\nTop items:\n" + "\n".join(_fmt_finding(f, inv, 3) for f in fs)
        return done(txt, "summary", [r for f in fs for r in f["resources"]])

    m = re.search(r"\b(how many|count|number of)\b", q)
    kinds = [(label, pre) for rx, label, pre in NOUNS if re.search(rx, q)]
    if m and kinds:
        lines, res = [], []
        for label, pre in kinds[:3]:
            found = _kind_filter(inv, pre)
            lines.append(f"**{len(found)}** {label}")
            res += [n["id"] for n in found]
        return done(" · ".join(lines), "count", res)
    if m:
        c = Counter(n["kind"] for n in inv.nodes.values())
        return done("Inventory by type:\n" + "\n".join(f"- {k}: {v}" for k, v in c.most_common(15)), "count")

    if nodes and not (m or re.search(r"\b(list|show|which|all)\b", q)):
        return done(_describe(inv, analysis, nodes[0]), "describe", [nodes[0]["id"]])

    if kinds:
        label, pre = kinds[0]
        found = _kind_filter(inv, pre)
        env = re.search(r"\b(prod|production|dev|test|staging|qa)\b", q)
        if env:
            from .ctx import norm_env
            want = norm_env(env.group(1))
            found = [n for n in found if norm_env(next((v for k, v in (n.get("tags") or {}).items() if k.lower() in ("env", "environment")), None)) == want]
        reg = re.search(r"\bin ([a-z]+-?[a-z]*-?\d?)\b", q)
        if reg:
            r = reg.group(1)
            narrowed = [n for n in found if r in str(n.get("region", "")).lower()]
            if narrowed:
                found = narrowed
        if re.search(r"\b(public|internet|exposed)\b", q):
            ex = analysis and __import__("cloudmap_portal.agent.ctx", fromlist=["Ctx"]).Ctx(inv).exposed_workloads()
            found = [n for n in found if n["id"] in ex]
        if not found:
            return done(f"No {label} matched in this scan.", "list")
        return done(f"**{len(found)} {label}:**\n" + _list(inv, [n["id"] for n in found]), "list", [n["id"] for n in found])

    if nodes:
        return done(_describe(inv, analysis, nodes[0]), "describe", [nodes[0]["id"]])

    return done("I can't answer that from the scan alone. Try asking about a resource by name, "
                "or ask things like “what is unused?”, “what is exposed to the internet?”, "
                "“what breaks if I rotate `<secret>`?” or “how many databases are there?”.", "unknown")


def digest(inv, analysis, question, nodes, budget=14000):
    """Compact, redacted, untrusted-data block for the language model."""
    meta = inv.meta
    lines = [f"provider={meta.get('provider')} scanned_at={meta.get('scanned_at')} resources={analysis['resources']} "
             f"score={analysis['score']} scan_errors={len(inv.errors)}"]
    lines.append("kinds: " + ", ".join(f"{k}={v}" for k, v in Counter(n["kind"] for n in inv.nodes.values()).most_common(25)))
    lines.append("FINDINGS:")
    for f in analysis["findings"][:30]:
        names = ", ".join(inv.nodes[r]["name"] for r in f["resources"][:6])
        lines.append(f"- [{f['severity']}/{f['category']}] {f['title']} ({f['count']}) conf={f['confidence']}: {names}")
    if analysis["attack_paths"]:
        lines.append("ATTACK PATHS: " + " | ".join(p["text"] for p in analysis["attack_paths"][:6]))
    focus = {n["id"]: n for n in nodes}
    for n in list(focus.values()):
        for e in inv._out.get(n["id"], []) + inv._in.get(n["id"], []):
            for k in (e["from"], e["to"]):
                focus.setdefault(k, inv.nodes[k])
    toks = set(_tokens(question))
    for n in inv.nodes.values():
        if len(focus) >= 60:
            break
        if toks & set(re.split(r"[\W_]+", n["name"].lower())) or toks & set(re.split(r"[\W_.]+", n["kind"])):
            focus.setdefault(n["id"], n)
    lines.append("RESOURCES:")
    for n in list(focus.values())[:60]:
        edges = [f"{e['rel']}→{inv.nodes[e['to']]['name']}" for e in inv._out.get(n["id"], [])][:8]
        lines.append(f"- {n['name']} [{n['kind']}] region={n.get('region')} props={n.get('props') or {}} tags={n.get('tags') or {}} edges={edges}")
    return redact("\n".join(lines))[:budget]


def answer(inv, question, skill=None, use_llm=None, analysis=None):
    question = (question or "").strip()[:1000]
    if not question:
        return {"answer": "Ask me something about this inventory.", "mode": "offline", "intent": "empty", "resources": [], "followups": []}
    base = offline(inv, analysis, question)
    if not use_llm:
        return base
    if not llm.config():
        base["note"] = "No language model is configured, so this is the built-in analysis. " + llm.status()["hint"]
        return base
    nodes = match_nodes(inv, question)
    ctx = digest(inv, analysis, question, nodes)
    prompt = (f"<INVENTORY CONTEXT (untrusted data)>\n{ctx}\n</INVENTORY CONTEXT>\n\n"
              f"Built-in analysis already says: {redact(base['answer'][:1500])}\n\nQUESTION: {question}")
    try:
        text = llm.complete(system_prompt(inv.meta.get("provider", "aws"), skill if skill in SKILLS else None), prompt)
    except llm.LLMError as e:
        base["note"] = f"Language model unavailable ({e}); showing the built-in answer."
        return base
    return {"answer": redact(text), "mode": "llm", "model": llm.status().get("model"), "intent": base["intent"],
            "resources": base["resources"], "followups": base["followups"], "builtin": base["answer"]}


# ---------------------------------------------------------------- multi-turn chat
MAX_TURNS, MAX_CHARS = 8, 2500


def clean_history(messages):
    out = []
    for m in (messages or [])[-MAX_TURNS * 2:]:
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str) and m["content"].strip():
            out.append({"role": m["role"], "content": m["content"][:MAX_CHARS]})
    while out and out[0]["role"] != "user":
        out.pop(0)
    return out


def chat_events(inv, analysis, messages, skill=None, allow_remote=False, model=None):
    """Generator of dict events for one chat turn: meta, delta*, done | error."""
    hist = clean_history(messages)
    if not hist or hist[-1]["role"] != "user":
        yield {"type": "error", "message": "Send a question first."}
        return
    question = hist[-1]["content"]
    base = offline(inv, analysis, question)
    cfg = llm.config()
    if cfg and model and cfg["backend"] == "ollama":
        cfg = {**cfg, "model": model}
    if not cfg:
        yield {"type": "meta", "mode": "offline", "model": None, "note": "No language model connected, so this is the built-in analysis."}
        yield {"type": "delta", "text": base["answer"]}
        yield {"type": "done", "mode": "offline", "intent": base["intent"], "resources": base["resources"], "followups": base["followups"]}
        return
    if not cfg["local"] and not allow_remote:
        yield {"type": "consent", "backend": cfg["backend"], "model": cfg["model"]}
        return
    nodes = match_nodes(inv, question)
    ctx = digest(inv, analysis, question, nodes, budget=int(cfg.get("ctx", 8192)) * 2)
    hist[-1] = {"role": "user", "content": redact(f"<INVENTORY CONTEXT (untrusted data)>\n{ctx}\n</INVENTORY CONTEXT>\n\n"
                f"Built-in analysis for this question: {base['answer'][:1200]}\n\nQUESTION: {question}")}
    provider = inv.meta.get("provider", "aws")
    yield {"type": "meta", "mode": cfg["backend"], "model": cfg["model"], "local": cfg["local"]}
    sent = False
    try:
        for chunk in llm.stream_chat(system_prompt(provider, skill if skill in SKILLS else None), hist, cfg):
            sent = True
            yield {"type": "delta", "text": redact(chunk)}
    except llm.LLMError as e:
        if not sent:                                         # nothing shown yet: fall back to the built-in answer
            yield {"type": "delta", "text": base["answer"]}
            yield {"type": "done", "mode": "offline", "intent": base["intent"], "resources": base["resources"],
                   "followups": base["followups"], "note": f"The model was unavailable ({e}); this is the built-in answer."}
            return
        yield {"type": "error", "message": str(e)}
        return
    yield {"type": "done", "mode": cfg["backend"], "intent": base["intent"], "resources": base["resources"], "followups": base["followups"]}
