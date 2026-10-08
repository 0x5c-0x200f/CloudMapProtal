from __future__ import annotations

import json
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from .. import agent, insights, report
from ..agent import llm as agent_llm
from ..schema import Inventory, SchemaError

STATIC = Path(__file__).parent / "static"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024
    store: dict[str, tuple[str, Inventory]] = {}  # MVP: in-memory, per process
    analyses: dict[str, dict] = {}                # agent analysis cache (deterministic per import)

    def _analysis(iid, inv):
        if iid not in analyses:
            analyses[iid] = agent.analyze(inv)
        return analyses[iid]

    def _add(name: str, inv: Inventory) -> str:
        iid = uuid.uuid4().hex[:12]
        store[iid] = (name, inv)
        return iid

    def _get(iid):
        return store.get(iid)

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    @app.post("/api/import")
    def import_file():
        f = request.files.get("file")
        if f is None:
            return jsonify(error="no file uploaded (field name: file)"), 400
        try:
            inv = Inventory.load(iter(f.stream.readline, b""))
        except (SchemaError, UnicodeDecodeError) as e:
            return jsonify(error=f"Invalid inventory: {e}"), 422
        iid = _add(f.filename or "upload.jsonci", inv)
        return jsonify(import_id=iid, filename=f.filename, summary=inv.summary())

    @app.post("/api/demo")
    def demo_import():
        from ..scanners import demo
        from ..scanners.base import Emitter
        provider = request.args.get("provider", "aws")
        if provider not in ("aws", "azure", "gcp"):
            return jsonify(error="provider must be aws, azure or gcp"), 400
        em = Emitter(provider, "demo01")
        demo.scan_provider(provider, em)
        inv = Inventory.load(json.dumps(r) for r in em.records())
        name = f"{provider}-demo01-demo.jsonci"
        return jsonify(import_id=_add(name, inv), filename=name, summary=inv.summary())

    @app.get("/api/imports")
    def imports():
        return jsonify([{"import_id": i, "filename": n, "summary": inv.summary()}
                        for i, (n, inv) in store.items()])

    @app.get("/api/imports/<iid>/graph")
    def graph(iid):
        hit = _get(iid)
        return jsonify(hit[1].to_graph()) if hit else (jsonify(error="unknown import"), 404)

    @app.get("/api/imports/<iid>/insights")
    def insights_route(iid):
        hit = _get(iid)
        return jsonify(insights.analyze(hit[1])) if hit else (jsonify(error="unknown import"), 404)

    @app.get("/api/agent/status")
    def agent_status():
        return jsonify(agent_llm.status(refresh=bool(request.args.get("refresh"))))

    @app.post("/api/agent/config")
    def agent_config():
        b = request.get_json(silent=True) or {}
        try:
            agent_llm.set_runtime(b.get("backend"), b.get("model"), b.get("base_url"))
        except agent_llm.LLMError as e:
            return jsonify(error=str(e)), 400
        return jsonify(agent_llm.status(refresh=True))

    @app.post("/api/agent/ollama/create")
    def agent_ollama_create():
        from ..agent.skills import SKILLS, system_prompt
        b = request.get_json(silent=True) or {}
        name, base = str(b.get("name", "")).strip(), str(b.get("base", "")).strip()
        skill = b.get("skill") if b.get("skill") in SKILLS else None
        params = {}
        try:
            if b.get("temperature") not in (None, ""):
                params["temperature"] = max(0.0, min(float(b["temperature"]), 1.5))
            if b.get("num_ctx") not in (None, ""):
                params["num_ctx"] = max(2048, min(int(b["num_ctx"]), 131072))
        except (TypeError, ValueError):
            return jsonify(error="temperature and context size must be numbers"), 400
        system = system_prompt(str(b.get("provider") or "aws"), skill)
        extra = str(b.get("instructions", "")).strip()[:2000]
        if extra:
            system += "\nAdditional instructions from the operator:\n" + extra + "\n"
        mf = agent_llm.modelfile_text(base, system, params)

        def gen():
            yield json.dumps({"modelfile": mf}) + "\n"
            try:
                for st in agent_llm.create_model(name, base, system, params):
                    yield json.dumps({"status": st}) + "\n"
                yield json.dumps({"done": True, "name": name}) + "\n"
            except agent_llm.LLMError as e:
                yield json.dumps({"error": str(e)}) + "\n"
        return Response(gen(), mimetype="application/x-ndjson")

    @app.post("/api/imports/<iid>/agent/chat")
    def agent_chat(iid):
        hit = _get(iid)
        if not hit:
            return jsonify(error="unknown import"), 404
        b = request.get_json(silent=True) or {}
        events = agent.chat_events(hit[1], _analysis(iid, hit[1]), b.get("messages"), skill=b.get("skill"),
                                   allow_remote=bool(b.get("allow_remote")), model=b.get("model"))

        def gen():
            for ev in events:
                yield json.dumps(ev) + "\n"
        return Response(gen(), mimetype="application/x-ndjson", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/api/imports/<iid>/agent")
    def agent_route(iid):
        hit = _get(iid)
        return jsonify(_analysis(iid, hit[1])) if hit else (jsonify(error="unknown import"), 404)

    @app.post("/api/imports/<iid>/agent/ask")
    def agent_ask(iid):
        hit = _get(iid)
        if not hit:
            return jsonify(error="unknown import"), 404
        body = request.get_json(silent=True) or {}
        q = str(body.get("question", "")).strip()
        if not q:
            return jsonify(error="question is required"), 400
        return jsonify(agent.ask(hit[1], q, skill=body.get("skill"), use_llm=bool(body.get("use_llm")),
                                 analysis=_analysis(iid, hit[1])))

    @app.get("/api/imports/<iid>/agent.md")
    def agent_md(iid):
        hit = _get(iid)
        if not hit:
            return jsonify(error="unknown import"), 404
        return Response(agent.report_markdown(hit[0], _analysis(iid, hit[1]), hit[1]), mimetype="text/markdown")

    @app.get("/api/imports/<iid>/report.<fmt>")
    def report_route(iid, fmt):
        hit = _get(iid)
        if not hit:
            return jsonify(error="unknown import"), 404
        name, inv = hit
        if fmt not in ("html", "md"):
            return jsonify(error="format must be html or md"), 404
        ins = insights.analyze(inv)
        body = report.render_html(inv, ins) if fmt == "html" else report.render_markdown(inv, ins)
        resp = Response(body, mimetype="text/html" if fmt == "html" else "text/markdown")
        if request.args.get("download"):
            stem = name.rsplit(".", 1)[0]
            resp.headers["Content-Disposition"] = f'attachment; filename="{stem}-report.{fmt}"'
        return resp

    @app.get("/api/imports/<iid>/blast")
    def blast(iid):
        hit = _get(iid)
        if not hit:
            return jsonify(error="unknown import"), 404
        try:
            hops = max(1, min(int(request.args.get("hops", 2)), 6))
            return jsonify(hit[1].blast(request.args.get("node", ""), hops,
                                        request.args.get("direction", "both")))
        except KeyError:
            return jsonify(error="unknown node"), 404

    return app
