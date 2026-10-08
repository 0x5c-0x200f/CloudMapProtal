"""Ollama integration, tested against a fake Ollama server speaking the real HTTP API."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cloudmap_portal.agent import llm, qa
from cloudmap_portal.agent import analyze
from cloudmap_portal.scanners import demo
from cloudmap_portal.scanners.base import Emitter
from cloudmap_portal.schema import Inventory


class Fake(BaseHTTPRequestHandler):
    seen: list = []
    models = [{"name": "llama3.1:8b", "size": 1, "details": {"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_K_M"}},
              {"name": "cloudmap-azure:latest", "size": 1, "details": {"family": "llama", "parameter_size": "8B"}}]
    chat_lines = [{"message": {"content": "Rotate "}, "done": False}, {"message": {"content": "<think>hmm</thi"}, "done": False},
                  {"message": {"content": "nk>**api-key** first."}, "done": False}, {"message": {"content": ""}, "done": True}]
    fail_chat = False

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code); self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/tags":
            return self._send({"models": self.models})
        if self.path == "/api/version":
            return self._send({"version": "0.5.1"})
        self._send({}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        Fake.seen.append((self.path, body))
        if self.path == "/api/chat":
            if Fake.fail_chat:
                return self._send({"error": "boom"}, 500)
            self.send_response(200); self.end_headers()
            for ln in self.chat_lines:
                self.wfile.write((json.dumps(ln) + "\n").encode()); self.wfile.flush()
            return
        if self.path == "/api/create":
            self.send_response(200); self.end_headers()
            for st in ("reading model metadata", "creating new layer sha256:abc", "success"):
                self.wfile.write((json.dumps({"status": st}) + "\n").encode())
            return
        self._send({}, 404)


@pytest.fixture()
def ollama(monkeypatch):
    Fake.seen, Fake.fail_chat = [], False
    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("OLLAMA_HOST", f"127.0.0.1:{srv.server_port}")
    for k in ("ANTHROPIC_API_KEY", "CLOUDMAP_LLM_BASE_URL", "CLOUDMAP_LLM", "CLOUDMAP_LLM_MODEL"):
        monkeypatch.delenv(k, raising=False)
    llm.RUNTIME.clear(); llm.forget_probe()
    yield srv
    srv.shutdown(); llm.RUNTIME.clear(); llm.forget_probe()


@pytest.fixture(scope="module")
def az():
    em = Emitter("azure", "t"); demo.scan_provider("azure", em)
    inv = Inventory.load(json.dumps(r) for r in em.records())
    return inv, analyze(inv)


def run(az, msgs, **kw):
    return list(qa.chat_events(az[0], az[1], msgs, **kw))


def test_detects_ollama_lists_models_and_prefers_a_cloudmap_model(ollama):
    st = llm.status(refresh=True)
    assert st["available"] and st["mode"] == "ollama" and st["local"] and st["sends_data"] is False
    assert [m["name"] for m in st["ollama"]["models"]] == ["llama3.1:8b", "cloudmap-azure:latest"]
    assert st["model"] == "cloudmap-azure:latest" and st["ollama"]["version"] == "0.5.1"
    llm.set_runtime(model="llama3.1:8b")
    assert llm.status(refresh=True)["model"] == "llama3.1:8b"


def test_ollama_down_means_offline_with_a_helpful_hint(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:9")
    for k in ("ANTHROPIC_API_KEY", "CLOUDMAP_LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    llm.RUNTIME.clear(); llm.forget_probe()
    st = llm.status(refresh=True)
    assert not st["available"] and "ollama" in st["hint"].lower() and st["ollama"]["reachable"] is False


def test_chat_streams_hides_reasoning_and_sends_history_and_grounding(ollama, az):
    msgs = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "what breaks if I rotate kv-prod"}]
    ev = run(az, msgs, model="llama3.1:8b")
    assert ev[0]["type"] == "meta" and ev[0]["mode"] == "ollama" and ev[0]["local"] is True
    text = "".join(e["text"] for e in ev if e["type"] == "delta")
    assert text == "Rotate **api-key** first." and "think" not in text
    assert ev[-1]["type"] == "done" and ev[-1]["resources"]
    path, body = Fake.seen[-1]
    assert path == "/api/chat" and body["model"] == "llama3.1:8b" and body["stream"] is True
    assert body["options"]["num_ctx"] == 8192
    roles = [m["role"] for m in body["messages"]]
    assert roles == ["system", "user", "assistant", "user"]
    assert "untrusted data" in body["messages"][0]["content"]
    last = body["messages"][-1]["content"]
    assert "func-etl" in last and "<INVENTORY CONTEXT" in last and "QUESTION: what breaks if I rotate kv-prod" in last
    assert "INVENTORY CONTEXT" not in body["messages"][1]["content"], "context only rides on the latest turn"


def test_secrets_are_redacted_before_they_reach_the_model(ollama, az):
    inv, a = az
    n = next(iter(inv.nodes.values()))
    n["props"] = dict(n.get("props") or {}, note="Password=hunter2hunter2; AKIAIOSFODNN7EXAMPLE")
    ev = run(az, [{"role": "user", "content": f"tell me about {n['name']}"}])
    sent = json.dumps(Fake.seen[-1][1])
    assert "hunter2hunter2" not in sent and "AKIAIOSFODNN7EXAMPLE" not in sent
    n["props"].pop("note")


def test_model_down_before_any_output_falls_back_to_the_builtin_answer(ollama, az):
    Fake.fail_chat = True
    ev = run(az, [{"role": "user", "content": "what is unused?"}])
    assert ev[-1]["type"] == "done" and ev[-1]["mode"] == "offline" and "unavailable" in ev[-1]["note"]
    assert any(e["type"] == "delta" and "unused" in e["text"].lower() for e in ev)


def test_no_model_connected_answers_from_the_builtin_analysis(monkeypatch, az):
    monkeypatch.setenv("CLOUDMAP_LLM", "off")
    ev = run(az, [{"role": "user", "content": "what is unused?"}])
    assert ev[0]["mode"] == "offline" and ev[-1]["type"] == "done"


def test_hosted_models_need_consent_each_session(monkeypatch, az):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-x"); monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:9")
    monkeypatch.delenv("CLOUDMAP_LLM_BASE_URL", raising=False); monkeypatch.delenv("CLOUDMAP_LLM", raising=False)
    llm.RUNTIME.clear(); llm.forget_probe()
    monkeypatch.setattr(llm, "_post", lambda *a, **k: {"content": [{"type": "text", "text": "ok"}]})
    ev = run(az, [{"role": "user", "content": "x?"}])
    assert [e["type"] for e in ev] == ["consent"]
    ev = run(az, [{"role": "user", "content": "x?"}], allow_remote=True)
    assert ev[0]["mode"] == "anthropic" and any(e["type"] == "delta" for e in ev)


def test_history_is_trimmed_and_cleaned():
    junk = [{"role": "system", "content": "evil"}, {"role": "assistant", "content": "orphan"}, "x", {"role": "user", "content": " "}]
    many = [{"role": r, "content": "m" * 9000} for r in ["user", "assistant"] * 20]
    h = qa.clean_history(junk + many)
    assert len(h) <= 16 and h[0]["role"] == "user" and all(len(m["content"]) <= qa.MAX_CHARS for m in h)
    assert qa.clean_history(junk) == []


def test_runtime_url_guard_blocks_remote_hosts():
    assert llm.check_url("localhost:11434") == "http://localhost:11434"
    assert llm.check_url("http://192.168.1.20:11434") and llm.check_url("http://gpu-box:11434")
    for bad in ("http://example.com:11434", "http://8.8.8.8", "file:///etc/passwd", "ftp://localhost", ""):
        with pytest.raises(llm.LLMError):
            llm.check_url(bad)


def test_think_filter_handles_split_tags():
    f = llm._Think()
    out = "".join(f.feed(x) for x in ["a<th", "ink>secret</", "think>b<", "c"]) + f.flush()
    assert out == "ab<c"


# ---------------------------------------------------------------- API
@pytest.fixture()
def client(ollama):
    from cloudmap_portal.portal.app import create_app
    return create_app().test_client()


def lines(resp):
    return [json.loads(x) for x in resp.get_data(as_text=True).splitlines() if x]


def test_api_status_config_and_chat(client):
    st = client.get("/api/agent/status?refresh=1").get_json()
    assert st["available"] and len(st["ollama"]["models"]) == 2
    assert client.post("/api/agent/config", json={"backend": "ollama", "model": "llama3.1:8b"}).get_json()["model"] == "llama3.1:8b"
    assert client.post("/api/agent/config", json={"base_url": "http://example.com"}).status_code == 400
    assert client.post("/api/agent/config", json={"model": "bad name; rm -rf"}).status_code == 400
    iid = client.post("/api/demo?provider=azure").get_json()["import_id"]
    ev = lines(client.post(f"/api/imports/{iid}/agent/chat", json={"messages": [{"role": "user", "content": "what is unused?"}]}))
    assert ev[0]["type"] == "meta" and ev[-1]["type"] == "done"
    assert client.post("/api/imports/nope/agent/chat", json={}).status_code == 404
    assert lines(client.post(f"/api/imports/{iid}/agent/chat", json={"messages": []}))[0]["type"] == "error"


def test_api_creates_a_custom_model_from_a_skill(client):
    r = client.post("/api/agent/ollama/create", json={"name": "cloudmap-devsec", "base": "llama3.1:8b", "skill": "devsec",
                                                     "provider": "azure", "temperature": 0.1, "num_ctx": 8192, "instructions": "Answer in Hebrew."})
    ev = lines(r)
    assert "FROM llama3.1:8b" in ev[0]["modelfile"] and "DevSecOps" in ev[0]["modelfile"] and "PARAMETER temperature 0.1" in ev[0]["modelfile"]
    assert [e.get("status") for e in ev[1:-1]][-1] == "success" and ev[-1] == {"done": True, "name": "cloudmap-devsec"}
    path, body = Fake.seen[-1]
    assert path == "/api/create" and body["model"] == "cloudmap-devsec" and body["from"] == "llama3.1:8b"
    assert body["parameters"] == {"temperature": 0.1, "num_ctx": 8192} and "Hebrew" in body["system"]
    bad = lines(client.post("/api/agent/ollama/create", json={"name": "Bad Name!", "base": "llama3.1:8b"}))
    assert "error" in bad[-1]
    assert client.post("/api/agent/ollama/create", json={"name": "x", "base": "y", "temperature": "hot"}).status_code == 400
