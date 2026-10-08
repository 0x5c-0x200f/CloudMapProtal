"""Language-model backends. Ollama is first-class; hosted APIs are optional.

Order of choice: what the user picked in the portal, then CLOUDMAP_LLM_BASE_URL (OpenAI-compatible),
then a reachable local Ollama, then ANTHROPIC_API_KEY. Nothing is sent anywhere until a chat or
question is actually asked, and hosted backends require explicit consent per session in the UI.

Env: OLLAMA_HOST (default http://localhost:11434), CLOUDMAP_LLM_MODEL, CLOUDMAP_LLM_CTX (default 8192),
     CLOUDMAP_LLM_BASE_URL/_API_KEY, ANTHROPIC_API_KEY, CLOUDMAP_LLM=off, CLOUDMAP_ALLOW_REMOTE_LLM=1
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
TIMEOUT = 120
RUNTIME: dict = {}                       # chosen in the portal: backend, model, base_url
_probe_cache: dict = {}
MODEL_NAME = re.compile(r"^[a-z0-9][a-z0-9._\-/]{0,80}(:[A-Za-z0-9._\-]{1,40})?$")


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------- addresses
def normalize_url(u: str) -> str:
    u = (u or "").strip().rstrip("/")
    if u and "://" not in u:
        u = "http://" + u
    return u


def is_local_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "host.docker.internal") or host.endswith((".local", ".lan", ".internal", ".home")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return "." not in host                      # docker/k8s service names


def check_url(url: str) -> str:
    """Browser-supplied URLs may only point at this machine or the private network (SSRF guard)."""
    url = normalize_url(url)
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise LLMError("Enter a URL like http://localhost:11434")
    if not is_local_url(url) and os.environ.get("CLOUDMAP_ALLOW_REMOTE_LLM") != "1":
        raise LLMError("Only local or private-network addresses are allowed. Set CLOUDMAP_ALLOW_REMOTE_LLM=1 to override.")
    return url


def ollama_base() -> str:
    return normalize_url(RUNTIME.get("base_url") or os.environ.get("OLLAMA_HOST") or "http://localhost:11434")


# ---------------------------------------------------------------- http
def _post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:       # noqa: S310 (operator-configured URL)
        return json.loads(r.read().decode())


def _get(url, timeout=2.0):
    with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as r:        # noqa: S310
        return json.loads(r.read().decode())


def _stream_lines(url, body, headers=None, timeout=TIMEOUT):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:       # noqa: S310
        for raw in r:
            raw = raw.strip()
            if raw:
                yield json.loads(raw.decode())


def _wrap(e):
    if isinstance(e, urllib.error.HTTPError):
        return LLMError(f"the model server returned HTTP {e.code}")          # never echo bodies/keys
    if isinstance(e, (urllib.error.URLError, ConnectionError, TimeoutError, OSError)):
        return LLMError("could not reach the model server")
    return LLMError(f"model call failed ({type(e).__name__})")


# ---------------------------------------------------------------- ollama
def ollama_info(refresh=False) -> dict:
    base = ollama_base()
    hit = _probe_cache.get(base)
    if hit and not refresh and time.time() - hit[0] < 8:
        return hit[1]
    info = {"base_url": base, "reachable": False, "models": [], "version": None, "local": is_local_url(base)}
    try:
        tags = _get(base + "/api/tags", 1.5)
        info["reachable"] = True
        for m in tags.get("models", []):
            d = m.get("details") or {}
            info["models"].append({"name": m.get("name") or m.get("model"), "size": m.get("size"), "family": d.get("family"),
                                   "params": d.get("parameter_size"), "quant": d.get("quantization_level")})
        try:
            info["version"] = _get(base + "/api/version", 1.0).get("version")
        except Exception:                                   # noqa: BLE001  (older servers)
            pass
    except Exception:                                       # noqa: BLE001
        pass
    _probe_cache[base] = (time.time(), info)
    return info


def forget_probe():
    _probe_cache.clear()


def _pick_ollama_model(info):
    names = [m["name"] for m in info["models"]]
    want = RUNTIME.get("model") or os.environ.get("CLOUDMAP_LLM_MODEL")
    if want and (want in names or want + ":latest" in names):
        return want if want in names else want + ":latest"
    if want and not info["models"]:
        return want
    custom = [n for n in names if n.startswith("cloudmap")]
    return (custom or names or [None])[0]


def create_model(name, base, system, parameters=None):
    """Create a custom model on the Ollama server. Yields status strings; raises LLMError."""
    if not MODEL_NAME.match(name or ""):
        raise LLMError("Model names use lowercase letters, digits, '.', '-', '_' (for example cloudmap-azure).")
    if not MODEL_NAME.match(base or "") and not re.match(r"^[A-Za-z0-9._\-/:]+$", base or ""):
        raise LLMError("Pick an installed base model.")
    body = {"model": name, "from": base, "system": system, "parameters": parameters or {}, "stream": True}
    try:
        for line in _stream_lines(ollama_base() + "/api/create", body, timeout=600):
            if line.get("error"):
                raise LLMError(str(line["error"])[:300])
            if line.get("status"):
                yield str(line["status"])
    except LLMError:
        raise
    except Exception as e:                                  # noqa: BLE001
        raise _wrap(e) from None
    forget_probe()


def modelfile_text(base, system, parameters) -> str:
    esc = system.replace('"""', "'''")
    params = "".join(f"PARAMETER {k} {v}\n" for k, v in (parameters or {}).items())
    return f'FROM {base}\n{params}SYSTEM """{esc}"""\n'


# ---------------------------------------------------------------- selection
def config():
    if os.environ.get("CLOUDMAP_LLM", "").lower() == "off" or RUNTIME.get("off"):
        return None
    ctx = int(os.environ.get("CLOUDMAP_LLM_CTX", "8192") or 8192)
    order = [RUNTIME.get("backend")] if RUNTIME.get("backend") else []
    order += ["openai"] if os.environ.get("CLOUDMAP_LLM_BASE_URL") else []
    order += ["ollama", "anthropic"]
    for b in order:
        if b == "openai" and os.environ.get("CLOUDMAP_LLM_BASE_URL"):
            base = os.environ["CLOUDMAP_LLM_BASE_URL"].rstrip("/")
            return {"backend": "openai", "base_url": base, "key": os.environ.get("CLOUDMAP_LLM_API_KEY", ""),
                    "model": os.environ.get("CLOUDMAP_LLM_MODEL", "llama3.1"), "local": is_local_url(base), "ctx": ctx}
        if b == "ollama":
            info = ollama_info()
            model = _pick_ollama_model(info) if info["reachable"] else None
            if model:
                return {"backend": "ollama", "base_url": info["base_url"], "model": model, "local": info["local"], "ctx": ctx}
        if b == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
            return {"backend": "anthropic", "key": os.environ["ANTHROPIC_API_KEY"], "base_url": "https://api.anthropic.com",
                    "model": os.environ.get("CLOUDMAP_LLM_MODEL", DEFAULT_ANTHROPIC_MODEL), "local": False, "ctx": ctx}
    return None


def status(refresh=False):
    cfg = config()
    info = ollama_info(refresh)
    out = {"ollama": info, "chosen": {k: RUNTIME.get(k) for k in ("backend", "model", "base_url")}}
    if not cfg:
        hint = ("Ollama is running but has no models. Run `ollama pull llama3.1` (or create a custom model here)."
                if info["reachable"] else
                "Start Ollama (https://ollama.com), pull a model, then press Refresh. Or set ANTHROPIC_API_KEY.")
        return {**out, "available": False, "mode": "offline", "hint": hint}
    return {**out, "available": True, "mode": cfg["backend"], "model": cfg["model"], "local": cfg["local"],
            "sends_data": not cfg["local"]}


def set_runtime(backend=None, model=None, base_url=None):
    if base_url:
        RUNTIME["base_url"] = check_url(base_url)
        forget_probe()
    if backend:
        if backend not in ("ollama", "anthropic", "openai", "offline"):
            raise LLMError("Unknown backend.")
        RUNTIME["backend"] = None if backend == "offline" else backend
        RUNTIME["off"] = backend == "offline"
    if model is not None:
        if model and not re.match(r"^[A-Za-z0-9._\-/:]{1,120}$", model):
            raise LLMError("Invalid model name.")
        RUNTIME["model"] = model or None


# ---------------------------------------------------------------- generation
class _Think:
    """Hide <think>…</think> reasoning that some local models stream inline (tags may split across chunks)."""
    OPEN, CLOSE = "<think>", "</think>"

    def __init__(self):
        self.buf, self.inside = "", False

    @staticmethod
    def _held(buf, tag):
        """Length of a suffix of buf that could be the start of `tag`."""
        for n in range(min(len(tag) - 1, len(buf)), 0, -1):
            if tag.startswith(buf[-n:]):
                return n
        return 0

    def feed(self, s):
        self.buf += s
        out = ""
        while True:
            tag = self.CLOSE if self.inside else self.OPEN
            i = self.buf.find(tag)
            if i >= 0:
                if not self.inside:
                    out += self.buf[:i]
                self.buf, self.inside = self.buf[i + len(tag):], not self.inside
                continue
            keep = self._held(self.buf, tag)
            cut = len(self.buf) - keep
            if not self.inside:
                out += self.buf[:cut]
            self.buf = self.buf[cut:]
            return out

    def flush(self):
        return "" if self.inside else self.buf


def stream_chat(system: str, messages: list, cfg=None, max_tokens=1200):
    """Yield text chunks for a conversation. messages: [{role, content}, ...]."""
    cfg = cfg or config()
    if not cfg:
        raise LLMError("no language model configured")
    try:
        if cfg["backend"] == "ollama":
            f = _Think()
            body = {"model": cfg["model"], "stream": True, "keep_alive": "10m",
                    "messages": [{"role": "system", "content": system}] + messages,
                    "options": {"num_ctx": cfg.get("ctx", 8192), "temperature": 0.2, "num_predict": max_tokens}}
            for line in _stream_lines(cfg["base_url"] + "/api/chat", body):
                if line.get("error"):
                    raise LLMError(str(line["error"])[:300])
                t = f.feed((line.get("message") or {}).get("content", ""))
                if t:
                    yield t
                if line.get("done"):
                    break
            tail = f.flush()
            if tail:
                yield tail
            return
        if cfg["backend"] == "anthropic":
            out = _post(cfg["base_url"] + "/v1/messages",
                        {"x-api-key": cfg["key"], "anthropic-version": "2023-06-01", "content-type": "application/json"},
                        {"model": cfg["model"], "max_tokens": max_tokens, "system": system, "messages": messages})
            yield "".join(b.get("text", "") for b in out.get("content", []) if b.get("type") == "text").strip()
            return
        headers = {"content-type": "application/json"}
        if cfg.get("key"):
            headers["authorization"] = "Bearer " + cfg["key"]
        out = _post(cfg["base_url"] + "/v1/chat/completions", headers,
                    {"model": cfg["model"], "max_tokens": max_tokens,
                     "messages": [{"role": "system", "content": system}] + messages})
        yield out["choices"][0]["message"]["content"].strip()
    except LLMError:
        raise
    except Exception as e:                                  # noqa: BLE001
        raise _wrap(e) from None


def complete(system: str, user: str, max_tokens: int = 1200) -> str:
    return "".join(stream_chat(system, [{"role": "user", "content": user}], max_tokens=max_tokens)).strip()
