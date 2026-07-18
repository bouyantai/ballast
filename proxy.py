"""
Ballast PROXY — Option 1 (zero-touch).

Sits in front of the model. An agent points its model URL here instead of at
the model endpoint; every prompt and response flows through and is audited at
the content boundary, with dangerous command intents flagged. The agent needs
no changes; it connects to this address as if it were the model endpoint.

    agent ──▶ Ballast proxy ──▶ model (e.g. Ollama)
              (audit + flag)

Scope: the proxy logs every exchange and flags dangerous intents in the model's
reply. It does not observe tool execution, which happens inside the agent — that
is the role of a future SDK adapter.

Run it:
    python3 proxy.py            # listens on :8100, forwards to Ollama by default

Then point ANY agent at the proxy, sending its model calls here instead of to the
model. Two common ways, depending on what the agent speaks (both are examples):
    OpenAI-compatible:  OPENAI_API_BASE=http://localhost:8100/v1   (Aider, LangChain, openai)
    Ollama-native:      OLLAMA_HOST=localhost:8100                 (ollama client, bundled agent.py)
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import core

LISTEN_PORT = int(os.environ.get("BALLAST_PROXY_PORT", "8100"))
UPSTREAM = os.environ.get("BALLAST_UPSTREAM", "http://localhost:11434")
UPSTREAM_TIMEOUT = float(os.environ.get("BALLAST_UPSTREAM_TIMEOUT", "30"))  # a hung model must not wedge the device

_step = 0


def _refusal(req_json, hits):
    """EXPERIMENTAL: a model-shaped response that withholds the flagged content."""
    msg = "[Ballast] Response withheld: dangerous intent detected (" + ", ".join(hits) + ")."
    if isinstance(req_json, dict) and req_json.get("messages") is not None:
        payload = {"message": {"role": "assistant", "content": msg}, "done": True}
    else:
        payload = {"response": msg, "done": True}
    return json.dumps(payload).encode()


def _content_str(c):
    """A message's content is a string, or a list of parts (OpenAI multimodal)."""
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c
                        if isinstance(p, dict) and p.get("type") == "text")
    return ""


def _extract(req_json, resp_json):
    """Pull (prompt, response_text) out of a chat/generate exchange. Handles both
    Ollama-native (/api/chat, /api/generate) and OpenAI-compatible (/v1) shapes, so
    the proxy is model-API agnostic, not just Ollama-shaped."""
    prompt = ""
    if isinstance(req_json, dict):
        msgs = req_json.get("messages")
        prompt = _content_str(msgs[-1].get("content", "")) if msgs else (req_json.get("prompt") or "")
    response = ""
    if isinstance(resp_json, dict):
        # Ollama: /api/chat -> message.content, /api/generate -> response
        response = (resp_json.get("message") or {}).get("content") or resp_json.get("response") or ""
        if not response:
            # OpenAI: /v1/chat/completions -> choices[0].message.content,
            #         /v1/completions      -> choices[0].text
            first = (resp_json.get("choices") or [{}])[0] or {}
            response = _content_str((first.get("message") or {}).get("content", "")) or first.get("text") or ""
    return prompt, response


def _error_body(message, code=502, err_type="ballast_error"):
    """A JSON, OpenAI-shaped error so a client degrades cleanly instead of choking
    on an HTML error page."""
    return json.dumps({"error": {"message": message, "type": err_type, "code": code}}).encode()


def _console_line(step, danger, control_hits, controls):
    """One human-readable status line. Surfaces danger-text flags AND framework
    control matches, so a pack doing its job is never silent."""
    policy = [c for c, is_flag in control_hits if is_flag]
    if danger:
        state = f"FLAGGED  danger={danger}"
    elif policy:
        state = f"FLAGGED  policy={policy}"
    elif controls:
        state = f"logged   controls={controls}"
    else:
        state = "logged   (clean)"
    return f"[ballast] step {step}  {state}"


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status, body):
        """Send a JSON response body. Swallows a client hang-up: the agent going
        away must never crash the proxy."""
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def do_POST(self):
        global _step
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)

        # 1. forward the request to the real model, untouched
        try:
            req = urllib.request.Request(
                UPSTREAM + self.path, data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as r:
                resp, status = r.read(), r.status
        except urllib.error.HTTPError as e:
            # The model itself returned an error status. Pass its own (already JSON)
            # body straight through so the agent sees the real error.
            core.log_system("upstream_http_error", f"{self.path}: {e.code}")
            self._reply(e.code, e.read())
            return
        except OSError as e:
            # Unreachable or timed out: a hung model must not wedge an unattended
            # device. Return a clean JSON error, not an HTML page, so the agent
            # degrades instead of choking on the response.
            core.log_system("upstream_error", f"{self.path}: {e}")
            self._reply(504, _error_body(f"upstream unavailable: {e}", 504, "upstream_unavailable"))
            return

        # 2. audit the content boundary (best-effort; skip if not plain JSON)
        blocked = False
        try:
            req_json = json.loads(body)
            prompt, response = _extract(req_json, json.loads(resp))
            _step += 1
            controls, control_hits = core.log_model_call(_step, prompt=prompt, response=response)
            danger = core.scan_text(response)
            if danger:
                core.log_flag("model_response", danger, response)
                if core.BLOCK == "on":                     # EXPERIMENTAL, best-effort
                    resp = _refusal(req_json, danger)
                    blocked = True
            print(_console_line(_step, danger, control_hits, controls), flush=True)
            if blocked:
                print(f"[ballast] step {_step}  BLOCKED (experimental)", flush=True)
        except (ValueError, KeyError, TypeError):
            pass  # streaming or non-JSON body — forward it, just don't parse

        # 3. hand the response back to the agent (unchanged, or a refusal if blocked)
        self._reply(200 if blocked else status, resp)

    def log_message(self, *args):
        pass  # silence the default per-request console spam


def _heartbeat_loop():
    """Prove liveness on a fixed interval so a supervisor can spot a wedged proxy
    even when there is no traffic."""
    while True:
        time.sleep(core.HEARTBEAT_INTERVAL)
        core.heartbeat(force=True)
        if core.REPORT != "none":   # opt-in: push the counts tally when online
            core.report()
        if core.SYNC != "none":     # store-and-forward: flush buffered records
            core.sync()


def _startup_banner():
    """What is listening, plus EXAMPLE ways to point an agent at it. These are
    examples, not required steps: any agent works by sending its model calls to
    this address instead of to the model. Reflects the real port, upstream, and
    loaded pack, so the banner never misstates the running config."""
    pack = os.environ.get("BALLAST_POLICY_FILE")
    return "\n".join([
        f"Ballast proxy listening on :{LISTEN_PORT}  ->  {UPSTREAM}",
        f"Policy pack: {pack}" if pack else "Policy pack: none (built-in default)",
        "",
        "Point any agent here by sending its model calls to the proxy instead of to",
        "the model. Pick the line matching what your agent speaks (these are examples):",
        f"  OpenAI-compatible:  OPENAI_API_BASE=http://localhost:{LISTEN_PORT}/v1   (Aider, LangChain, openai)",
        f"  Ollama-native:      OLLAMA_HOST=localhost:{LISTEN_PORT}                 (ollama client, bundled agent.py)",
        "",
        "Read the trail:  python3 cli.py log   (also: summary, verify)",
    ])


def main():
    print(_startup_banner())
    core.log_system("startup", f"proxy on :{LISTEN_PORT} -> {UPSTREAM}")
    core.heartbeat(force=True)
    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    ThreadingHTTPServer(("", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
