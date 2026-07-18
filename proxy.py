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
    python3 proxy.py                     # listens on :8100, forwards to Ollama
    # then, in another terminal:
    OLLAMA_HOST=localhost:8100 python3 agent.py "list the files here"
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


def _extract(req_json, resp_json):
    """Pull (prompt, response_text) out of Ollama's chat/generate payloads."""
    prompt = ""
    if isinstance(req_json, dict):
        msgs = req_json.get("messages")
        prompt = (msgs[-1].get("content", "") if msgs else req_json.get("prompt", ""))
    response = ""
    if isinstance(resp_json, dict):
        response = (resp_json.get("message") or {}).get("content", "") or resp_json.get("response", "")
    return prompt, response


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global _step
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        # 1. forward the request to the real model, untouched
        try:
            req = urllib.request.Request(
                UPSTREAM + self.path, data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as r:
                resp, status = r.read(), r.status
        except OSError as e:
            # A hung or unreachable model must not wedge an unattended device:
            # time out, record it, and return a clear error instead of hanging.
            core.log_system("upstream_error", f"{self.path}: {e}")
            self.send_error(504, f"upstream unavailable: {e}")
            return

        # 2. audit the content boundary (best-effort; skip if not plain JSON)
        blocked = False
        try:
            req_json = json.loads(body)
            prompt, response = _extract(req_json, json.loads(resp))
            _step += 1
            core.log_model_call(_step, prompt=prompt, response=response)
            hits = core.scan_text(response)
            if hits:
                core.log_flag("model_response", hits, response)
                if core.BLOCK == "on":                     # EXPERIMENTAL, best-effort
                    resp = _refusal(req_json, hits)
                    blocked = True
                    print(f"[ballast] step {_step}  BLOCKED (experimental): {hits}")
                else:
                    print(f"[ballast] step {_step}  FLAGGED: {hits}")
            else:
                print(f"[ballast] step {_step}  logged (clean)")
        except (ValueError, KeyError, TypeError):
            pass  # streaming or non-JSON body — forward it, just don't parse

        # 3. hand the response back to the agent (unchanged, or a refusal if blocked)
        self.send_response(200 if blocked else status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

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


def main():
    print(f"Ballast proxy listening on :{LISTEN_PORT}  ->  {UPSTREAM}")
    print(f"Point an agent at it:  OLLAMA_HOST=localhost:{LISTEN_PORT} python3 agent.py \"...\"")
    core.log_system("startup", f"proxy on :{LISTEN_PORT} -> {UPSTREAM}")
    core.heartbeat(force=True)
    threading.Thread(target=_heartbeat_loop, daemon=True).start()
    ThreadingHTTPServer(("", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
