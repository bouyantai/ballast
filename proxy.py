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
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import core

LISTEN_PORT = int(os.environ.get("BALLAST_PROXY_PORT", "8100"))
UPSTREAM = os.environ.get("BALLAST_UPSTREAM", "http://localhost:11434")

_step = 0


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
            with urllib.request.urlopen(req) as r:
                resp, status = r.read(), r.status
        except urllib.error.URLError as e:
            self.send_error(502, f"upstream unreachable: {e}")
            return

        # 2. audit the content boundary (best-effort; skip if not plain JSON)
        try:
            prompt, response = _extract(json.loads(body), json.loads(resp))
            _step += 1
            core.log_model_call(_step, prompt=prompt, response=response)
            hits = core.scan_text(response)
            if hits:
                core.log_flag("model_response", hits, response)
                print(f"[ballast] step {_step}  ⚠  FLAGGED dangerous intent: {hits}")
            else:
                print(f"[ballast] step {_step}  logged (clean)")
        except (ValueError, KeyError, TypeError):
            pass  # streaming or non-JSON body — forward it, just don't parse

        # 3. hand the model's response back to the agent, unchanged
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):
        pass  # silence the default per-request console spam


def main():
    print(f"Ballast proxy listening on :{LISTEN_PORT}  ->  {UPSTREAM}")
    print(f"Point an agent at it:  OLLAMA_HOST=localhost:{LISTEN_PORT} python3 agent.py \"...\"")
    ThreadingHTTPServer(("", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
