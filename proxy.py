"""
Ballast PROXY — Option 1 (zero-touch).

Sits in front of the model. An agent points its model URL here instead of at
the model endpoint; every prompt and response flows through and is audited at
the content boundary. Dangerous intents in either the prompt or the reply get a
best-effort flag (a keyword hint, not comprehensive). The agent needs no changes;
it connects to this address as if it were the model endpoint.

    agent --> Ballast proxy --> model (e.g. Ollama)
              (audit + flag)

Scope: the proxy logs every exchange and best-effort-flags dangerous intents in
the prompt or reply. A call that fails (timeout or upstream error) still records
its attempted prompt, so nothing the agent tried is lost. It does not observe tool
execution, which happens inside the agent; that is the role of a future SDK
adapter. And the flag is a substring hint, not a guarantee: it misses intents
phrased outside its keyword list.

Run it:
    python3 proxy.py            # listens on :8100, forwards to Ollama by default

Then point ANY agent at the proxy, sending its model calls here instead of to the
model. Two common ways, depending on what the agent speaks (both are examples):
    OpenAI-compatible:  OPENAI_API_BASE=http://localhost:8100/v1   (Aider, LangChain, openai)
    Ollama-native:      OLLAMA_HOST=localhost:8100                 (ollama client, bundled agent.py)
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import core

LISTEN_PORT = int(os.environ.get("BALLAST_PROXY_PORT", "8100"))
UPSTREAM = os.environ.get("BALLAST_UPSTREAM", "http://localhost:11434")
# Watchdog for a HUNG model, not a latency target. The default is tuned for LOCAL
# edge inference (slow), not a responsive cloud model: set it ABOVE your worst-case
# legitimate call, and cap the model's max_tokens to bound that worst case. Lower it
# (e.g. 30) only for a fast/cloud model; raise it for constrained hardware or big prompts.
UPSTREAM_TIMEOUT = float(os.environ.get("BALLAST_UPSTREAM_TIMEOUT", "120"))

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


def _tool_calls_text(msg):
    """Render a message's tool calls as text so the model's PROPOSED actions are
    captured and scannable. Without this, a tool-calling agent's action (the thing
    that matters) is invisible: it lives in `tool_calls`, not `content`. Handles
    OpenAI (arguments as a JSON string) and Ollama (arguments as a dict)."""
    out = []
    for tc in (msg or {}).get("tool_calls") or []:
        fn = tc.get("function") or {}
        args = fn.get("arguments", "")
        if not isinstance(args, str):
            try:
                args = json.dumps(args)
            except (TypeError, ValueError):
                args = str(args)
        out.append(f"[tool_call] {fn.get('name', '')}({args})")
    return "\n".join(out)


def _extract(req_json, resp_json):
    """Pull (prompt, response_text) out of a chat/generate exchange. Handles both
    Ollama-native (/api/chat, /api/generate) and OpenAI-compatible (/v1) shapes, and
    captures tool calls, so the proxy is model-API agnostic and sees proposed actions."""
    prompt = ""
    if isinstance(req_json, dict):
        msgs = req_json.get("messages")
        prompt = _content_str(msgs[-1].get("content", "")) if msgs else (req_json.get("prompt") or "")
    response = ""
    if isinstance(resp_json, dict):
        # find the assistant message: Ollama has it top-level, OpenAI under choices[0]
        msg = resp_json.get("message")
        if msg is None:
            msg = ((resp_json.get("choices") or [{}])[0] or {}).get("message") or {}
        response = (_content_str(msg.get("content", ""))
                    or resp_json.get("response")
                    or ((resp_json.get("choices") or [{}])[0] or {}).get("text")
                    or "")
        tools = _tool_calls_text(msg)
        if tools:
            response = (response + "\n" + tools).strip()
    return prompt, response


def _reassemble_stream(raw):
    """Reassemble a STREAMED response body into its full text, so streamed replies
    are captured instead of silently dropped. Handles OpenAI SSE (`data: {json}`
    lines with choices[].delta) and Ollama ndjson (one JSON object per line with
    message.content / response). Streamed tool calls are stitched back together and
    rendered too."""
    try:
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    except Exception:
        return ""
    parts = []
    tool_names, tool_args = {}, {}   # index -> name / concatenated arguments
    for line in s.splitlines():
        line = line.strip()
        if line.startswith("data:"):        # OpenAI SSE prefix
            line = line[5:].strip()
        if not line or line == "[DONE]":
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        choices = obj.get("choices")
        if choices:                          # OpenAI streaming: choices[0].delta
            delta = (choices[0] or {}).get("delta") or {}
            if delta.get("content"):
                parts.append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                idx, fn = tc.get("index", 0), (tc.get("function") or {})
                if fn.get("name"):
                    tool_names[idx] = fn["name"]
                if fn.get("arguments"):
                    tool_args[idx] = tool_args.get(idx, "") + fn["arguments"]
            continue
        msg = obj.get("message") or {}       # Ollama streaming: message.content / response
        if msg.get("content"):
            parts.append(msg["content"])
        if obj.get("response"):
            parts.append(obj["response"])
        for tc in msg.get("tool_calls") or []:
            idx, fn = tc.get("index", len(tool_names)), (tc.get("function") or {})
            if fn.get("name"):
                tool_names[idx] = fn["name"]
            args = fn.get("arguments")
            if args is not None:
                tool_args[idx] = tool_args.get(idx, "") + (args if isinstance(args, str) else json.dumps(args))
    text = "".join(parts)
    tools = "\n".join(f"[tool_call] {tool_names.get(i, '')}({tool_args.get(i, '')})"
                      for i in sorted(set(tool_names) | set(tool_args)))
    if tools:
        text = (text + "\n" + tools).strip()
    return text


def _parse_response(raw):
    """Return (dict for _extract, was_streamed). A non-streamed body parses directly;
    a streamed body is reassembled into a single message so it is captured too."""
    try:
        return json.loads(raw), False
    except ValueError:
        text = _reassemble_stream(raw)
        return ({"message": {"content": text}} if text else {}), True


_TOOL_RE = re.compile(r"\[tool_call\]\s*([^\s(]+)\(")


def _chosen_tools(response_text):
    """The tool names the model chose to call, parsed from the captured response.
    Both the streamed and non-streamed paths render tool calls as `[tool_call]
    name(...)`, so this one parser covers both. Deduped, order preserved."""
    seen, out = set(), []
    for name in _TOOL_RE.findall(response_text or ""):
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _danger_flags(prompt, response):
    """Best-effort danger scan of BOTH sides of the exchange. Intent can arrive in
    the prompt (what the agent was told to do) or the reply (what the model
    proposed), so scan each. Returns [(where, hits, text), ...], one entry per side
    that matched. Substring-based, so it is a hint, not a guarantee."""
    out = []
    for where, text in (("prompt", prompt), ("model_response", response)):
        hits = core.scan_text(text)
        if hits:
            out.append((where, hits, text))
    return out


def _error_body(message, code=502, err_type="ballast_error"):
    """A JSON, OpenAI-shaped error so a client degrades cleanly instead of choking
    on an HTML error page."""
    return json.dumps({"error": {"message": message, "type": err_type, "code": code}}).encode()


def _console_line(step, danger, control_hits, controls):
    """One human-readable status line. FLAGGED means a danger-text hit, which emits a
    separate flag record. TAGGED means a policy/control matcher fired, which tags this
    record in place (no separate record). Kept distinct so the console never implies a
    flag record that was not written."""
    policy = [c for c, is_flag in control_hits if is_flag]
    parts = []
    if danger:
        parts.append(f"FLAGGED danger={danger}")
    if policy:
        parts.append(f"TAGGED policy={policy}")
    if parts:
        state = "  ".join(parts)
    elif controls:
        state = f"logged  controls={controls}"
    else:
        state = "logged  (clean)"
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

    def _log_attempt(self, body, error):
        """Record the attempted prompt of a FAILED call so it is never lost. Scans
        and tags the prompt like any exchange. Returns True if it captured an attempt
        (the request was parseable), False otherwise."""
        global _step
        try:
            req_json = json.loads(body)
        except (ValueError, TypeError):
            return False
        prompt, _ = _extract(req_json, {})
        _step += 1
        controls, control_hits = core.log_model_error(_step, prompt, error, model=req_json.get("model"))
        flags = _danger_flags(prompt, "")
        for where, hits, text in flags:
            core.log_flag(where, hits, text)
        danger = sorted({h for _, hits, _ in flags for h in hits})
        print(_console_line(_step, danger, control_hits, controls) + f"  [FAILED: {error}]", flush=True)
        return True

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
            # The model itself returned an error status. Capture the attempted prompt,
            # then pass its own (already JSON) body straight through to the agent.
            err = f"{self.path}: HTTP {e.code}"
            if not self._log_attempt(body, err):
                core.log_system("upstream_http_error", err)
            self._reply(e.code, e.read())
            return
        except OSError as e:
            # Unreachable or timed out: a hung model must not wedge an unattended
            # device. Capture the attempted prompt, return a clean JSON error (not an
            # HTML page), so the agent degrades instead of choking on the response.
            err = f"{self.path}: {e}"
            if not self._log_attempt(body, err):
                core.log_system("upstream_error", err)
            self._reply(504, _error_body(f"upstream unavailable: {e}", 504, "upstream_unavailable"))
            return

        # 2. audit the content boundary (handles streamed and non-streamed replies)
        blocked = False
        try:
            req_json = json.loads(body)
            resp_json, streamed = _parse_response(resp)
            prompt, response = _extract(req_json, resp_json)
            _step += 1
            controls, control_hits = core.log_model_call(
                _step, prompt=prompt, response=response,
                tools_chosen=_chosen_tools(response), model=req_json.get("model"))
            # scan BOTH sides: dangerous intent can arrive in the prompt or the reply
            flags = _danger_flags(prompt, response)
            for where, hits, text in flags:
                core.log_flag(where, hits, text)
            resp_danger = next((hits for where, hits, _ in flags if where == "model_response"), [])
            if resp_danger and core.BLOCK == "on" and not streamed:  # EXPERIMENTAL; can't cleanly block a stream
                resp = _refusal(req_json, resp_danger)
                blocked = True
            danger = sorted({h for _, hits, _ in flags for h in hits})
            print(_console_line(_step, danger, control_hits, controls), flush=True)
            if blocked:
                print(f"[ballast] step {_step}  BLOCKED (experimental)", flush=True)
        except (ValueError, KeyError, TypeError):
            pass  # unparseable request body — forward it, just don't parse

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
