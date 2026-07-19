"""Tests for the proxy's audit-parsing, JSON errors, and console reporting.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import unittest

import core
import proxy


class ExtractTests(unittest.TestCase):
    """The proxy must parse both Ollama-native and OpenAI-compatible shapes."""

    def test_ollama_chat(self):
        req = {"messages": [{"role": "user", "content": "hi"}]}
        resp = {"message": {"content": "hello"}}
        self.assertEqual(proxy._extract(req, resp), ("hi", "hello"))

    def test_ollama_generate(self):
        self.assertEqual(proxy._extract({"prompt": "hi"}, {"response": "hey"}), ("hi", "hey"))

    def test_openai_chat_and_flagging(self):
        req = {"messages": [{"role": "user", "content": "do it"}]}
        resp = {"choices": [{"message": {"content": "sure, run rm -rf /"}}]}
        prompt, out = proxy._extract(req, resp)
        self.assertEqual(prompt, "do it")
        self.assertEqual(out, "sure, run rm -rf /")
        # the whole point: flagging now works on an OpenAI-shaped response
        self.assertIn("rm -rf", core.scan_text(out))

    def test_openai_legacy_completion(self):
        self.assertEqual(proxy._extract({"prompt": "x"}, {"choices": [{"text": "y"}]}), ("x", "y"))

    def test_openai_tool_call_captured_and_flaggable(self):
        resp = {"choices": [{"message": {"content": None, "tool_calls": [
            {"type": "function", "function": {"name": "run_command",
                                              "arguments": '{"cmd": "rm -rf /data"}'}}]}}]}
        _, out = proxy._extract({"messages": [{"role": "user", "content": "clean up"}]}, resp)
        self.assertIn("run_command", out)
        self.assertIn("rm -rf /data", out)
        # the proposed action is now visible to the danger scan
        self.assertIn("rm -rf", core.scan_text(out))

    def test_ollama_tool_call_dict_args(self):
        resp = {"message": {"content": "", "tool_calls": [
            {"function": {"name": "set_thermostat", "arguments": {"celsius": 21}}}]}}
        _, out = proxy._extract({"messages": [{"role": "user", "content": "warm up"}]}, resp)
        self.assertIn("set_thermostat", out)
        self.assertIn("21", out)

    def test_multimodal_content_list(self):
        req = {"messages": [{"role": "user", "content": [{"type": "text", "text": "describe this"}]}]}
        prompt, _ = proxy._extract(req, {"choices": [{"message": {"content": "ok"}}]})
        self.assertEqual(prompt, "describe this")


class StreamReassemblyTests(unittest.TestCase):
    """Streamed replies must be reassembled and captured, not dropped."""

    def test_openai_sse_content(self):
        raw = (b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
               b'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
               b'data: [DONE]\n\n')
        self.assertEqual(proxy._reassemble_stream(raw), "Hello world")

    def test_ollama_ndjson_content(self):
        raw = (b'{"message":{"content":"Hi"}}\n'
               b'{"message":{"content":" there"}}\n'
               b'{"message":{"content":""},"done":true}\n')
        self.assertEqual(proxy._reassemble_stream(raw), "Hi there")

    def test_streamed_danger_is_captured_and_flaggable(self):
        # the exact failure that started this: danger in a streamed reply
        raw = (b'data: {"choices":[{"delta":{"content":"run "}}]}\n\n'
               b'data: {"choices":[{"delta":{"content":"rm -rf /data"}}]}\n\n'
               b'data: [DONE]\n\n')
        resp_json, streamed = proxy._parse_response(raw)
        self.assertTrue(streamed)
        _, out = proxy._extract({"messages": [{"role": "user", "content": "x"}]}, resp_json)
        self.assertIn("rm -rf", core.scan_text(out))

    def test_streamed_tool_call_reassembled(self):
        raw = (b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"run_command"}}]}}]}\n\n'
               b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"cmd\\":\\"rm -rf /\\"}"}}]}}]}\n\n'
               b'data: [DONE]\n\n')
        out = proxy._reassemble_stream(raw)
        self.assertIn("run_command", out)
        self.assertIn("rm -rf", out)

    def test_nonstream_still_parses_and_is_not_marked_streamed(self):
        resp_json, streamed = proxy._parse_response(b'{"choices":[{"message":{"content":"hi"}}]}')
        self.assertFalse(streamed)
        _, out = proxy._extract({"messages": [{"role": "user", "content": "x"}]}, resp_json)
        self.assertEqual(out, "hi")


class ErrorBodyTests(unittest.TestCase):
    def test_json_error_shape(self):
        body = proxy._error_body("upstream unavailable: timed out", 504, "upstream_unavailable")
        data = json.loads(body)  # must be valid JSON, not an HTML page
        self.assertEqual(data["error"]["code"], 504)
        self.assertEqual(data["error"]["type"], "upstream_unavailable")
        self.assertIn("timed out", data["error"]["message"])


class ConsoleLineTests(unittest.TestCase):
    def test_clean(self):
        self.assertIn("(clean)", proxy._console_line(1, [], [], []))

    def test_danger(self):
        line = proxy._console_line(2, ["rm -rf"], [], [])
        self.assertIn("FLAGGED", line)
        self.assertIn("rm -rf", line)

    def test_policy_match_is_tagged_not_flagged(self):
        # a control matcher fired: it TAGS the record in place, it does NOT emit a flag
        # record, so the console must say TAGGED, not FLAGGED
        line = proxy._console_line(3, [], [("164.502(b)", True)], ["164.312(b)", "164.502(b)"])
        self.assertIn("TAGGED", line)
        self.assertNotIn("FLAGGED", line)
        self.assertIn("164.502(b)", line)
        self.assertNotIn("(clean)", line)

    def test_danger_and_policy_shown_separately(self):
        line = proxy._console_line(5, ["rm -rf"], [("164.502(b)", True)], ["164.502(b)"])
        self.assertIn("FLAGGED", line)   # danger emits a flag record
        self.assertIn("TAGGED", line)    # policy tags in place

    def test_ambient_controls_shown_without_flag(self):
        line = proxy._console_line(4, [], [], ["164.312(b)"])
        self.assertIn("164.312(b)", line)
        self.assertNotIn("FLAGGED", line)


class DangerScanTests(unittest.TestCase):
    """Danger is scanned on BOTH sides, and honestly limited to what the keyword
    list knows."""

    def test_flags_prompt_side(self):
        flags = proxy._danger_flags("please run rm -rf /", "sure thing")
        self.assertIn("prompt", [w for w, _, _ in flags])

    def test_flags_response_side(self):
        flags = proxy._danger_flags("hi", "ok: rm -rf /tmp/x")
        self.assertIn("model_response", [w for w, _, _ in flags])

    def test_flags_both_sides(self):
        flags = proxy._danger_flags("rm -rf a", "rm -rf b")
        self.assertEqual(sorted(w for w, _, _ in flags), ["model_response", "prompt"])

    def test_clean_exchange_has_no_flags(self):
        self.assertEqual(proxy._danger_flags("hello", "world"), [])

    def test_substring_limitation_is_real(self):
        # honest: a Python-destructive call is NOT caught by the shell-word list.
        # This test documents the limitation on purpose, so a regression is visible.
        self.assertEqual(proxy._danger_flags("clear the cache", "shutil.rmtree('./cache')"), [])


class ChosenToolsTests(unittest.TestCase):
    """tools_chosen summarizes which tools the model picked, from the response text."""

    def test_parses_names_in_order(self):
        text = ('some reasoning\n[tool_call] run_command({"cmd":"ls"})\n'
                '[tool_call] set_thermostat({"celsius":21})')
        self.assertEqual(proxy._chosen_tools(text), ["run_command", "set_thermostat"])

    def test_dedupes(self):
        text = "[tool_call] run_command(a)\n[tool_call] run_command(b)"
        self.assertEqual(proxy._chosen_tools(text), ["run_command"])

    def test_empty_when_no_tool_calls(self):
        self.assertEqual(proxy._chosen_tools("just a normal reply"), [])


class RequestPassthroughTests(unittest.TestCase):
    """INVARIANT: Ballast forwards the request body to the model byte-for-byte.
    Proven by putting a mock model behind the proxy and comparing what it received
    to what was sent."""

    def test_request_body_is_forwarded_unchanged(self):
        import os
        import tempfile
        import threading
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        received = {}

        class Echo(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                received["body"] = self.rfile.read(n)
                out = b'{"message": {"content": "ok"}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        d = tempfile.mkdtemp()   # audit to temp so we don't touch the working dir
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        saved_upstream = proxy.UPSTREAM

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        proxy.UPSTREAM = f"http://127.0.0.1:{upstream.server_address[1]}"
        front = ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
        threading.Thread(target=front.serve_forever, daemon=True).start()
        port = front.server_address[1]

        # exact bytes, including non-ASCII and doubled whitespace we must not touch
        body = b'{"model":"m","messages":[{"role":"user","content":"exact  \xc3\xa9  bytes"}],"z":true}'
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        finally:
            front.shutdown()
            upstream.shutdown()
            proxy.UPSTREAM = saved_upstream

        self.assertEqual(received.get("body"), body)   # nothing added, removed, or rewritten


class UsageTests(unittest.TestCase):
    """Token counts come from the model's own usage report, non-streamed and streamed."""

    def test_openai_usage(self):
        u = proxy._usage({"usage": {"prompt_tokens": 12, "completion_tokens": 7}})
        self.assertEqual(u, {"prompt": 12, "completion": 7})

    def test_ollama_eval_counts(self):
        self.assertEqual(proxy._usage({"prompt_eval_count": 20, "eval_count": 9}),
                         {"prompt": 20, "completion": 9})

    def test_none_when_absent(self):
        self.assertIsNone(proxy._usage({"message": {"content": "hi"}}))

    def test_stream_usage_openai(self):
        raw = (b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
               b'data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3}}\n\n'
               b'data: [DONE]\n\n')
        self.assertEqual(proxy._stream_usage(raw), {"prompt": 5, "completion": 3})

    def test_stream_usage_ollama(self):
        raw = b'{"message":{"content":"hi"}}\n{"done":true,"prompt_eval_count":8,"eval_count":4}\n'
        self.assertEqual(proxy._stream_usage(raw), {"prompt": 8, "completion": 4})

    def test_parse_response_streamed_surfaces_usage(self):
        raw = (b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
               b'data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3}}\n\n'
               b'data: [DONE]\n\n')
        d, streamed = proxy._parse_response(raw)
        self.assertTrue(streamed)
        self.assertEqual(proxy._usage(d), {"prompt": 5, "completion": 3})


class BannerTests(unittest.TestCase):
    """The startup banner must show both integration routes and read as examples,
    so it never regresses to implying an Ollama-only, must-run-agent.py workflow."""

    def test_shows_both_routes_port_and_reads_as_example(self):
        b = proxy._startup_banner()
        self.assertIn(f":{proxy.LISTEN_PORT}", b)   # the real listen port
        self.assertIn("/v1", b)                     # OpenAI-compatible route
        self.assertIn("OPENAI_API_BASE", b)
        self.assertIn("OLLAMA_HOST", b)             # Ollama-native route
        self.assertIn("example", b.lower())         # framed as examples, not steps


if __name__ == "__main__":
    unittest.main()
