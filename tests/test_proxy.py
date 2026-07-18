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

    def test_multimodal_content_list(self):
        req = {"messages": [{"role": "user", "content": [{"type": "text", "text": "describe this"}]}]}
        prompt, _ = proxy._extract(req, {"choices": [{"message": {"content": "ok"}}]})
        self.assertEqual(prompt, "describe this")


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

    def test_policy_flag_is_surfaced(self):
        # a matcher fired: the console must say so, not "(clean)"
        line = proxy._console_line(3, [], [("164.502(b)", True)], ["164.312(b)", "164.502(b)"])
        self.assertIn("FLAGGED", line)
        self.assertIn("164.502(b)", line)
        self.assertNotIn("(clean)", line)

    def test_ambient_controls_shown_without_flag(self):
        line = proxy._console_line(4, [], [], ["164.312(b)"])
        self.assertIn("164.312(b)", line)
        self.assertNotIn("FLAGGED", line)


if __name__ == "__main__":
    unittest.main()
