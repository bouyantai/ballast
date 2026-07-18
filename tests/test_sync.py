"""Tests for store-and-forward and the experimental block refusal.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(self.d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(self.d, "a.chain")
        core.HEALTH_FILE = os.path.join(self.d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.REDACT_MODE = "off"
        self.sink = os.path.join(self.d, "sink.ndjson")
        core.SYNC = "file:" + self.sink

    def _sink_lines(self):
        try:
            with open(self.sink) as f:
                return [l for l in f.read().splitlines() if l.strip()]
        except FileNotFoundError:
            return []

    def test_delivers_then_idempotent(self):
        core.log_model_call(1, "a", "b")
        core.log_model_call(2, "c", "d")
        self.assertEqual(core.sync(), 2)
        self.assertEqual(len(self._sink_lines()), 2)
        self.assertEqual(core.sync(), 0)              # nothing new to send
        self.assertEqual(len(self._sink_lines()), 2)  # not double-sent

    def test_only_sends_new_records(self):
        core.log_model_call(1, "a", "b")
        self.assertEqual(core.sync(), 1)
        core.log_model_call(2, "c", "d")
        core.log_tool_call("run_shell", "ls", "allow", "ok", result="x")
        self.assertEqual(core.sync(), 2)              # only the two new ones
        self.assertEqual(len(self._sink_lines()), 3)

    def test_noop_when_disabled(self):
        core.SYNC = "none"
        core.log_model_call(1, "a", "b")
        self.assertEqual(core.sync(), 0)
        self.assertEqual(self._sink_lines(), [])

    def test_block_refusal_matches_request_shape(self):
        import proxy
        chat = json.loads(proxy._refusal({"messages": [{"role": "user", "content": "x"}]}, ["rm -rf"]))
        self.assertIn("message", chat)
        gen = json.loads(proxy._refusal({"prompt": "x"}, ["rm -rf"]))
        self.assertIn("response", gen)


if __name__ == "__main__":
    unittest.main()
