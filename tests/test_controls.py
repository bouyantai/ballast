"""Tests for control tagging.

Two behaviors:
  - AMBIENT controls tag every record of a kind (record-keeping style).
  - MATCHER controls tag a record only when its content matches, and an
    on_match:flag matcher also stores content and raises the flag count.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class ControlTagTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.REDACT_MODE = "off"
        core._counts = {"flagged": 0, "actions": 0}
        # one ambient control (all model_calls) + one triggered flag matcher
        core.AMBIENT_TAGS = {"model_call": ["164.312(b)"]}
        core.MATCHERS = [{
            "id": "164.502(b)",
            "kinds": {"model_call", "tool_call"},
            "text": ["patient", "diagnos"],
            "regex": [],
            "flag": True,
        }]

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_ambient_tags_every_record_of_kind(self):
        core.log_model_call(1, "hello there", "hi")  # benign, no PHI
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        self.assertEqual(mc.get("controls"), ["164.312(b)"])
        self.assertEqual(core._counts["flagged"], 0)

    def test_matcher_tags_flags_and_stores_on_hit(self):
        core.log_model_call(2, "summarize the patient chart", "the diagnosis is X")
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        # carries both the ambient tag and the triggered control
        self.assertIn("164.312(b)", mc["controls"])
        self.assertIn("164.502(b)", mc["controls"])
        # a flag matcher forces content storage and bumps the flag count
        self.assertIn("content", mc)
        self.assertEqual(core._counts["flagged"], 1)

    def test_no_match_no_triggered_tag(self):
        core.log_model_call(3, "what is the weather", "sunny")
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        self.assertNotIn("164.502(b)", mc.get("controls", []))
        self.assertEqual(core._counts["flagged"], 0)

    def test_matcher_sees_content_before_redaction(self):
        # PHI-context word survives; detection runs pre-redaction regardless
        core.REDACT_MODE = "on"
        core.log_tool_call("run_shell", "echo patient record", "ALLOW", "ok", result="done")
        tc = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertIn("164.502(b)", tc.get("controls", []))

    def test_untagged_kind_has_no_controls_field(self):
        core.log_tool_call("run_shell", "ls", "ALLOW", "ok", result="x")  # no ambient, no match
        tc = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertNotIn("controls", tc)

    def test_tagged_chain_still_verifies(self):
        core.log_model_call(4, "patient intake", "ok")
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])


if __name__ == "__main__":
    unittest.main()
