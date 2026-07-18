"""Tests for control tagging: records carry the control ids they evidence.

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
        core.CONTROL_TAGS = {"flag": ["MEASURE 2.6", "MANAGE 4.3"], "model_call": ["MEASURE 2.8"]}

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_records_carry_control_tags(self):
        core.log_model_call(1, "a", "b")
        core.log_flag("model", ["rm -rf"], "rm -rf *")
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        fl = next(r for r in self._records() if r["kind"] == "flag")
        self.assertEqual(mc.get("controls"), ["MEASURE 2.8"])
        self.assertIn("MANAGE 4.3", fl.get("controls", []))

    def test_untagged_kind_has_no_controls_field(self):
        core.log_tool_call("run_shell", "ls", "allow", "ok", result="x")  # not in the map
        rec = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertNotIn("controls", rec)

    def test_tagged_chain_still_verifies(self):
        core.log_flag("model", ["rm -rf"], "x")
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])


if __name__ == "__main__":
    unittest.main()
