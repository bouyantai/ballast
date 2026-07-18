"""Tests for the opt-in live counter. The load-bearing property is privacy:
the payload must be counts only, never content.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class ReportTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.ALERT = "none"
        core.REPORT = "none"
        core._counts = {"flagged": 0, "actions": 0}

    def test_counts_track_flags_and_blocks(self):
        core.log_flag("model", ["rm -rf"], "rm -rf *")
        core.log_tool_call("run_shell", "ls", "allow", "ok", result="a")
        core.log_tool_call("run_shell", "rm -rf *", "BLOCK", "blocked")
        self.assertEqual(core._counts["flagged"], 2)   # 1 flag + 1 block
        self.assertEqual(core._counts["actions"], 2)   # 2 tool calls

    def test_payload_is_counts_only(self):
        core.log_flag("model", ["rm -rf"], "delete files for jane.doe@example.com")
        payload = core._pending_report()
        self.assertEqual(set(payload), {"flagged", "actions", "reported_at"})
        blob = json.dumps(payload)
        self.assertNotIn("jane.doe@example.com", blob)   # no content
        self.assertNotIn("rm -rf", blob)                  # no content
        self.assertNotIn("session", blob)                 # nothing identifying

    def test_report_is_noop_and_lossless_when_disabled(self):
        core.REPORT = "none"
        core.log_flag("model", ["x"], "y")
        self.assertFalse(core.report())
        self.assertEqual(core._counts["flagged"], 1)      # tally kept, nothing sent


if __name__ == "__main__":
    unittest.main()
