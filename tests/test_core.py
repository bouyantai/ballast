"""Tests for Ballast core: policy, content scanning, and the tamper-evident audit.

Pure standard library — run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class CoreTests(unittest.TestCase):
    def setUp(self):
        # redirect the audit trail into a throwaway temp dir per test
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "audit.jsonl")
        core.CHAIN_FILE = os.path.join(d, "audit.chain")
        core._last = None
        core.CONTENT_MODE = "events"

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_decide_blocks_rm_and_allows_ls(self):
        self.assertFalse(core.decide("run_shell", "rm -rf *")[0])
        self.assertFalse(core.decide("run_shell", "find . -delete")[0])  # allowlist closes the hole
        self.assertTrue(core.decide("run_shell", "ls -l")[0])

    def test_scan_text_flags_dangerous_intent(self):
        self.assertIn("rm -rf", core.scan_text("sure, just run rm -rf / to clean up"))
        self.assertEqual(core.scan_text("please list the files"), [])

    def test_chain_verifies_clean_and_catches_tampering(self):
        core.log_model_call(1, "count lines", "ACTION: list_files | .")
        core.log_tool_call("list_files", ".", "allow", "ok", result="a\nb")
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])

        # edit one byte of the first record on disk
        with open(core.AUDIT_FILE) as f:
            lines = f.read().splitlines()
        lines[0] = lines[0].replace('"model_call"', '"forged"')
        with open(core.AUDIT_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")

        ok, msg = core.verify_chain(core.AUDIT_FILE)
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

    def test_tiering_is_lean_by_default(self):
        core.log_tool_call("list_files", ".", "allow", "ok", result="x")  # routine -> hash only
        core.log_flag("model_response", ["rm -rf"], "rm -rf *")            # noteworthy -> full content
        recs = self._records()
        self.assertNotIn("content", recs[0], "allowed calls should not store bulky content")
        self.assertIn("content", recs[1], "flags should store the offending content")


if __name__ == "__main__":
    unittest.main()
