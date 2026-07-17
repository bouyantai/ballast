"""Tests for external anchoring: proving the local trail against off-device roots.

The point of anchoring is to catch tampering that stays internally consistent, so
these tests confirm that plain verify_chain() passes on the tampered trail while
verify_against() catches it.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class AnchorTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.REDACT_MODE = "off"
        core.ANCHOR = "none"

    def _checkpoint(self):
        cp, _ = core.anchor()
        return cp

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def _write(self, records):
        with open(core.AUDIT_FILE, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_passes_when_untampered(self):
        core.log_model_call(1, "a", "b")
        core.log_model_call(2, "c", "d")
        cp = self._checkpoint()          # anchors records=2
        core.log_model_call(3, "e", "f")  # trail keeps growing, that's fine
        ok, _ = core.verify_against([cp])
        self.assertTrue(ok)

    def test_detects_truncation(self):
        core.log_model_call(1, "a", "b")
        core.log_model_call(2, "c", "d")
        core.log_model_call(3, "e", "f")
        cp = self._checkpoint()          # anchors records=3
        # attacker deletes the last two records to hide recent activity
        self._write(self._records()[:1])
        # a purely local check cannot see it: the shortened chain is still consistent
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])
        # the external anchor catches it
        ok, msg = core.verify_against([cp])
        self.assertFalse(ok)
        self.assertIn("truncat", msg)

    def test_detects_consistent_rewrite(self):
        core.log_tool_call("run_shell", "ls", "allow", "ok", result="x")
        core.log_tool_call("run_shell", "cat file", "allow", "ok", result="y")
        cp = self._checkpoint()          # anchors records=2, root=H
        # attacker rewrites record 2 and re-chains it so plain verify still passes
        recs = self._records()
        r = recs[1]
        r.pop("hash")
        r.pop("seal", None)
        r["arg"] = "rm -rf /"            # the action they want to hide
        r["prev"] = recs[0]["hash"]
        r["hash"] = core._sha(r["prev"] + json.dumps(r, sort_keys=True))
        recs[1] = r
        self._write(recs)
        # the forged chain is internally consistent, so plain verify passes
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])
        # but its root no longer matches the external anchor
        ok, msg = core.verify_against([cp])
        self.assertFalse(ok)
        self.assertIn("anchor mismatch", msg)


if __name__ == "__main__":
    unittest.main()
