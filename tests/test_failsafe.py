"""Tests for fail-safe posture and liveness/watchdog behavior.

Standard library only. Run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class FailSafeTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core._last_beat = 0.0
        core.FAIL_MODE = "closed"

    def test_fail_closed_denies_by_default(self):
        core.FAIL_MODE = "closed"
        allowed, reason = core.safe_verdict("boom")
        self.assertFalse(allowed)
        self.assertIn("fail-closed", reason)

    def test_fail_open_allows_when_configured(self):
        core.FAIL_MODE = "open"
        allowed, reason = core.safe_verdict("boom")
        self.assertTrue(allowed)
        self.assertIn("fail-open", reason)

    def test_decide_never_raises_and_falls_back_safe(self):
        core.FAIL_MODE = "closed"
        allowed, _ = core.decide("run_shell", None)   # None.lower() would raise
        self.assertFalse(allowed)                       # ...but we fail closed instead

    def test_heartbeat_then_healthy(self):
        core.heartbeat(force=True)
        self.assertTrue(core.health()["alive"])

    def test_stale_heartbeat_reads_as_down(self):
        core.heartbeat(force=True)
        with open(core.HEALTH_FILE) as f:
            rec = json.load(f)
        rec["epoch"] = 0                                # long ago
        with open(core.HEALTH_FILE, "w") as f:
            json.dump(rec, f)
        self.assertFalse(core.health(max_age=5)["alive"])

    def test_no_heartbeat_reads_as_down(self):
        if os.path.exists(core.HEALTH_FILE):
            os.remove(core.HEALTH_FILE)
        self.assertFalse(core.health()["alive"])


if __name__ == "__main__":
    unittest.main()
