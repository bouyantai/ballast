"""Tests for the audit-value features: sessions, redaction, sealing, attest, SDK.

Standard library only — run with:  python3 -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

import core


class FeatureTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "audit.jsonl")
        core.CHAIN_FILE = os.path.join(d, "audit.chain")
        core._last = None
        core.CONTENT_MODE = "events"
        core.REDACT_MODE = "on"
        core.SIGN_KEY = None
        core.ALERT = "none"

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_every_record_carries_a_session(self):
        core.log_model_call(1, "hi", "there")
        rec = self._records()[0]
        self.assertTrue(rec["session"])
        self.assertEqual(rec["session"], core.SESSION)

    def test_redaction_scrubs_pii_before_storage(self):
        core.CONTENT_MODE = "always"  # force content storage so we can inspect it
        core.log_model_call(1, "reach me at jane.doe@example.com", "ok")
        stored = self._records()[0]["content"]["prompt"]
        self.assertNotIn("jane.doe@example.com", stored)
        self.assertIn("[REDACTED]", stored)

    def test_hmac_seal_survives_verify_and_catches_wrong_key(self):
        core.SIGN_KEY = "topsecret"
        core.log_model_call(1, "a", "b")
        core.log_tool_call("ls", ".", "allow", "ok", result="x")
        self.assertIn("seal", self._records()[0])
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])

        core.SIGN_KEY = "wrong-key"  # a different key must fail the seal check
        ok, msg = core.verify_chain(core.AUDIT_FILE)
        self.assertFalse(ok)
        self.assertIn("seal", msg)

    def test_attest_reports_head_and_count(self):
        core.log_model_call(1, "a", "b")
        core.log_model_call(2, "c", "d")
        att = core.attest(core.AUDIT_FILE)
        self.assertEqual(att["records"], 2)
        self.assertEqual(len(att["root"]), 64)
        self.assertFalse(att["sealed"])

    def test_redaction_covers_all_fields_not_just_content(self):
        core.CONTENT_MODE = "always"
        core.log_tool_call(
            "transmit",
            "camera: jane.doe@example.com SSN 123-45-6789",
            "BLOCK", "offsite transmit forbidden",
            result="sent jane.doe@example.com",
        )
        raw = open(core.AUDIT_FILE).read()
        self.assertNotIn("jane.doe@example.com", raw)   # must not leak via meta `arg`
        self.assertNotIn("123-45-6789", raw)
        self.assertIn("[REDACTED]", raw)


if __name__ == "__main__":
    unittest.main()
