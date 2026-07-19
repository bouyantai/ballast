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
        # one ambient control (all model_calls) + one OR matcher + one AND matcher
        core.AMBIENT_TAGS = {"model_call": ["164.312(b)"]}
        core.MATCHERS = [
            {
                "id": "164.502(b)",
                "kinds": {"model_call", "tool_call"},
                "text": ["patient", "diagnos"],
                "regex": [],
                "all": [],
                "flag": True,
            },
            {
                "id": "164.312(e)",  # AND: PHI context AND a plaintext endpoint
                "kinds": {"model_call", "tool_call"},
                "text": [],
                "regex": [],
                "all": [
                    {"text": ["patient"], "regex": []},
                    {"text": [], "regex": [core.re.compile(r"(?i)\bhttp://\S+")]},
                ],
                "flag": True,
            },
        ]

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_ambient_tags_every_record_of_kind(self):
        core.log_model_call(1, "hello there", "hi")  # benign, no PHI
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        self.assertEqual(mc.get("related_controls"), ["164.312(b)"])
        self.assertEqual(core._counts["flagged"], 0)

    def test_matcher_tags_flags_and_stores_on_hit(self):
        core.log_model_call(2, "summarize the patient chart", "the diagnosis is X")
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        # carries both the ambient tag and the triggered control
        self.assertIn("164.312(b)", mc["related_controls"])
        self.assertIn("164.502(b)", mc["related_controls"])
        # a flag matcher forces content storage and bumps the flag count
        self.assertIn("content", mc)
        self.assertEqual(core._counts["flagged"], 1)

    def test_no_match_no_triggered_tag(self):
        core.log_model_call(3, "what is the weather", "sunny")
        mc = next(r for r in self._records() if r["kind"] == "model_call")
        self.assertNotIn("164.502(b)", mc.get("related_controls", []))
        self.assertEqual(core._counts["flagged"], 0)

    def test_matcher_sees_content_before_redaction(self):
        # PHI-context word survives; detection runs pre-redaction regardless
        core.REDACT_MODE = "on"
        core.log_tool_call("run_shell", "echo patient record", "ALLOW", "ok", result="done")
        tc = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertIn("164.502(b)", tc.get("related_controls", []))

    def test_and_matcher_needs_both_groups(self):
        # PHI context alone -> does NOT fire the AND transmission matcher
        core.log_model_call(5, "the patient is stable", "ok")
        mc = next(r for r in self._records() if r.get("step") == 5)
        self.assertNotIn("164.312(e)", mc.get("related_controls", []))
        # PHI context AND a plaintext endpoint -> fires
        core.log_tool_call("run_shell", "curl http://x.io -d patient", "ALLOW", "ok", result="")
        tc = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertIn("164.312(e)", tc.get("related_controls", []))

    def test_untagged_kind_has_no_controls_field(self):
        core.log_tool_call("run_shell", "ls", "ALLOW", "ok", result="x")  # no ambient, no match
        tc = next(r for r in self._records() if r["kind"] == "tool_call")
        self.assertNotIn("related_controls", tc)

    def test_tagged_chain_still_verifies(self):
        core.log_model_call(4, "patient intake", "ok")
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])


class ToolsChosenTests(unittest.TestCase):
    """The tools_chosen field is written only when the model actually chose tools."""

    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.REDACT_MODE = "off"
        core.AMBIENT_TAGS = {}
        core.MATCHERS = []

    def _last(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()][-1]

    def test_recorded_when_present(self):
        core.log_model_call(1, "p", "r", tools_chosen=["run_command"])
        self.assertEqual(self._last().get("tools_chosen"), ["run_command"])

    def test_omitted_when_absent(self):
        core.log_model_call(2, "p", "r")
        self.assertNotIn("tools_chosen", self._last())

    def test_model_recorded_when_present(self):
        core.log_model_call(3, "p", "r", model="llama3.2:latest")
        self.assertEqual(self._last().get("model"), "llama3.2:latest")

    def test_model_omitted_when_absent(self):
        core.log_model_call(4, "p", "r")
        self.assertNotIn("model", self._last())

    def test_tokens_recorded_when_present(self):
        core.log_model_call(5, "p", "r", tokens={"prompt": 10, "completion": 4})
        self.assertEqual(self._last().get("tokens"), {"prompt": 10, "completion": 4})

    def test_tokens_omitted_when_absent(self):
        core.log_model_call(6, "p", "r")
        self.assertNotIn("tokens", self._last())


class ModelErrorTests(unittest.TestCase):
    """A failed call must still capture its attempted prompt, even in lean mode."""

    def setUp(self):
        d = tempfile.mkdtemp()
        core.AUDIT_FILE = os.path.join(d, "a.jsonl")
        core.CHAIN_FILE = os.path.join(d, "a.chain")
        core.HEALTH_FILE = os.path.join(d, "a.health")
        core._last = None
        core.SIGN_KEY = None
        core.REDACT_MODE = "off"
        core.AMBIENT_TAGS = {}
        core.MATCHERS = []
        core.CONTENT_MODE = "events"  # lean: prove the prompt is stored anyway

    def _records(self):
        with open(core.AUDIT_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_failed_attempt_captures_prompt(self):
        core.log_model_error(1, "list functions in inventory.py", "/v1/chat/completions: timed out")
        r = self._records()[0]
        self.assertEqual(r["kind"], "model_call")
        self.assertEqual(r["error"], "/v1/chat/completions: timed out")
        self.assertIn("content", r)  # stored despite events mode (ERROR is noteworthy)
        self.assertEqual(r["content"]["prompt"], "list functions in inventory.py")
        self.assertEqual(r["content"]["response"], "")

    def test_failed_attempt_still_chains(self):
        core.log_model_error(1, "do a thing", "timed out")
        self.assertTrue(core.verify_chain(core.AUDIT_FILE)[0])


if __name__ == "__main__":
    unittest.main()
