# Policy packs

Optional starter policy packs. Point `BALLAST_POLICY_FILE` at one.

**These are convenience indexes, not compliance claims.** Ballast captures a
tamper-evident record; an auditor evaluates it against whatever framework they
bring. A tag points to records relevant to a control for review. It does not
assert that the control is satisfied. Revise a pack for your own context.

## How a pack tags records

A pack's `controls` block maps records to framework control ids two ways:

- **Ambient control**: no `match` block. Tags *every* record of the listed
  `record_kinds`. Use it only where the control genuinely covers all activity
  (e.g. HIPAA 164.312(b) "record and examine activity"). It's an honest
  blanket label, not per-record evidence.
- **Matcher control**: has a `match` block. Tags a record *only when its content
  matches*, so the tag is real evidence. Two forms:
  - **OR**: top-level `text` substrings and/or `regex`; fires if any hit.
  - **AND**: an `all` list of groups; fires only when *every* group hits (e.g.
    PHI context **and** a plaintext endpoint → possible unencrypted transmission).

  Add `"on_match": "flag"` to also raise the record's visibility (it's counted
  and alerted like any flag, and its content is stored). Matchers run on the raw
  content **before** redaction, so detection isn't blinded by masking.

```json
{
  "extends_default": true,          // keep Ballast's built-in danger detection; add to it
  "redact": ["(?i)\\bmrn[\\s:#-]*\\d{3,}"],   // framework-specific redaction, merged with defaults
  "controls": [
    { "id": "164.312(b)", "ambient": true, "record_kinds": ["model_call","tool_call"] },
    { "id": "164.502(b)", "on_match": "flag", "record_kinds": ["model_call","tool_call"],
      "match": { "text": ["patient","diagnos"], "regex": ["(?i)\\bmrn[\\s:#-]*\\d{3,}"] } }
  ]
}
```

Set `"extends_default": true` so the pack **adds** to the built-in detection
instead of replacing it. Without it, a pack's `safe_programs`/`danger`/
`text_danger` (empty in framework packs) would turn off Ballast's normal
flagging. `title`, `summary`, and `relevance` are human documentation; the
engine reads only `id`, `record_kinds`, `ambient`, `match`, and `on_match`.

A tagged record carries a `related_controls` field listing the control ids it
relates to. It is a relevance cross-reference, not an assertion that the control is
satisfied. (The pack's `controls` block, above, is where controls are *defined*;
`related_controls` on a record is what a matcher or ambient rule *stamped* on it.)

## Available

- `hipaa_policy.json`: HIPAA (45 CFR Part 164). Six runtime-observable provisions:
  ambient tags for audit controls (164.312(b)), activity review (164.308(a)(1)(ii)(D)),
  and integrity (164.312(c), evidence is `ballast verify`); matchers that flag + tag
  PHI/minimum-necessary (164.502(b), Safe Harbor identifiers), unencrypted transmission
  (164.312(e), PHI **and** a plaintext endpoint), and security-incident language
  (164.308(a)(6)(ii)). Adds MRN redaction. Deliberately does *not* cover the ~80% of
  HIPAA that is administrative/physical/organizational process Ballast can't observe.
  Note: an audit trail of a system handling ePHI is itself ePHI and must be protected
  accordingly.
- `eu_ai_act_policy.json`: EU AI Act (Regulation (EU) 2024/1689), high-risk
  systems. Ambient record-keeping (Art 12) and deployer monitoring/retention
  (Art 26); matchers that flag + tag human-oversight points (Art 14) and
  serious-incident language (Art 73). The same trail also evidences provider
  log-keeping (Art 19) and post-market monitoring (Art 72). Not conformity
  assessment.
- `nist_ai_rmf_policy.json`: NIST AI RMF 1.0, Measure + Manage only (not Govern
  or Map). Ambient transparency (MEASURE 2.8) and post-deployment monitoring
  (MANAGE 4.1); matchers that flag + tag safety (2.6), security & resilience incl.
  prompt-injection (2.7), privacy/PII (2.10), risk/anomaly (3.1), and incident/
  error (MANAGE 4.3).

## Use

```bash
BALLAST_POLICY_FILE=packs/hipaa_policy.json python3 proxy.py
ballast log --control '164.502(b)'    # records where PHI context was detected
```
