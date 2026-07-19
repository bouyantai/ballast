# Policy packs

Optional starter policy packs. Point `BALLAST_POLICY_FILE` at one.

**These are convenience indexes, not compliance claims.** Ballast captures a
tamper-evident record; an auditor evaluates it against whatever framework they
bring. A tag points to records relevant to a control for review. It does not
assert that the control is satisfied. Revise a pack for your own context.

## How a pack tags records

A record is tagged with a control **only when its content earns it**. Tagging is
done by **matcher** controls, which carry a `match` block:

- **OR**: top-level `text` substrings and/or `regex`; fires if any hit.
- **AND**: an `all` list of groups; fires only when *every* group hits (e.g. PHI
  context **and** a plaintext endpoint → possible unencrypted transmission).

Add `"on_match": "flag"` to also raise the record's visibility (it's counted and
alerted, and its content is stored). Matchers run on the raw content **before**
redaction, so detection isn't blinded by masking.

The engine also supports **ambient** controls (no `match` block) that stamp *every*
record of a kind, but the shipped packs deliberately **avoid** them: a blanket
label on every record is noise, not evidence, and it inflates any evidence count by
tagging records that never earned it. A framework's blanket, whole-trail provisions
(audit controls, activity review, integrity, record-keeping) are documented in the
pack's `note` instead — they describe the mechanism, not any single record.

```json
{
  "extends_default": true,          // keep Ballast's built-in danger detection; add to it
  "redact": ["(?i)\\bmrn[\\s:#-]*\\d{3,}"],   // framework-specific redaction, merged with defaults
  "controls": [
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
`related_controls` on a record is what a matcher *stamped* on it because the content
earned it.)

## Available

- `hipaa_policy.json`: HIPAA (45 CFR Part 164). Matchers that flag + tag
  PHI/minimum-necessary (164.502(b), Safe Harbor identifiers), unencrypted
  transmission (164.312(e), PHI **and** a plaintext endpoint), and security-incident
  language (164.308(a)(6)(ii)). Adds MRN redaction. The whole-trail provisions
  (audit controls 164.312(b), activity review, integrity via `ballast verify`) are
  documented in the note, not stamped per-record. Deliberately does *not* cover the
  ~80% of HIPAA that is administrative/physical/organizational. Note: an audit trail
  of a system handling ePHI is itself ePHI and must be protected accordingly.
- `eu_ai_act_policy.json`: EU AI Act (Regulation (EU) 2024/1689), high-risk systems.
  Matchers for human-oversight points (Art 14) and serious-incident language (Art 73).
  The record-keeping / monitoring / retention obligations (Art 12, 19, 26, 72) are
  whole-trail and documented in the note. Not conformity assessment.
- `nist_ai_rmf_policy.json`: NIST AI RMF 1.0, Measure + Manage only (not Govern or
  Map). Matchers for safety (2.6), security & resilience incl. prompt-injection (2.7),
  privacy/PII (2.10), risk/anomaly (3.1), and incident/error (MANAGE 4.3). Transparency
  (MEASURE 2.8) and post-deployment monitoring (MANAGE 4.1) are whole-trail, in the note.

## Use

```bash
BALLAST_POLICY_FILE=packs/hipaa_policy.json python3 proxy.py
ballast log --control '164.502(b)'    # records where PHI context was detected
```
