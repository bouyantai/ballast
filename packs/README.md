# Policy packs

Optional starter policy packs. Point `BALLAST_POLICY_FILE` at one.

**These are convenience indexes, not compliance claims.** Ballast captures a
tamper-evident record; an auditor evaluates it against whatever framework they
bring. A tag points to records relevant to a control for review. It does not
assert that the control is satisfied. Revise a pack for your own context.

## How a pack tags records

A pack's `controls` block maps records to framework control ids two ways:

- **Ambient control** — no `match` block. Tags *every* record of the listed
  `record_kinds`. Use it only where the control genuinely covers all activity
  (e.g. HIPAA 164.312(b) "record and examine activity"). It's an honest
  blanket label, not per-record evidence.
- **Matcher control** — has a `match` block (`text` substrings and/or `regex`).
  Tags a record *only when its content matches*, so the tag is real evidence.
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

## Available

- `hipaa_policy.json` — HIPAA Security Rule (45 CFR Part 164). Ambient audit-
  controls tag (164.312(b)) plus matchers that flag + tag PHI / minimum-necessary
  (164.502(b), based on the Safe Harbor identifiers) and security-incident
  language (164.308(a)(6)(ii)). Adds MRN redaction. Note: an audit trail of a
  system handling ePHI is itself ePHI and must be protected accordingly.
- `nist_ai_rmf_policy.json` — NIST AI RMF 1.0 (7 subcategories). **Ambient-only
  for now** (label-by-kind); matcher conversion pending.
- `eu_ai_act_policy.json` — EU AI Act (Regulation (EU) 2024/1689, 6 articles).
  **Ambient-only for now** (label-by-kind); matcher conversion pending.

## Use

```bash
BALLAST_POLICY_FILE=packs/hipaa_policy.json python3 proxy.py
ballast log --control '164.502(b)'    # records where PHI context was detected
```
