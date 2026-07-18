# Policy packs

Optional starter policy packs. Point `BALLAST_POLICY_FILE` at one. A pack can carry
a `controls` block that maps record kinds to framework control ids, so each record
is tagged with the controls it is relevant to (see "Framework control tagging" in
the main README).

**These are convenience indexes, not compliance claims.** Ballast captures a
tamper-evident record; an auditor evaluates it against whatever framework they
bring. A tag points to records relevant to a control for review. It does not
assert that the control is satisfied. Revise a pack for your own context.

## Available

- `nist_ai_rmf_policy.json` — NIST AI RMF 1.0. A lean relevance index for the
  Measure and Manage controls a runtime record most relates to (7 subcategories).
- `hipaa_policy.json` — HIPAA Security Rule (45 CFR Part 164). Audit controls,
  activity review, integrity, incident procedures, and minimum-necessary
  redaction (5 provisions). Note: an audit trail of a system handling ePHI is
  itself ePHI and must be protected accordingly.
- `eu_ai_act_policy.json` — EU AI Act (Regulation (EU) 2024/1689). Record-keeping,
  logging, deployer monitoring, post-market monitoring, incident reporting, and
  human oversight for high-risk AI systems (6 articles).

## Use

```bash
BALLAST_POLICY_FILE=packs/nist_ai_rmf_policy.json python3 proxy.py
ballast log --control 'MEASURE 2.8'    # records relevant to this control
```
