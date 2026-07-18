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

## Use

```bash
BALLAST_POLICY_FILE=packs/nist_ai_rmf_policy.json python3 proxy.py
ballast log --control 'MEASURE 2.8'    # records relevant to this control
```
