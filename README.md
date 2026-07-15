# Ballast · by Bouyant AI

> Buoyancy keeps a hull afloat; **ballast keeps it upright so it doesn't capsize.**

A lightweight, **local-first** safety + audit layer for autonomous AI agents.
No cloud, no account. It records what an agent is asked and what it decides,
flags dangerous intents, and keeps a **tamper-evident, edge-safe** log.

## Architecture: one core, thin adapters

```
                 ┌──────────── core.py ────────────┐
                 │  decide()   — allow / block      │   built once
                 │  audit      — tiered, hash-chain │
                 │  scan_text  — flag danger        │
                 └───────┬──────────────────┬───────┘
              ┌──────────▼─────┐    ┌────────▼──────────┐
              │ proxy.py       │    │ (SDK adapter —    │
              │ Option 1       │    │  later, when      │
              │ zero-touch     │    │  someone asks)    │
              └────────────────┘    └───────────────────┘
```

- **`core.py`** — the shared brain: policy, edge-safe tamper-evident audit, content scanning, `--verify`.
- **`proxy.py`** — **Option 1 (zero-touch):** sits in front of the model; audits every
  prompt/response and flags dangerous intents. The agent needs no changes.
- **`agent.py`** — a throwaway demo agent (a stand-in for "someone else's agent").
  It does **not** import Ballast — that's how we prove zero-touch.

## Try it (Option 1 — the proxy)

Three terminals:

```bash
# 1. the model
ollama run llama3.2

# 2. Ballast, in front of the model
cd ~/Development/ballast
python3 proxy.py                       # listens on :8100 -> Ollama :11434

# 3. an UNMODIFIED agent, pointed at Ballast by changing ONE env var
OLLAMA_HOST=localhost:8100 python3 agent.py "count the lines in agent.py"
OLLAMA_HOST=localhost:8100 python3 agent.py "delete every file here"   # watch it get FLAGGED
```

Then inspect and verify the trail:

```bash
cat ballast_audit.jsonl          # every exchange; dangerous intents flagged
python3 core.py --verify         # confirm the hash-chain is intact
```

## Demo

An agent that has **no idea Ballast exists** tries to delete everything — Ballast
catches it at the proxy, fully offline:

```text
# terminal running the proxy
[ballast] step 7  logged (clean)
[ballast] step 8  ⚠  FLAGGED dangerous intent: ['rm -rf', 'rm -r']

# the audit trail (tamper-evident, hash-chained)
{"kind": "flag", "matched": ["rm -rf", "rm -r"], "content": {"text": "ACTION: run_shell | rm -rf *"}, ...}

$ python3 core.py --verify
PASS: OK — 12 records, chain intact
```

### What the proxy can and can't do
- **Can:** log every prompt/response with near-zero weight; flag a dangerous
  command the model proposes; run fully offline.
- **Can't:** stop a tool from actually executing — it never sees that. Real
  action-blocking is the future **SDK adapter's** job.

## Tuning (env vars)
- `BALLAST_LOG_CONTENT=events|always|never` — how much full content to store (default `events` = lean).
- `BALLAST_MAX_BYTES` — rotate the log at this size (default 2 MB).
- `BALLAST_PROXY_PORT`, `BALLAST_UPSTREAM` — proxy listen port / upstream model.

## No dependencies
Pure Python standard library. Nothing to `pip install`. Runs on constrained /
offline / air-gapped machines where a heavier stack won't fit.

## License
MIT — see [LICENSE](LICENSE).

