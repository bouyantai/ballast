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

## Deployment

Ballast is not a cloud service — it's a small process you run **next to your
agent** (same machine or same local network). Deploying it is three steps: run
the proxy, point your agent at it, keep it alive.

### Install

```bash
# from source
git clone https://github.com/bouyantai/ballast && cd ballast

# ...or install the CLI (still zero runtime dependencies)
pip install git+https://github.com/bouyantai/ballast
```

### Run it

**Quick (dev / trying it out):**
```bash
python3 proxy.py          # or, if pip-installed:  ballast-proxy
```

**As a service on a Linux edge device (systemd):**
```ini
# /etc/systemd/system/ballast.service
[Unit]
Description=Ballast agent audit proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/ballast-proxy          # wherever pip installed it (`which ballast-proxy`)
Environment=BALLAST_UPSTREAM=http://localhost:11434
Environment=BALLAST_PROXY_PORT=8100
Environment=BALLAST_AUDIT_FILE=/var/lib/ballast/audit.jsonl
Restart=always
User=ballast

[Install]
WantedBy=multi-user.target
```
```bash
sudo mkdir -p /var/lib/ballast
sudo systemctl enable --now ballast
```

**macOS / quick background:** `nohup ballast-proxy &`, a `tmux` pane, or a launchd plist.

### Point your agent at it

Change only the model base URL — nothing else about the agent changes:

| Your agent talks to… | …point it at Ballast instead |
|---|---|
| Ollama (`http://localhost:11434`) | `http://localhost:8100` |
| any OpenAI-compatible endpoint | `http://<ballast-host>:8100` |

For the bundled demo agent: `OLLAMA_HOST=localhost:8100 python3 agent.py "..."`

### Before you expose it — read this
- **No authentication yet.** Bind Ballast to `localhost` or a trusted private
  network. Do **not** put the port on the public internet.
- **Single process.** Ideal for one agent on a device; not sized for high concurrency.
- **Pin `BALLAST_AUDIT_FILE`** to an absolute path when running as a service, so the
  trail lands somewhere stable rather than in the service's working directory.

## Configuration (env vars)
- `BALLAST_UPSTREAM` — the real model endpoint to forward to (default `http://localhost:11434`).
- `BALLAST_PROXY_PORT` — port the proxy listens on (default `8100`).
- `BALLAST_AUDIT_FILE` — where the audit trail is written (default `./ballast_audit.jsonl`).
- `BALLAST_LOG_CONTENT=events|always|never` — how much full content to store (default `events` = lean).
- `BALLAST_MAX_BYTES` — rotate the log at this size (default 2 MB).

## No dependencies
Pure Python standard library. Nothing to `pip install`. Runs on constrained /
offline / air-gapped machines where a heavier stack won't fit.

## License
MIT — see [LICENSE](LICENSE).

