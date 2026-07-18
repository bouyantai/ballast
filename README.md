# Ballast · by Bouyant AI

> **Keeps your AI agents from going overboard.**

A local-first safety + audit layer for autonomous AI agents. No cloud, no
account. It records what an agent is asked and what it decides, flags dangerous
intents, and keeps a **tamper-evident, edge-safe** log.

## A quick look

An agent that has never heard of Ballast tries to wipe a folder. Ballast, running
as a proxy in front of the model, catches the intent — fully offline:

```text
$ python3 agent.py "delete every file here"
[step 1] brain says -> ACTION: run_shell | rm -rf *

[ballast] ⚠  FLAGGED dangerous intent: ['rm -rf', 'rm -r']

$ ballast verify
PASS: OK — 12 records, chain intact
```

## Architecture: one core, thin adapters

```
                 ┌──────────── core.py ────────────┐
                 │  decide()   — allow / block      │   built once
                 │  audit      — tiered, hash-chain │
                 │  scan_text  — flag danger        │
                 └───────┬──────────────────┬───────┘
              ┌──────────▼─────┐    ┌────────▼──────────┐
              │ proxy.py       │    │ (SDK adapter —    │
              │ Option 1       │    │  planned)         │
              │ zero-touch     │    │                   │
              └────────────────┘    └───────────────────┘

  cli.py — read-only tools over the trail: log · summary · verify · attest
```

- **`core.py`** — the shared brain: policy, edge-safe tamper-evident audit, content scanning, `--verify`.
- **`proxy.py`** — **Option 1 (zero-touch):** sits in front of the model; audits every
  prompt/response and flags dangerous intents. The agent needs no changes.
- **`agent.py`** — a small demonstration agent used to exercise the proxy. It
  does **not** import Ballast, showing that no changes to the agent are required.

## Quick start (Option 1 — the proxy)

Three terminals:

```bash
# 1. the model
ollama run llama3.2

# 2. Ballast, in front of the model
cd ~/Development/ballast
python3 proxy.py                       # listens on :8100 -> Ollama :11434

# 3. an unmodified agent, pointed at Ballast by changing one environment variable
OLLAMA_HOST=localhost:8100 python3 agent.py "count the lines in agent.py"
OLLAMA_HOST=localhost:8100 python3 agent.py "delete every file here"   # the dangerous intent is flagged
```

Then inspect and verify the trail:

```bash
cat ballast_audit.jsonl          # every exchange; dangerous intents flagged
python3 core.py --verify         # confirm the hash-chain is intact
```

## Demo

An agent with no awareness of Ballast attempts to delete files. The proxy
detects and flags the intent, fully offline:

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
- **Can't:** stop a tool from actually executing — it never observes execution.
  Blocking a tool at execution time is planned for a future SDK adapter.

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

**Quick start (any platform):**
```bash
python3 proxy.py          # or, if pip-installed:  ballast-proxy
```

**As a service — Linux (systemd), recommended for edge devices:**
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

**As a service — other platforms:**
- **macOS:** run under `launchd` (a LaunchAgent or LaunchDaemon plist).
- **Windows:** register as a service (e.g. NSSM) or a Scheduled Task.

**Any platform, minimal:** `nohup ballast-proxy &`, or a `tmux` / `screen` session.

### Point your agent at it

Change only the model base URL — nothing else about the agent changes:

| Your agent talks to… | …point it at Ballast instead |
|---|---|
| Ollama (`http://localhost:11434`) | `http://localhost:8100` |
| any OpenAI-compatible endpoint | `http://<ballast-host>:8100` |

For the bundled demo agent: `OLLAMA_HOST=localhost:8100 python3 agent.py "..."`

### Security considerations
- **No authentication yet.** Bind Ballast to `localhost` or a trusted private
  network. Do **not** put the port on the public internet.
- **Single process.** Ideal for one agent on a device; not sized for high concurrency.
- **Pin `BALLAST_AUDIT_FILE`** to an absolute path when running as a service, so the
  trail lands somewhere stable rather than in the service's working directory.

## Reading the trail (CLI)

Read-only, streaming, stdout-only — works over SSH on a headless box.
(From a clone, use `python3 cli.py <cmd>`; after `pip install`, just `ballast`.)

```bash
ballast log                # timeline: asked -> decided -> did
ballast log --flagged      # only the dangerous-intent flags
ballast log --session ID   # one run
ballast summary            # per-run rollup
ballast verify             # is the hash-chain intact?
ballast attest             # a portable, optionally-sealed proof of state
```

## Privacy & trust

- **Redaction is on by default.** Emails, SSNs, card numbers, and API tokens are
  scrubbed from stored content before it touches disk (regex, no ML, edge-safe).
  Disable with `BALLAST_REDACT=off`; customise via the policy's `redact` list.
- **Optional sealing.** Set `BALLAST_SIGN_KEY` and every record is HMAC-sealed;
  `ballast verify` then also proves it was signed by *your* key, and `ballast attest`
  emits a portable proof of the trail's state. Pure standard library — no crypto deps.

## Fail-safe & health (for unattended devices)

When no one is watching, Ballast defaults to safe behavior:

- **Fail-closed by default.** If Ballast cannot evaluate an action (bad policy or an
  internal error), it denies rather than allows. Flip with `BALLAST_FAIL=open` when
  availability matters more than safety for your deployment.
- **Upstream timeout.** A hung or unreachable model cannot wedge the device. The
  proxy times out (`BALLAST_UPSTREAM_TIMEOUT`, default 30s), records it, and returns
  a clear error.
- **Liveness heartbeat.** Ballast writes a small heartbeat so a supervisor can tell
  whether it has wedged. Check it with `ballast health` (exit 0 = alive, 1 = down)
  and wire that into a systemd or cron healthcheck.

```bash
ballast health          # OK - alive, last heartbeat 4.2s ago
```

## Proving it after the fact (external anchoring)

A local hash chain can be recomputed by anyone who fully controls the device, and
records can be truncated to hide recent activity. Both attacks leave the chain
internally consistent, so a purely local check passes and cannot catch them.

External anchoring closes that gap. Ballast publishes the current chain head and
record count to somewhere the device does not control (a server, a write-once
store, a git repo, another machine). Later, `ballast verify --anchors` proves the
local trail still reproduces those anchors. A rewrite or a truncation of the
offline window will not match, and you can prove it.

```bash
BALLAST_ANCHOR=webhook:https://anchor.example/ingest ballast anchor   # publish a checkpoint
ballast verify --anchors anchors.jsonl                                # prove the trail matches
```

Anchoring is optional and opportunistic (run it on a timer or when the device
reconnects), and the target is yours to choose, so the offline, no-cloud core is
unchanged. Honest limits: anchoring does not prevent tampering, it makes it
provable after the fact, and only if an honest anchor was recorded before
compromise and the target stays outside the attacker's reach. For the strongest
guarantee, pair it with a hardware-backed key.

## Live counter (opt-in, counts only)

Ballast can send a running tally to a public counter so the community can see how
many dangerous actions have been caught in the field. It is **off by default and
opt in**, and it sends **counts only**: never a prompt, never content, never
anything identifying, just two numbers and a timestamp. Enable it by pointing it
at an endpoint:

```bash
BALLAST_REPORT=https://bouyant.ai/ingest ballast-proxy
```

The tally is kept locally and pushed opportunistically when online, so a
disconnected device loses nothing and reveals nothing until you opt in.

## Configuration (env vars)
- `BALLAST_UPSTREAM` — the real model endpoint to forward to (default `http://localhost:11434`).
- `BALLAST_PROXY_PORT` — port the proxy listens on (default `8100`).
- `BALLAST_AUDIT_FILE` — where the audit trail is written (default `./ballast_audit.jsonl`).
- `BALLAST_LOG_CONTENT=events|always|never` — how much full content to store (default `events` = lean).
- `BALLAST_MAX_BYTES` — rotate the log at this size (default 2 MB).
- `BALLAST_POLICY_FILE` — path to a JSON policy that overrides the built-in default (see **Policy** below).
- `BALLAST_REDACT=on|off` — scrub PII/secrets from stored content (default `on`).
- `BALLAST_SIGN_KEY` — if set, HMAC-seal every record (tamper-evidence + authenticity).
- `BALLAST_ALERT` — where flag/block alerts go: `none` (default), `stderr`, `file:PATH`, `command:CMD`, `webhook:URL`.
- `BALLAST_SESSION` — group records under a fixed run id (default: random per process).
- `BALLAST_FAIL=closed|open` — behavior when Ballast cannot evaluate an action (default `closed`).
- `BALLAST_UPSTREAM_TIMEOUT` — seconds before a hung model call is aborted (default `30`).
- `BALLAST_HEARTBEAT_SEC` — liveness heartbeat interval (default `30`).
- `BALLAST_ANCHOR` — where to publish chain-head checkpoints: `none` (default), `stderr`, `file:PATH`, `command:CMD`, `webhook:URL`.
- `BALLAST_REPORT` — opt-in public-counter endpoint; sends counts only (default `none`).

## Policy (what counts as dangerous)

Ballast core is **agnostic** — it does not know what any given agent's tools
mean. What ships is a sensible **default policy for shell-command agents**
(`safe_programs` / `danger` / `text_danger`) — a starting point, not universal
truth. Define your own for your agent by copying `default_policy.json`, editing
it, and pointing `BALLAST_POLICY_FILE` at it:

```bash
BALLAST_POLICY_FILE=./my_policy.json python3 proxy.py
```

## No dependencies
Pure Python standard library. Nothing to `pip install`. Runs on constrained /
offline / air-gapped machines where a heavier stack won't fit.

## License
MIT — see [LICENSE](LICENSE).

