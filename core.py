"""
Ballast CORE — the shared brain used by every adapter (proxy, SDK, CLI).

  DECIDE  (enforcement)  -> allow / block an action        [decide()]
  RECORD  (audit)        -> tamper-evident, edge-safe, tiered log

Design invariant: Ballast runs ANYWHERE, including constrained / headless /
offline edge devices. So: zero runtime dependencies (standard library only),
frugal with flash, no screen assumed, and no network ever required. Network
(alert webhooks) and heavy crypto are optional, opt-in extras — never core.
"""

import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

# --- where the audit trail is written -------------------------------------
# Defaults to the working directory (so a pip-installed copy never writes into
# site-packages). Pin it as a service: BALLAST_AUDIT_FILE=/var/lib/ballast/audit.jsonl
AUDIT_FILE = os.environ.get("BALLAST_AUDIT_FILE", os.path.join(os.getcwd(), "ballast_audit.jsonl"))
CHAIN_FILE = AUDIT_FILE + ".chain"

CONTENT_MODE = os.environ.get("BALLAST_LOG_CONTENT", "events")  # events | always | never
MAX_CONTENT_CHARS = int(os.environ.get("BALLAST_MAX_CONTENT", "2000"))
MAX_BYTES = int(os.environ.get("BALLAST_MAX_BYTES", str(2 * 1024 * 1024)))  # rotate at 2MB
GENESIS = "0" * 64
_NOTEWORTHY = {"BLOCK", "FLAG", "ERROR"}  # decisions worth storing full content for

# --- a session id groups one run's records (#2) ---------------------------
SESSION = os.environ.get("BALLAST_SESSION") or uuid.uuid4().hex[:8]

# --- optional HMAC sealing — edge-safe attestation, stdlib only (#6) -------
SIGN_KEY = os.environ.get("BALLAST_SIGN_KEY")  # if set, each record is sealed

# --- optional PII redaction (on by default; regex, no ML) (#5) ------------
REDACT_MODE = os.environ.get("BALLAST_REDACT", "on")  # on | off

# --- optional alert sink — default none; command/webhook are opt-in (#4) --
ALERT = os.environ.get("BALLAST_ALERT", "none")  # none | stderr | file:PATH | command:CMD | webhook:URL

# --- fail-safe posture + liveness (for unattended devices) ----------------
FAIL_MODE = os.environ.get("BALLAST_FAIL", "closed")   # closed | open — what to do when we cannot evaluate
HEALTH_FILE = os.environ.get("BALLAST_HEALTH_FILE", AUDIT_FILE + ".health")
HEARTBEAT_INTERVAL = int(os.environ.get("BALLAST_HEARTBEAT_SEC", "30"))

# --- external anchoring — publish the chain head somewhere the device does
#     NOT control, so a rewrite or truncation of the offline window becomes
#     provable after reconnect. Optional and opportunistic; the core still runs
#     fully offline without it.
ANCHOR = os.environ.get("BALLAST_ANCHOR", "none")  # none | stderr | file:PATH | command:CMD | webhook:URL

# --- optional public counter (opt-in telemetry) — sends COUNTS ONLY, never
#     content or anything identifying, so a community counter can total flags.
REPORT = os.environ.get("BALLAST_REPORT", "none")  # none | https://.../ingest
REPORT_KEY = os.environ.get("BALLAST_REPORT_KEY", "")  # optional shared secret (sent as x-ballast-key)
_counts = {"flagged": 0, "actions": 0}


# =========================================================================
#  POLICY — the DEPLOYER's to define. core is agnostic; what ships is a
#  sensible DEFAULT for shell-command agents. Override the whole thing with
#  BALLAST_POLICY_FILE (see default_policy.json for the template).
# =========================================================================
_DEFAULT_POLICY = {
    "safe_programs": [
        "ls", "pwd", "cat", "head", "tail", "wc",
        "find", "echo", "grep", "file", "stat", "date",
    ],
    "danger": [
        "rm ", "rm-", "sudo", "mkfs", "dd ", ":(){", "shutdown", "reboot",
        "chmod", "chown", "curl", "wget", "ssh", "nc ", "mv ", "kill",
        "-delete", "-exec",
        ";", "&&", "||", "|", ">", "<", "`", "$(",
    ],
    "text_danger": [
        "rm -rf", "rm -r", "sudo ", "mkfs", "dd if=", ":(){", "shutdown",
        "reboot", "chmod 777", "> /dev/", "curl ", "wget ",
        "find . -delete", "find . -exec",
    ],
    "redact": [
        r"[\w.+-]+@[\w-]+\.[\w.-]+",                            # emails
        r"\b\d{3}-\d{2}-\d{4}\b",                               # US SSN
        r"\b(?:\d[ -]?){13,16}\b",                              # card-ish numbers
        r"(?i)\b(?:bearer\s+|sk-|api[_-]?key\s*[:=]\s*)\S+",    # tokens / api keys
    ],
}


def _load_policy():
    """Load the active policy. Deployer overrides via BALLAST_POLICY_FILE (JSON
    with keys safe_programs / danger / text_danger / redact). A bad override
    fails loudly rather than silently running open."""
    data = _DEFAULT_POLICY
    path = os.environ.get("BALLAST_POLICY_FILE")
    if path:
        with open(path) as f:
            data = json.load(f)
    return (
        set(data.get("safe_programs", [])),
        list(data.get("danger", [])),
        list(data.get("text_danger", [])),
        list(data.get("redact", [])),
    )


SAFE_PROGRAMS, DANGER, TEXT_DANGER, REDACT = _load_policy()
_REDACT_RX = [re.compile(p) for p in REDACT]


def safe_verdict(reason="could not evaluate"):
    """The fail-safe fallback used whenever Ballast cannot make a decision.
    Fail-closed (the default) denies; fail-open allows. Flip with BALLAST_FAIL=open."""
    if FAIL_MODE == "open":
        return True, f"fail-open: {reason}"
    return False, f"fail-closed: {reason}"


def decide(tool_name, arg):
    """Pure decision: may this action run? Returns (allowed, reason). No logging.
    Never raises: any internal error falls back to the fail-safe posture."""
    try:
        if tool_name == "run_shell":
            low = arg.lower()
            for bad in DANGER:
                if bad in low:
                    return False, f"contains blocked pattern {bad!r}"
            try:
                program = shlex.split(arg)[0]
            except (ValueError, IndexError):
                return False, "could not parse command"
            if program not in SAFE_PROGRAMS:
                return False, f"'{program}' is not on the allowlist of safe programs"
            return True, "ok"
        return True, "read-only tool"
    except Exception as e:
        return safe_verdict(f"decision error: {e}")


def scan_text(text):
    """Flag high-signal dangerous intents in free text (uses policy.text_danger)."""
    low = (text or "").lower()
    return [p for p in TEXT_DANGER if p in low]


def redact(text):
    """Strip PII/secrets from text before it is stored (policy.redact patterns)."""
    if REDACT_MODE == "off" or not text:
        return text
    for rx in _REDACT_RX:
        text = rx.sub("[REDACTED]", text)
    return text


# =========================================================================
#  AUDIT — edge-safe, tiered, hash-chained, optionally sealed
# =========================================================================
def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


_last = None


def _last_hash():
    global _last
    if _last is None:
        try:
            with open(CHAIN_FILE) as f:
                _last = f.read().strip() or GENESIS
        except FileNotFoundError:
            _last = GENESIS
    return _last


def _set_last_hash(h):
    global _last
    _last = h
    with open(CHAIN_FILE, "w") as f:
        f.write(h)


def _store_content(decision):
    if CONTENT_MODE == "always":
        return True
    if CONTENT_MODE == "never":
        return False
    return decision in _NOTEWORTHY


def _rotate_if_needed():
    if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > MAX_BYTES:
        os.replace(AUDIT_FILE, AUDIT_FILE + ".1")


def _emit(kind, meta, content, decision=None):
    """Write one tiered, hash-chained (optionally sealed) record."""
    if REDACT_MODE != "off":
        meta = {k: (redact(v) if isinstance(v, str) else v) for k, v in meta.items()}
        content = {k: redact(v) for k, v in content.items()}
    blob = json.dumps(content, sort_keys=True)
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "session": SESSION,
        **meta,
        "chars": len(blob),
        "content_hash": _sha(blob),
    }
    if _store_content(decision):
        rec["content"] = {k: (v or "")[:MAX_CONTENT_CHARS] for k, v in content.items()}

    prev = _last_hash()
    rec["prev"] = prev
    rec["hash"] = _sha(prev + json.dumps(rec, sort_keys=True))
    if SIGN_KEY:  # seal is added AFTER hash, so it is excluded from the hash
        rec["seal"] = hmac.new(SIGN_KEY.encode(), rec["hash"].encode(), hashlib.sha256).hexdigest()

    _rotate_if_needed()
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    _set_last_hash(rec["hash"])
    heartbeat()  # activity proves liveness (throttled)


def log_model_call(step, prompt, response, chose=None):
    """CONTENT boundary: the agent<->model exchange."""
    _emit(
        "model_call",
        meta={"step": step, "chose": chose or "(n/a)"},
        content={"prompt": prompt, "response": response},
    )


def log_tool_call(tool, arg, decision, reason, result=None):
    """ACTION boundary: what the agent actually tried to DO."""
    _emit(
        "tool_call",
        meta={"tool": tool, "arg": arg, "decision": decision, "reason": reason},
        content={"arg": arg, "result": result},
        decision=decision,
    )
    _counts["actions"] += 1
    if decision == "BLOCK":
        _counts["flagged"] += 1
        _notify("block", f"{tool}: {arg}")


def log_flag(where, matched, text):
    """A dangerous intent was spotted in text (e.g. the model proposed `rm -rf`)."""
    _emit("flag", {"where": where, "matched": matched}, {"text": text}, decision="FLAG")
    _counts["flagged"] += 1
    _notify("flag", f"{matched} in {where}")


# =========================================================================
#  ALERT SINK — optional, local-first. Network/command are opt-in and must
#  NEVER break the agent, so every failure is swallowed. (#4)
# =========================================================================
def _notify(kind, summary):
    if ALERT == "none":
        return
    msg = f"[ballast:{kind}] {summary}"
    try:
        if ALERT == "stderr":
            print(msg, file=sys.stderr)
        elif ALERT.startswith("file:"):
            with open(ALERT[5:], "a") as f:
                f.write(msg + "\n")
        elif ALERT.startswith("command:"):
            subprocess.run(ALERT[8:], shell=True, input=msg.encode(), timeout=5)
        elif ALERT.startswith("webhook:"):  # opt-in network
            req = urllib.request.Request(
                ALERT[8:],
                data=json.dumps({"event": kind, "detail": summary, "session": SESSION}).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # alerting is best-effort; it must never take the agent down


# =========================================================================
#  LIVE COUNTER — opt-in telemetry. Sends COUNTS ONLY (flagged, actions), never
#  content or anything identifying, so a public counter can total the dangerous
#  actions caught across all opted-in agents. Off by default.
# =========================================================================
def _pending_report():
    if _counts["flagged"] == 0 and _counts["actions"] == 0:
        return None
    return {
        "flagged": _counts["flagged"],
        "actions": _counts["actions"],
        "reported_at": datetime.now(timezone.utc).isoformat(),
    }


def report():
    """Opt-in: POST the running tally to BALLAST_REPORT so a community counter can
    total it. Counts only. Resets on success, keeps the tally on failure so nothing
    is lost. Returns True if sent."""
    if REPORT == "none":
        return False
    payload = _pending_report()
    if payload is None:
        return False
    try:
        headers = {"Content-Type": "application/json"}
        if REPORT_KEY:
            headers["x-ballast-key"] = REPORT_KEY
        req = urllib.request.Request(REPORT, data=json.dumps(payload).encode(), headers=headers)
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        return False  # keep the tally and retry next time
    _counts["flagged"] = 0
    _counts["actions"] = 0
    return True


# =========================================================================
#  LIVENESS / WATCHDOG — prove Ballast is alive so a supervisor can restart
#  it if it wedges. Edge-safe: tiny file, throttled writes, no network.
# =========================================================================
_last_beat = 0.0


def heartbeat(status="ok", force=False):
    """Write a small liveness record, at most once per HEARTBEAT_INTERVAL."""
    global _last_beat
    now = time.time()
    if not force and (now - _last_beat) < HEARTBEAT_INTERVAL:
        return
    _last_beat = now
    try:
        with open(HEALTH_FILE, "w") as f:
            json.dump({"epoch": now, "session": SESSION, "status": status, "pid": os.getpid()}, f)
    except Exception:
        pass  # liveness writes must never break the agent


def health(max_age=None):
    """Report whether Ballast is alive, based on the age of the last heartbeat."""
    limit = max_age if max_age is not None else HEARTBEAT_INTERVAL * 3
    try:
        with open(HEALTH_FILE) as f:
            h = json.load(f)
    except (FileNotFoundError, ValueError):
        return {"alive": False, "reason": "no heartbeat found"}
    age = time.time() - h.get("epoch", 0)
    return {"alive": age <= limit, "age_seconds": round(age, 1),
            "status": h.get("status"), "pid": h.get("pid"), "session": h.get("session")}


def log_system(event, detail=""):
    """Record a Ballast operational event (startup, degraded, upstream_error...)."""
    _emit("system", {"event": event, "detail": detail}, {"detail": detail})


# =========================================================================
#  VERIFY / ATTEST
# =========================================================================
def verify_chain(path=None):
    path = path or AUDIT_FILE
    prev = GENESIS
    n = 0
    try:
        f = open(path)
    except FileNotFoundError:
        return True, "no audit file yet"
    with f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            stored = rec.pop("hash", None)
            seal = rec.pop("seal", None)
            if rec.get("prev") != prev:
                return False, f"line {i}: broken link (a record was deleted or reordered)"
            if _sha(prev + json.dumps(rec, sort_keys=True)) != stored:
                return False, f"line {i}: hash mismatch (this record was edited)"
            if SIGN_KEY and seal is not None:
                expect = hmac.new(SIGN_KEY.encode(), stored.encode(), hashlib.sha256).hexdigest()
                if expect != seal:
                    return False, f"line {i}: seal mismatch (not signed by this key)"
            prev = stored
            n += 1
    return True, f"OK, {n} records, chain intact"


def attest(path=None):
    """A compact, portable proof of the trail's current state: the chain head
    hash + record count, HMAC-sealed if BALLAST_SIGN_KEY is set."""
    path = path or AUDIT_FILE
    prev = GENESIS
    n = 0
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    prev = json.loads(line).get("hash", prev)
                    n += 1
    except FileNotFoundError:
        pass
    out = {"session": SESSION, "records": n, "root": prev, "sealed": bool(SIGN_KEY)}
    if SIGN_KEY:
        out["seal"] = hmac.new(SIGN_KEY.encode(), (prev + str(n)).encode(), hashlib.sha256).hexdigest()
    return out


# =========================================================================
#  EXTERNAL ANCHORING — root trust off the device so offline-window tampering
#  (rewrite or truncation) is provable after reconnect. Optional, pluggable.
# =========================================================================
def _publish_anchor(cp):
    """Send a checkpoint to the external anchor sink. Returns True on success."""
    if ANCHOR == "none":
        return False
    line = json.dumps(cp)
    try:
        if ANCHOR == "stderr":
            print("[ballast:anchor] " + line, file=sys.stderr)
        elif ANCHOR.startswith("file:"):
            with open(ANCHOR[5:], "a") as f:
                f.write(line + "\n")
        elif ANCHOR.startswith("command:"):
            subprocess.run(ANCHOR[8:], shell=True, input=line.encode(), timeout=10)
        elif ANCHOR.startswith("webhook:"):
            req = urllib.request.Request(
                ANCHOR[8:], data=line.encode(), headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        else:
            return False
        return True
    except Exception:
        return False  # anchoring is best-effort; the caller reports success


def anchor():
    """Publish the current chain head + record count to the external anchor sink.
    Returns (checkpoint, published). verify_against() later proves the local trail
    still reproduces the checkpoint, which is what catches rewrite and truncation."""
    cp = attest()
    cp["ts"] = datetime.now(timezone.utc).isoformat()
    return cp, _publish_anchor(cp)


def verify_against(checkpoints, path=None):
    """Prove the local chain still reproduces externally-held checkpoints. Catches
    tampering that stays internally consistent (a full rewrite) and truncation of
    recent records, neither of which verify_chain() alone can detect.
    `checkpoints` is a list of {"records": n, "root": hash}."""
    path = path or AUDIT_FILE
    ok, msg = verify_chain(path)
    if not ok:
        return False, msg
    expected = {c["records"]: c["root"] for c in checkpoints if "records" in c and "root" in c}
    prev, n = GENESIS, 0
    try:
        f = open(path)
    except FileNotFoundError:
        f = None
    if f:
        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                prev = json.loads(line).get("hash", prev)
                n += 1
                if n in expected and prev != expected[n]:
                    return False, f"anchor mismatch at record {n}: the local trail no longer matches its external anchor (it was rewritten)"
    for c_count in sorted(expected):
        if c_count > n:
            return False, f"missing record {c_count}: an external anchor exists for it but the local trail is shorter (records were truncated)"
    return True, f"OK, chain matches {len(expected)} external anchor(s)"


def _verify_cli():
    ok, msg = verify_chain()
    print(("PASS: " if ok else "FAIL: ") + msg)
    raise SystemExit(0 if ok else 1)


def main():
    if "--verify" in sys.argv:
        _verify_cli()
    print("Ballast core. Use the `ballast` CLI (log / summary / verify / attest), or run proxy.py.")


if __name__ == "__main__":
    main()
