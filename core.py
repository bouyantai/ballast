"""
Ballast CORE — the shared brain used by every adapter (proxy, SDK, ...).

Two jobs, kept separate on purpose:

  DECIDE   (enforcement)  -> allow / block an action         [decide()]
  RECORD   (audit)        -> log what happened, tamper-evident and EDGE-SAFE

Audit is TIERED so it stays light on constrained devices:
  * metadata is ALWAYS written (timestamp, kind, sizes, a hash) — tiny
  * full content is stored ONLY when it matters (blocks, flags, errors),
    or always if you set BALLAST_LOG_CONTENT=always

Every record is hash-chained to the previous one, so tampering is detectable
with `python3 core.py --verify`.
"""

import hashlib
import json
import os
import shlex
from datetime import datetime, timezone

# Where the audit trail is written. Defaults to the current working directory
# (so a pip-installed copy never writes into site-packages). Pin it explicitly
# when running as a service, e.g. BALLAST_AUDIT_FILE=/var/lib/ballast/audit.jsonl
AUDIT_FILE = os.environ.get("BALLAST_AUDIT_FILE", os.path.join(os.getcwd(), "ballast_audit.jsonl"))
CHAIN_FILE = AUDIT_FILE + ".chain"

CONTENT_MODE = os.environ.get("BALLAST_LOG_CONTENT", "events")  # events | always | never
MAX_CONTENT_CHARS = int(os.environ.get("BALLAST_MAX_CONTENT", "2000"))
MAX_BYTES = int(os.environ.get("BALLAST_MAX_BYTES", str(2 * 1024 * 1024)))  # rotate at 2MB
GENESIS = "0" * 64
_NOTEWORTHY = {"BLOCK", "FLAG", "ERROR"}  # decisions that justify storing full content


# =========================================================================
#  ENFORCEMENT — the DECIDE half (used by the SDK adapter; a deployer's
#  policy would plug in here)
# =========================================================================
SAFE_PROGRAMS = {
    "ls", "pwd", "cat", "head", "tail", "wc",
    "find", "echo", "grep", "file", "stat", "date",
}
DANGER = [
    "rm ", "rm-", "sudo", "mkfs", "dd ", ":(){", "shutdown", "reboot",
    "chmod", "chown", "curl", "wget", "ssh", "nc ", "mv ", "kill",
    "-delete", "-exec",  # e.g. `find . -delete` — allowlisting the program isn't enough
    ";", "&&", "||", "|", ">", "<", "`", "$(",
]


def decide(tool_name, arg):
    """Pure decision: may this action run? Returns (allowed, reason). No logging."""
    if tool_name == "run_shell":
        lowered = arg.lower()
        for bad in DANGER:
            if bad in lowered:
                return False, f"contains blocked pattern {bad!r}"
        try:
            program = shlex.split(arg)[0]
        except (ValueError, IndexError):
            return False, "could not parse command"
        if program not in SAFE_PROGRAMS:
            return False, f"'{program}' is not on the allowlist of safe programs"
        return True, "ok"
    return True, "read-only tool"


# =========================================================================
#  CONTENT SCANNING — high-signal danger patterns for scanning free text
#  (e.g. a dangerous command the MODEL proposes). Deliberately narrower than
#  DANGER above, so ordinary punctuation in prose doesn't trip it.
# =========================================================================
TEXT_DANGER = [
    "rm -rf", "rm -r", "sudo ", "mkfs", "dd if=", ":(){", "shutdown", "reboot",
    "chmod 777", "> /dev/", "curl ", "wget ", "find . -delete", "find . -exec",
]


def scan_text(text):
    """Return the list of dangerous command intents found in free text."""
    low = (text or "").lower()
    return [p for p in TEXT_DANGER if p in low]


# =========================================================================
#  AUDIT — edge-safe, tiered, hash-chained
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
    """Write one tiered, hash-chained record."""
    blob = json.dumps(content, sort_keys=True)
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        **meta,
        "chars": len(blob),
        "content_hash": _sha(blob),
    }
    if _store_content(decision):
        rec["content"] = {k: (v or "")[:MAX_CONTENT_CHARS] for k, v in content.items()}

    prev = _last_hash()
    rec["prev"] = prev
    rec["hash"] = _sha(prev + json.dumps(rec, sort_keys=True))

    _rotate_if_needed()
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    _set_last_hash(rec["hash"])


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


def log_flag(where, matched, text):
    """A dangerous intent was spotted in text (e.g. the model proposed `rm -rf`)."""
    _emit(
        "flag",
        meta={"where": where, "matched": matched},
        content={"text": text},
        decision="FLAG",
    )


# =========================================================================
#  VERIFY — prove the trail wasn't tampered with
# =========================================================================
def verify_chain(path=AUDIT_FILE):
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
            if rec.get("prev") != prev:
                return False, f"line {i}: broken link (a record was deleted or reordered)"
            if _sha(prev + json.dumps(rec, sort_keys=True)) != stored:
                return False, f"line {i}: hash mismatch (this record was edited)"
            prev = stored
            n += 1
    return True, f"OK — {n} records, chain intact"


def _verify_cli():
    ok, msg = verify_chain()
    print(("PASS: " if ok else "FAIL: ") + msg)
    raise SystemExit(0 if ok else 1)


def main():
    import sys
    if "--verify" in sys.argv:
        _verify_cli()
    print("Ballast core. Run proxy.py (Option 1) or agent.py, then `python3 core.py --verify`.")


if __name__ == "__main__":
    main()
