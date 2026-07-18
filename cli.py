"""
Ballast CLI — read-only tools over the local audit trail.

Streams the log line by line (constant memory) and prints plain text to stdout,
so it works over SSH on a headless edge box. Standard library only.

    ballast log                 # the timeline: asked -> decided -> did
    ballast log --flagged       # only the dangerous-intent flags
    ballast log --session ab12  # one run
    ballast summary             # per-run rollup
    ballast verify              # is the hash-chain intact?
    ballast attest              # a portable, optionally-sealed proof of state
    ballast health              # is Ballast alive? (exit 0=ok, 1=down)
    ballast anchor              # publish the chain head to the external anchor sink
    ballast verify --anchors F  # also prove the trail matches external anchors in F
    ballast report              # send the opt-in counts tally to BALLAST_REPORT
    ballast sync                # deliver buffered audit records to BALLAST_SYNC
"""

import argparse
import json
import sys

import core


def _iter_records(path):
    try:
        f = open(path)
    except FileNotFoundError:
        return
    with f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def _one_line(rec):
    kind = rec.get("kind")
    if kind == "model_call":
        return f"model  step {rec.get('step')}  chose={rec.get('chose')}"
    if kind == "tool_call":
        return f"tool   {rec.get('tool')}({rec.get('arg')!r}) -> {rec.get('decision')}  ({rec.get('reason')})"
    if kind == "flag":
        text = (rec.get("content") or {}).get("text", "")
        return f"FLAG   {rec.get('matched')}  {text}"
    return kind or "?"


def cmd_log(args):
    for rec in _iter_records(core.AUDIT_FILE):
        if args.flagged and rec.get("kind") != "flag":
            continue
        if args.session and rec.get("session") != args.session:
            continue
        if getattr(args, "control", None) and args.control not in (rec.get("controls") or []):
            continue
        ts = (rec.get("ts") or "")[:19].replace("T", " ")
        line = _one_line(rec)
        ctrls = rec.get("controls")
        if ctrls:
            line += f"   ({', '.join(ctrls)})"
        print(f"{ts}  [{rec.get('session', '')}]  {line}")


def cmd_summary(args):
    runs = {}
    for rec in _iter_records(core.AUDIT_FILE):
        sid = rec.get("session", "?")
        r = runs.setdefault(sid, {"events": 0, "flags": 0, "blocks": 0, "first": rec.get("ts"), "last": rec.get("ts")})
        r["events"] += 1
        if rec.get("kind") == "flag":
            r["flags"] += 1
        if rec.get("decision") == "BLOCK":
            r["blocks"] += 1
        r["last"] = rec.get("ts")
    if not runs:
        print("(no audit records yet)")
        return
    for sid, r in runs.items():
        span = f"{(r['first'] or '')[:19]} -> {(r['last'] or '')[:19]}".replace("T", " ")
        print(f"session {sid}: {r['events']} events, {r['flags']} flag(s), {r['blocks']} block(s)   {span}")


def cmd_verify(args):
    if getattr(args, "anchors", None):
        checkpoints = []
        try:
            with open(args.anchors) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        checkpoints.append(json.loads(line))
        except FileNotFoundError:
            print(f"FAIL: anchor file not found: {args.anchors}")
            sys.exit(1)
        ok, msg = core.verify_against(checkpoints)
    else:
        ok, msg = core.verify_chain()
    print(("PASS: " if ok else "FAIL: ") + msg)
    sys.exit(0 if ok else 1)


def cmd_anchor(args):
    cp, published = core.anchor()
    print(json.dumps(cp, indent=2))
    if not published:
        print("(no anchor sink configured; set BALLAST_ANCHOR to publish it)", file=sys.stderr)


def cmd_report(args):
    if core.REPORT == "none":
        print("(opt-in only; set BALLAST_REPORT=https://your-endpoint to enable)", file=sys.stderr)
        sys.exit(0)
    print("reported" if core.report() else "(nothing to report yet)")


def cmd_sync(args):
    if core.SYNC == "none":
        print("(set BALLAST_SYNC=file:/command:/webhook: to enable store-and-forward)", file=sys.stderr)
        sys.exit(0)
    print(f"synced {core.sync()} record(s)")


def cmd_attest(args):
    print(json.dumps(core.attest(), indent=2))


def cmd_health(args):
    h = core.health()
    if args.json:
        print(json.dumps(h, indent=2))
    elif h["alive"]:
        print(f"OK - alive, last heartbeat {h['age_seconds']}s ago (pid {h.get('pid')})")
    else:
        print("DOWN - " + (h.get("reason") or f"stale (no heartbeat for {h.get('age_seconds')}s)"))
    sys.exit(0 if h["alive"] else 1)


def main():
    p = argparse.ArgumentParser(prog="ballast", description="Ballast audit tools (local, read-only).")
    sub = p.add_subparsers(dest="command")

    lg = sub.add_parser("log", help="print the audit timeline")
    lg.add_argument("--flagged", action="store_true", help="only dangerous-intent flags")
    lg.add_argument("--session", help="filter to one run/session id")
    lg.add_argument("--control", help="filter to records evidencing a control id, e.g. 'MEASURE 2.8'")
    lg.set_defaults(func=cmd_log)

    sm = sub.add_parser("summary", help="per-session rollup (a digest)")
    sm.set_defaults(func=cmd_summary)

    vf = sub.add_parser("verify", help="verify the hash-chain is intact")
    vf.add_argument("--anchors", help="also prove the chain against a JSONL file of external anchors")
    vf.set_defaults(func=cmd_verify)

    at = sub.add_parser("attest", help="print a portable proof of the trail's state")
    at.set_defaults(func=cmd_attest)

    hp = sub.add_parser("health", help="report whether Ballast is alive (exit 0=ok, 1=down)")
    hp.add_argument("--json", action="store_true")
    hp.set_defaults(func=cmd_health)

    an = sub.add_parser("anchor", help="publish the current chain head to the external anchor sink")
    an.set_defaults(func=cmd_anchor)

    rp = sub.add_parser("report", help="send the opt-in counts tally to BALLAST_REPORT")
    rp.set_defaults(func=cmd_report)

    sy = sub.add_parser("sync", help="deliver buffered audit records to BALLAST_SYNC (store-and-forward)")
    sy.set_defaults(func=cmd_sync)

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
