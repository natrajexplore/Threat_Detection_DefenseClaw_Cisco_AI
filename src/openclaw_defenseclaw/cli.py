"""`dclab` — operator CLI for the DefenseClaw x OpenClaw NetOps lab."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys

from . import lab
from .security import PROJECT_ROOT, a2a_ledger, events_ledger


def _load_env() -> None:
    """Load .env without printing it. Existing environment variables win."""
    env = PROJECT_ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            if v.strip():
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def cmd_preflight(_: argparse.Namespace) -> int:
    checks = lab.preflight()
    for name, ok, info in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<34} {info}")
    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


def cmd_canary(a: argparse.Namespace) -> int:
    status = lab.canary_status() if a.verify else lab.canary_create()
    print(json.dumps({"dir": str(lab.CANARY_DIR), **status}, indent=2))
    return 0 if all(v == "intact" for v in status.values()) else 1


def cmd_cases(_: argparse.Namespace) -> int:
    res = lab.results()
    for c in lab.catalog():
        r = res.get(c["id"], {})
        print(f"{c['id']:<12} {c['category']:<20} obs={r.get('observe', {}).get('result', '-'):<5} "
              f"act={r.get('action', {}).get('result', '-'):<5} {c['title']}")
    return 0


def cmd_show(a: argparse.Namespace) -> int:
    c = lab.case(a.id)
    print(f"# {c['id']} — {c['title']}\nCategory: {c['category']}\n")
    if c.get("setup"):
        print("Setup:\n" + "\n".join(f"  - {s}" for s in c["setup"]) + "\n")
    if c.get("prompt"):
        print(f"Prompt to paste into OpenClaw ({c.get('agent', 'orchestrator')}):\n\n  {c['prompt']}\n")
    print(f"Expected (observe): {c['observe']}\nExpected (action):  {c['action']}")
    return 0


def cmd_evidence(a: argparse.Namespace) -> int:
    out = lab.capture_evidence(a.id, a.mode, a.result, a.notes or "")
    print(f"Evidence written to {out}")
    print("Add a TUI/dashboard screenshot to the same folder to complete the evidence checklist.")
    return 0


def cmd_ledger(a: argparse.Namespace) -> int:
    for name, led in (("lab-events", events_ledger()), ("a2a", a2a_ledger())):
        ok, n = led.verify()
        print(f"{name:<10} {'OK' if ok else f'TAMPERED at row {n}'} ({len(led.read())} rows)")
    return 0


def cmd_trace(a: argparse.Namespace) -> int:
    from . import trace
    errors: list[str] = []
    runs = trace.build(errors)
    for e in errors:
        print(f"  ! {e}", file=sys.stderr)
    if not a.export:
        for r in runs[:a.limit]:
            print(f"{r['id']}  {r['count']:>4} events  {r['blocked']:>2} blocked  {' > '.join(r['lanes'])}  {r['title']}")
        if not runs:
            print("No runs yet. Send a prompt to an agent in OpenClaw first.")
        return 0
    run = runs[0] if a.export == "latest" else next((r for r in runs if r["id"] == a.export), None)
    if run is None:
        print(f"run {a.export} not found; list runs with `dclab trace`", file=sys.stderr)
        return 1
    from .dashboard.app import save_trace_report
    print(f"Saved {save_trace_report(run, a.tc or '')}")
    return 0


def cmd_genkey(_: argparse.Namespace) -> int:
    print(secrets.token_hex(32))
    return 0


def cmd_mcp(a: argparse.Namespace) -> int:
    from .mcp_server import run
    run(a.role)
    return 0


def cmd_observe(_: argparse.Namespace) -> int:
    from .observer import run
    run()
    return 0


def cmd_dashboard(a: argparse.Namespace) -> int:
    if len(os.environ.get("DCLAB_DASH_TOKEN", "")) < 32:
        print("DCLAB_DASH_TOKEN missing/short in .env — run `dclab genkey` and add it.", file=sys.stderr)
        return 2
    import uvicorn
    from .dashboard.app import create_app
    print(f"Dashboard: http://127.0.0.1:{a.port}  (loopback only; log in with DCLAB_DASH_TOKEN)")
    uvicorn.run(create_app(port=a.port), host="127.0.0.1", port=a.port, log_level="warning",
                server_header=False, proxy_headers=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_env()
    p = argparse.ArgumentParser(prog="dclab", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("preflight", help="check VM, versions, loopback binds, secrets hygiene").set_defaults(fn=cmd_preflight)
    s = sub.add_parser("canary", help="create (or --verify) inert canary files")
    s.add_argument("--verify", action="store_true")
    s.set_defaults(fn=cmd_canary)
    sub.add_parser("cases", help="list test cases and recorded results").set_defaults(fn=cmd_cases)
    s = sub.add_parser("show", help="print a test case prompt + expected results")
    s.add_argument("id")
    s.set_defaults(fn=cmd_show)
    s = sub.add_parser("evidence", help="capture audit export + ledgers into evidence/<date>-<id>/")
    s.add_argument("id")
    s.add_argument("--mode", choices=["observe", "action"], required=True)
    s.add_argument("--result", choices=["Pass", "Fail", "Gap"])
    s.add_argument("--notes")
    s.set_defaults(fn=cmd_evidence)
    sub.add_parser("ledger", help="verify hash chains of lab ledgers").set_defaults(fn=cmd_ledger)
    s = sub.add_parser("trace", help="list end-to-end conversation runs, or --export one as offline HTML")
    s.add_argument("--export", metavar="RUN_ID|latest")
    s.add_argument("--tc", help="attach the report to a test case evidence folder")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_trace)
    sub.add_parser("genkey", help="print a random 32-byte hex key").set_defaults(fn=cmd_genkey)
    s = sub.add_parser("mcp", help="run the NetOps MCP server (stdio) for one agent role")
    s.add_argument("--role", required=True, choices=["orchestrator", "config-analyst", "change-reviewer"])
    s.set_defaults(fn=cmd_mcp)
    sub.add_parser("observe", help="run the read-only Lab Observer MCP server (stdio) for Claude Code"
                   ).set_defaults(fn=cmd_observe)
    s = sub.add_parser("dashboard", help="run the local web dashboard on 127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(fn=cmd_dashboard)
    a = p.parse_args(argv)
    return a.fn(a)
