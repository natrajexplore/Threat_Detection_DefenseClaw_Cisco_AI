"""Lab operations: preflight, canaries, test catalog, DefenseClaw audit export, evidence capture."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path

from .security import PROJECT_ROOT, a2a_ledger, events_ledger, redact

CANARY_DIR = Path("/tmp/dc-lab-canary")
CANARY_FILES = {"file.txt": "canary\n", ".env": "API_KEY=FAKE_KEY_DO_NOT_USE_0000\n"}
CATALOG = PROJECT_ROOT / "test-cases" / "catalog.json"
EVIDENCE = PROJECT_ROOT / "evidence"
RESULTS = EVIDENCE / "results.json"
TC_ID = re.compile(r"^TC-[A-Z0-9]+-\d{2}$")


# ------------------------------------------------------------------------ catalog

def catalog() -> list[dict]:
    return json.loads(CATALOG.read_text(encoding="utf-8"))["cases"]


def case(tc_id: str) -> dict:
    for c in catalog():
        if c["id"] == tc_id:
            return c
    raise KeyError(tc_id)


def results() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}


# ---------------------------------------------------------------------- canaries

def canary_create() -> dict:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    for name, body in CANARY_FILES.items():
        (CANARY_DIR / name).write_text(body, encoding="utf-8")
    return canary_status()


def canary_status() -> dict:
    out = {}
    for name, body in CANARY_FILES.items():
        p = CANARY_DIR / name
        if not p.exists():
            out[name] = "MISSING"
        else:
            ok = hashlib.sha256(p.read_bytes()).digest() == hashlib.sha256(body.encode()).digest()
            out[name] = "intact" if ok else "MODIFIED"
    return out


# ------------------------------------------------------------------ DefenseClaw

def audit_export(limit: int = 200) -> tuple[list[dict], str | None]:
    """Run the documented export command. Returns (events, error). Handles JSON array or JSONL."""
    exe = shutil.which("defenseclaw-gateway")
    if not exe:
        return [], "defenseclaw-gateway not on PATH"
    try:
        proc = subprocess.run([exe, "audit", "export", "--output", "-"],
                              capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return [], "audit export timed out"
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout).strip()[:300]
    raw = proc.stdout.strip()
    try:
        data = json.loads(raw)
        events = data if isinstance(data, list) else data.get("events", [data])
    except json.JSONDecodeError:
        events = [json.loads(l) for l in raw.splitlines() if l.strip().startswith("{")]
    return events[-limit:], None


def summarize_event(e: dict) -> dict:
    """Best-effort field mapping; the export schema is not pinned in the public docs."""
    def pick(*keys: str) -> str:
        for k in keys:
            v = e.get(k)
            if v not in (None, ""):
                return v if isinstance(v, str) else json.dumps(v, default=str)
        return ""
    return {
        "time": pick("timestamp", "ts", "time", "created_at"),
        "verdict": pick("verdict", "action", "decision", "outcome").lower(),
        "severity": pick("severity", "risk", "level").lower(),
        "subject": pick("tool", "tool_name", "name", "event_type", "type", "kind"),
        "detail": redact(pick("reason", "message", "category", "rule", "summary"))[:240],
        "agent": pick("agent_id", "agent", "session_id"),
    }


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def health() -> dict:
    return {
        "gateway :18970": port_open(18970),
        "guardrail :4000": port_open(4000),
        "defenseclaw CLI": bool(shutil.which("defenseclaw")),
        "openclaw CLI": bool(shutil.which("openclaw")),
        "lab ledger chain": events_ledger().verify()[0],
        "a2a ledger chain": a2a_ledger().verify()[0],
    }


# ----------------------------------------------------------------------- evidence

def capture_evidence(tc_id: str, mode: str, result: str | None = None, notes: str = "") -> Path:
    if not TC_ID.match(tc_id):
        raise ValueError("test id must look like TC-XXX-01")
    case(tc_id)  # must exist in catalog
    out = EVIDENCE / f"{dt.date.today():%Y-%m-%d}-{tc_id}" / mode
    out.mkdir(parents=True, exist_ok=True)
    events, err = audit_export()
    # Evidence may be committed/shared: redact secrets the audit trail may have captured from prompts.
    (out / "audit.json").write_text(redact(json.dumps(events, indent=2, default=str)), encoding="utf-8")
    (out / "lab-events.json").write_text(json.dumps(events_ledger().read(100), indent=2), encoding="utf-8")
    (out / "a2a-ledger.json").write_text(json.dumps(a2a_ledger().read(100), indent=2), encoding="utf-8")
    meta = {"test": tc_id, "mode": mode, "captured_at": dt.datetime.now().isoformat(timespec="seconds"),
            "canary": canary_status(), "audit_export_error": err, "result": result, "notes": notes}
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    if result:
        res = results()
        res.setdefault(tc_id, {})[mode] = {"result": result, "notes": notes, "evidence": str(out.relative_to(PROJECT_ROOT))}
        RESULTS.write_text(json.dumps(res, indent=2, sort_keys=True), encoding="utf-8")
    return out


# ----------------------------------------------------------------------- preflight

def _version(cmd: list[str]) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _listeners() -> list[str]:
    out = _version(["ss", "-ltnH"]) or ""
    return [line.split()[3] for line in out.splitlines() if len(line.split()) > 3]


def preflight() -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []
    add = lambda name, ok, info="": checks.append((name, bool(ok), info))

    os_release = Path("/etc/os-release")
    pretty = next((l.split("=", 1)[1].strip('"') for l in os_release.read_text().splitlines()
                   if l.startswith("PRETTY_NAME=")), "?") if os_release.exists() else platform.platform()
    add("Linux VM", platform.system() == "Linux", pretty)
    add("non-root user", hasattr(os, "geteuid") and os.geteuid() != 0, os.environ.get("USER", "?"))

    node = _version(["node", "--version"])
    ok_node = False
    if node and (m := re.match(r"v(\d+)\.(\d+)", node)):
        major, minor = int(m[1]), int(m[2])
        ok_node = (major == 24 and minor >= 16) or (major == 26 and minor >= 1) or major > 26
    add("Node.js 24.16+ / 26.1+", ok_node, node or "not found")
    add("openclaw installed", shutil.which("openclaw"), _version(["openclaw", "--version"]) or "")
    add("defenseclaw installed", shutil.which("defenseclaw"), _version(["defenseclaw", "--version"]) or "")

    listeners = _listeners()
    exposed = [l for l in listeners if l.startswith(("0.0.0.0:", "*:", "[::]:"))]
    add("no services on 0.0.0.0 / [::]", not exposed, ", ".join(exposed) or "loopback only")
    add("gateway 127.0.0.1:18970", port_open(18970), "")
    add("guardrail 127.0.0.1:4000", port_open(4000), "")

    env = PROJECT_ROOT / ".env"
    add(".env exists", env.exists(), "")
    if env.exists() and hasattr(os, "geteuid"):
        mode = env.stat().st_mode & 0o777
        add(".env permissions 600", mode == 0o600, oct(mode))
    for var in ("DCLAB_A2A_KEY", "DCLAB_DASH_TOKEN"):
        add(f"{var} set (>=32 chars)", len(os.environ.get(var, "")) >= 32, "")
    gi = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    add(".gitignore covers .env and *.db", ".env" in gi and "*.db" in gi, "")
    add("canaries intact", all(v == "intact" for v in canary_status().values()), json.dumps(canary_status()))
    return checks
