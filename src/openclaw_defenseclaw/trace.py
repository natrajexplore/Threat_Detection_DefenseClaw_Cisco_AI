"""End-to-end conversation trace: OpenClaw transcripts + DefenseClaw verdicts + lab ledgers.

Sources are read only through documented CLIs (`openclaw sessions|transcripts ... --json`,
`defenseclaw-gateway audit export`) and the lab's own ledgers. OpenClaw's transcript JSON
schema is not pinned in public docs, so the normalizer accepts several common shapes and
falls back to showing the raw (redacted) entry rather than guessing.
"""

from __future__ import annotations

import datetime as dt
import glob
import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import lab
from .security import AGENTS, a2a_ledger, events_ledger, redact

RUN_GAP_S = 120          # a silence longer than this starts a new run
MATCH_WINDOW_S = 8       # DefenseClaw / lab verdicts attach to a tool call within this window
MAX_BODY = 1200
MAX_LANES = 10
_CACHE: dict[str, tuple[float, object]] = {}
CACHE_TTL_S = 5


@dataclass
class Event:
    ts: float
    lane: str                 # operator | orchestrator | config-analyst | change-reviewer | <other agent> | apps
    kind: str                 # message | tool_call | tool_result | handoff | verdict | lab
    title: str
    body: str = ""
    source: str = "openclaw"  # openclaw | defenseclaw | lab | a2a
    verdict: str = ""         # allow | block | confirm | observe | flag | rejected | accepted ...
    tool: str = ""
    target: str = ""          # handoff recipient lane
    session: str = ""
    verdicts: list[dict] = field(default_factory=list)  # correlated DefenseClaw / lab decisions
    raw: str = ""

    @property
    def worst(self) -> str:
        order = ["block", "blocked", "deny", "rejected", "confirm", "observe", "flag", "alert", "allow", "accepted"]
        found = [v.get("verdict", "") for v in self.verdicts] + [self.verdict]
        for o in order:
            if o in found:
                return o
        return ""


# ------------------------------------------------------------------ helpers

def _cached(key: str, fn):
    hit = _CACHE.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
        return hit[1]
    val = fn()
    _CACHE[key] = (time.monotonic(), val)
    return val


def _ts(v) -> float | None:
    if v in (None, ""):
        return None
    if isinstance(v, str):
        try:
            v = float(v)  # epoch seconds/ms serialized as text
        except ValueError:
            pass
    if isinstance(v, (int, float)):
        return v / 1000 if v > 1e11 else float(v)
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _clip(text: str) -> str:
    text = redact(text or "")
    return text if len(text) <= MAX_BODY else text[:MAX_BODY] + " …[truncated]"


def _raw(obj) -> str:
    return _clip(json.dumps(obj, indent=2, default=str, ensure_ascii=False))


def _openclaw_bin() -> str | None:
    """The dashboard may run without nvm on PATH; fall back to the nvm install location."""
    found = shutil.which("openclaw")
    if found:
        return found
    cands = sorted(glob.glob(os.path.expanduser("~/.nvm/versions/node/*/bin/openclaw")))
    return cands[-1] if cands else None


def _openclaw_json(*args: str):
    exe = _openclaw_bin()
    if not exe:
        return None, "openclaw not found"
    env = {**os.environ, "PATH": f"{Path(exe).parent}:{os.environ.get('PATH', '')}", "NO_COLOR": "1"}
    try:
        p = subprocess.run([exe, *args, "--json"], capture_output=True, text=True, timeout=25, env=env)
    except subprocess.TimeoutExpired:
        return None, f"openclaw {' '.join(args)} timed out"
    if p.returncode != 0:
        return None, (p.stderr or p.stdout).strip()[:300]
    try:
        return json.loads(p.stdout), None
    except json.JSONDecodeError:
        return None, f"openclaw {' '.join(args)}: non-JSON output"


# --------------------------------------------------------- OpenClaw sources

def _lane_for_agent(agent: str) -> str:
    return agent if agent else "orchestrator"


def _text_of(content) -> tuple[str, list[dict]]:
    """Return (text, tool_calls) from str / list-of-parts / dict content."""
    calls: list[dict] = []
    if content is None:
        return "", calls
    if isinstance(content, str):
        return content, calls
    if isinstance(content, dict):
        content = [content]
    parts = []
    for part in content if isinstance(content, list) else []:
        if not isinstance(part, dict):
            parts.append(str(part))
            continue
        ptype = str(part.get("type", ""))
        if ptype in ("tool_use", "tool_call", "toolCall", "function_call"):
            calls.append({"name": part.get("name") or part.get("tool") or "?",
                          "args": part.get("input") or part.get("arguments") or part.get("args") or {}})
        elif ptype in ("tool_result", "toolResult", "function_result"):
            parts.append(_text_of(part.get("content") or part.get("output"))[0])
        else:
            parts.append(str(part.get("text") or part.get("content") or ""))
    return "\n".join(p for p in parts if p), calls


def normalize_transcript_entry(entry: dict, agent: str, session: str, fallback_ts: float) -> list[Event]:
    if not isinstance(entry, dict):
        return []
    msg = entry.get("message") if isinstance(entry.get("message"), dict) else entry
    role = str(msg.get("role") or msg.get("author") or entry.get("type") or "").lower()
    ts = _ts(entry.get("timestamp") or entry.get("ts") or entry.get("time") or entry.get("createdAt")
             or msg.get("timestamp")) or fallback_ts
    text, calls = _text_of(msg.get("content", msg.get("text")))
    for tc in msg.get("tool_calls") or msg.get("toolCalls") or []:
        fn = tc.get("function", tc) if isinstance(tc, dict) else {}
        calls.append({"name": fn.get("name", "?"), "args": fn.get("arguments") or fn.get("input") or {}})
    lane = _lane_for_agent(agent)
    events: list[Event] = []
    if role in ("user", "human", "operator"):
        events.append(Event(ts, "operator", "message", "Operator", _clip(text), session=session, raw=_raw(entry),
                            target=lane))
    elif role in ("tool", "tool_result", "toolresult", "function"):
        name = str(msg.get("name") or msg.get("toolName") or msg.get("tool") or "tool")
        events.append(Event(ts, lane, "tool_result", f"{name} → result", _clip(text), tool=name,
                            session=session, raw=_raw(entry)))
    elif role in ("assistant", "agent", "model") or text or calls:
        if text:
            events.append(Event(ts, lane, "message", agent or "agent", _clip(text), session=session, raw=_raw(entry)))
        for i, c in enumerate(calls):
            args = c["args"] if isinstance(c["args"], str) else json.dumps(c["args"], default=str)
            name = str(c["name"])
            target = ""
            if name in ("sessions_send", "sessions_spawn"):
                for a in AGENTS:
                    if a in args:
                        target = a
            events.append(Event(ts + (i + 1) * 1e-3, lane, "tool_call", name, _clip(args), tool=name,
                                target=target, session=session, raw=_raw(c)))
    return events


def _transcript_entries(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("messages", "entries", "events", "turns", "transcript", "items"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def openclaw_events(errors: list[str]) -> list[Event]:
    data, err = _cached("sessions", lambda: _openclaw_json("sessions", "--all-agents", "--limit", "25"))
    if err:
        errors.append(f"OpenClaw sessions: {err}")
        return []
    events: list[Event] = []
    for s in (data or {}).get("sessions", []):
        sid, agent = s.get("sessionId", ""), s.get("agentId", "")
        if not sid:
            continue
        tdata, terr = _cached(f"t:{sid}", lambda sid=sid: _openclaw_json("transcripts", "show", sid))
        if terr:
            # A session with no stored transcript yet is normal; only surface real failures.
            if "not found" not in terr.lower() and "no transcript" not in terr.lower():
                errors.append(f"OpenClaw transcript {sid[:8]}: {terr}")
            continue
        base = _ts(s.get("sessionStartedAt")) or time.time()
        for i, entry in enumerate(_transcript_entries(tdata)):
            events.extend(normalize_transcript_entry(entry, agent, sid, base + i * 1e-3))
    return events


# ------------------------------------------------------ DefenseClaw + lab

def defenseclaw_events(errors: list[str]) -> list[Event]:
    raw, err = _cached("audit", lambda: lab.audit_export(limit=500))
    if err:
        errors.append(f"DefenseClaw audit: {err}")
    out = []
    for e in raw:
        s = lab.summarize_event(e)
        ts = _ts(s["time"])
        if ts is None:
            continue
        agent = s["agent"] if s["agent"] in AGENTS else ""
        out.append(Event(ts, agent or "orchestrator", "verdict", s["subject"] or "event", s["detail"],
                         source="defenseclaw", verdict=s["verdict"], tool=s["subject"], raw=_raw(e)))
    return out


def lab_events() -> list[Event]:
    out = []
    for r in events_ledger().read(500):
        if r.get("kind") == "tool":
            out.append(Event(r["ts"], r.get("agent", "apps"), "lab", f"{r.get('tool')} (NetOps app)",
                             _clip(r.get("reason") or r.get("args", "")), source="lab",
                             verdict=r.get("verdict", ""), tool=r.get("tool", ""), raw=_raw(r)))
        else:
            out.append(Event(r["ts"], r.get("agent", "apps"), "lab", "content scan", _clip(r.get("reason", "")),
                             source="lab", verdict=r.get("verdict", ""), raw=_raw(r)))
    for r in a2a_ledger().read(500):
        ev = r.get("event")
        if ev == "handoff":
            out.append(Event(r["ts"], r["from"], "handoff", f"handoff → {r['to']}", _clip(r.get("task", "")),
                             source="a2a", verdict="signed", target=r["to"], raw=_raw(r)))
        elif ev == "accepted":
            out.append(Event(r["ts"], r["to"], "handoff", f"verified task from {r['from']}", "",
                             source="a2a", verdict="accepted", raw=_raw(r)))
        else:
            out.append(Event(r["ts"], r.get("to", "apps"), "handoff",
                             f"REJECTED handoff claiming {r.get('claimed_from')}", _clip(r.get("reason", "")),
                             source="a2a", verdict="rejected", raw=_raw(r)))
    return out


# ------------------------------------------------------------- correlate

def correlate(events: list[Event]) -> list[Event]:
    """Attach DefenseClaw/lab verdicts to the matching OpenClaw tool call (same tool, close in time).
    Unmatched verdicts stay as their own rows so nothing is hidden."""
    calls = [e for e in events if e.kind == "tool_call"]
    keep = []
    for e in events:
        if e.kind in ("verdict", "lab") and e.tool:
            best = min((c for c in calls if c.tool and (c.tool == e.tool or c.tool.endswith("__" + e.tool)
                                                         or c.tool.endswith("." + e.tool))
                        and abs(c.ts - e.ts) <= MATCH_WINDOW_S),
                       key=lambda c: abs(c.ts - e.ts), default=None)
            if best is not None:
                best.verdicts.append({"source": e.source, "verdict": e.verdict, "detail": e.body})
                continue
        keep.append(e)
    return keep


def split_runs(events: list[Event]) -> list[dict]:
    runs: list[list[Event]] = []
    for e in events:
        if not runs or e.ts - runs[-1][-1].ts > RUN_GAP_S:
            runs.append([])
        runs[-1].append(e)
    out = []
    for r in runs:
        lanes = lanes_of(r)
        if len(lanes) > MAX_LANES:  # the grid has 10 columns; fold the rest into "other"
            keep = set(lanes[:MAX_LANES - 1])
            for e in r:
                e.lane = e.lane if e.lane in keep else "other"
                e.target = e.target if (not e.target or e.target in keep) else "other"
        first_prompt = next((e.body for e in r if e.lane == "operator"), r[0].title)
        out.append({
            "id": str(int(r[0].ts)),
            "start": r[0].ts,
            "end": r[-1].ts,
            "title": first_prompt[:90],
            "events": r,
            "lanes": lanes_of(r),
            "blocked": sum(1 for e in r if e.worst in ("block", "blocked", "deny", "rejected")),
            "count": len(r),
        })
    return list(reversed(out))  # newest first


def lanes_of(events: list[Event]) -> list[str]:
    preferred = ["operator", "orchestrator", "config-analyst", "change-reviewer"]
    seen = {e.lane for e in events} | {e.target for e in events if e.target}
    return [l for l in preferred if l in seen] + sorted(seen - set(preferred) - {""})


def build(errors: list[str] | None = None) -> list[dict]:
    errors = errors if errors is not None else []
    events = openclaw_events(errors) + defenseclaw_events(errors) + lab_events()
    events.sort(key=lambda e: e.ts)
    return split_runs(correlate(events))


def run_by_id(run_id: str, errors: list[str] | None = None) -> dict | None:
    return next((r for r in build(errors) if r["id"] == run_id), None)


def to_dict(run: dict) -> dict:
    return {**run, "events": [{**asdict(e), "worst": e.worst} for e in run["events"]]}
