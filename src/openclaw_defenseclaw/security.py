"""Lab-side defense-in-depth controls.

These run *in addition to* DefenseClaw, never instead of it. DefenseClaw is the
policy decision point for every LLM call and tool call; these controls make the
NetOps tools themselves safe even if a verdict is missed (observe mode, gap, outage).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- paths

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = Path(os.environ.get("DCLAB_STATE_DIR", PROJECT_ROOT / ".dclab"))
ALLOWED_SUFFIXES = {".cfg", ".conf", ".txt"}
MAX_FILE_BYTES = 256 * 1024


class PolicyViolation(Exception):
    """Raised when a lab control refuses an action. Message is safe to show the agent."""

    def __init__(self, control: str, message: str):
        super().__init__(f"[{control}] {message}")
        self.control = control


def workspace_root() -> Path:
    return Path(os.environ.get("DCLAB_WORKSPACE") or PROJECT_ROOT / "workspace").resolve()


def jail_path(name: str, root: Path | None = None) -> Path:
    """Resolve `name` inside the workspace or raise. Blocks traversal, absolute paths,
    symlink escapes, hidden files, non-config suffixes and oversized files."""
    root = (root or workspace_root()).resolve()
    if not name or "\x00" in name:
        raise PolicyViolation("path-jail", "empty or invalid file name")
    candidate = Path(name)
    if candidate.is_absolute() or name.startswith("~"):
        raise PolicyViolation("path-jail", "absolute paths are not allowed; use a name inside workspace/")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise PolicyViolation("path-jail", "path escapes the workspace")
    if any(part.startswith(".") for part in resolved.relative_to(root).parts):
        raise PolicyViolation("path-jail", "hidden files are not readable")
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise PolicyViolation("path-jail", f"only {sorted(ALLOWED_SUFFIXES)} files are readable")
    if not resolved.is_file():
        raise PolicyViolation("path-jail", "file not found in workspace")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise PolicyViolation("path-jail", "file too large")
    return resolved


# ------------------------------------------------------------- dangerous NetOps text

NETOPS_BLOCKED = [
    (re.compile(r"\bconf(?:igure)?\s+t(?:erminal)?\b", re.I), "config-mode entry"),
    (re.compile(r"\bwr(?:ite)?\s+(?:mem(?:ory)?|erase)\b", re.I), "persist/erase config"),
    (re.compile(r"\bcopy\s+run(?:ning-config)?\s+start(?:up-config)?\b", re.I), "persist config"),
    (re.compile(r"(?m)^\s*reload\b", re.I), "device reload"),
    (re.compile(r"\berase\s+(?:startup-config|nvram|flash)", re.I), "erase storage"),
    (re.compile(r"\bformat\s+(?:flash|disk|bootflash)", re.I), "format storage"),
    (re.compile(r"\bno\s+aaa\b", re.I), "disable AAA"),
    (re.compile(r"\bdebug\s+all\b", re.I), "debug all"),
    (re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b", re.I), "remote exec"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\b", re.I), "recursive delete"),
]

INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I), "instruction override"),
    (re.compile(r"\b(?:pre-?approved|already\s+approved|skip\s+(?:the\s+)?checks?)\b", re.I), "trust exploitation"),
    (re.compile(r"\b(?:print|dump|show)\s+(?:all\s+)?(?:env(?:ironment)?\s+var|secrets?|api\s*keys?)", re.I), "secret harvesting"),
    (re.compile(r"\byou\s+are\s+now\b|\bnew\s+system\s+prompt\b", re.I), "role hijack"),
    (re.compile(r"<\s*(?:important|system|instructions?)\s*>", re.I), "hidden instruction tag"),
    (re.compile(r"\.ssh/id_|/etc/shadow|\.aws/credentials", re.I), "sensitive path reference"),
]


def find_dangerous(text: str) -> list[str]:
    return [label for rx, label in NETOPS_BLOCKED if rx.search(text or "")]


def find_injection(text: str) -> list[str]:
    return [label for rx, label in INJECTION_PATTERNS if rx.search(text or "")]


# ---------------------------------------------------------------------- redaction

_REDACTIONS = [
    (re.compile(r"(\b(?:enable\s+)?secret\s+\d+\s+)\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\bpassword\s+(?:\d+\s+)?)\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\bsnmp-server\s+community\s+)\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\bkey-string\s+)\S+", re.I), r"\1<REDACTED>"),
    (re.compile(r"FAKE_KEY_DO_NOT_USE_\w*"), "<REDACTED>"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), "<REDACTED>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<REDACTED>"),
    (re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._\-]{12,}"), r"\1<REDACTED>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<REDACTED PRIVATE KEY>"),
]


def redact(text: str) -> str:
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


# -------------------------------------------------------------------- rate limits

@dataclass
class RateLimiter:
    """Token bucket per key. Stops a looping/beaconing agent from hammering a tool."""

    rate_per_min: int = 30
    _buckets: dict[str, tuple[float, float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.rate_per_min), now))
            tokens = min(self.rate_per_min, tokens + (now - last) * self.rate_per_min / 60)
            if tokens < 1:
                raise PolicyViolation("rate-limit", f"too many calls to {key}; slow down")
            self._buckets[key] = (tokens - 1, now)


# ---------------------------------------------------------- tamper-evident ledger

class Ledger:
    """Append-only JSONL with a SHA-256 hash chain. Any edit/delete breaks `verify()`."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def append(self, event: dict) -> dict:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            record = {"ts": time.time(), **event, "prev": self._last_hash()}
            record["hash"] = hashlib.sha256(_canonical(record).encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
            return record

    def read(self, limit: int | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        rows = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        return rows[-limit:] if limit else rows

    def verify(self) -> tuple[bool, int]:
        """Return (ok, index_of_first_bad_row_or_count)."""
        prev = "0" * 64
        rows = self.read()
        for i, row in enumerate(rows):
            body = {k: v for k, v in row.items() if k != "hash"}
            if row.get("prev") != prev or hashlib.sha256(_canonical(body).encode()).hexdigest() != row.get("hash"):
                return False, i
            prev = row["hash"]
        return True, len(rows)


def events_ledger() -> Ledger:
    return Ledger(STATE_DIR / "lab-events.jsonl")


def a2a_ledger() -> Ledger:
    return Ledger(STATE_DIR / "a2a-ledger.jsonl")


# ------------------------------------------------------ signed agent-to-agent (A2A)

AGENTS = ("orchestrator", "config-analyst", "change-reviewer")

# Hub-and-spoke only: specialists never talk to each other directly, so a compromised
# analyst cannot ask the reviewer to approve something without the orchestrator/human seeing it.
ALLOWED_HANDOFFS = {
    ("orchestrator", "config-analyst"),
    ("orchestrator", "change-reviewer"),
    ("config-analyst", "orchestrator"),
    ("change-reviewer", "orchestrator"),
}
HANDOFF_TTL_S = 300
MAX_TASK_CHARS = 4000


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def a2a_key() -> bytes:
    key = os.environ.get("DCLAB_A2A_KEY", "")
    if len(key) < 32:
        raise PolicyViolation("a2a", "DCLAB_A2A_KEY missing or shorter than 32 chars; see .env.example")
    return key.encode()


def sign_handoff(sender: str, recipient: str, task: str, *, key: bytes | None = None) -> dict:
    """Create a signed task envelope. `sender` must come from the server's bound role,
    never from model-supplied text, so an agent cannot spoof another agent's identity."""
    if sender not in AGENTS or recipient not in AGENTS:
        raise PolicyViolation("a2a", "unknown agent id")
    if (sender, recipient) not in ALLOWED_HANDOFFS:
        raise PolicyViolation("a2a", f"handoff {sender} -> {recipient} is not on the allowlist")
    if len(task) > MAX_TASK_CHARS:
        raise PolicyViolation("a2a", "task too long")
    if hits := find_injection(task):
        raise PolicyViolation("a2a", f"task contains injection markers: {', '.join(hits)}")
    if hits := find_dangerous(task):
        raise PolicyViolation("a2a", f"task contains blocked NetOps actions: {', '.join(hits)}")
    env = {
        "v": 1,
        "from": sender,
        "to": recipient,
        "task": redact(task),
        "nonce": secrets.token_hex(12),
        "iat": int(time.time()),
    }
    env["sig"] = hmac.new(key or a2a_key(), _canonical(env).encode(), hashlib.sha256).hexdigest()
    return env


class ReplayCache:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            self._seen = {n: t for n, t in self._seen.items() if now - t < HANDOFF_TTL_S}
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


def verify_handoff(env: dict, recipient: str, replay: ReplayCache, *, key: bytes | None = None) -> dict:
    """Verify signature, recipient binding, freshness and replay. Returns the envelope."""
    if not isinstance(env, dict) or "sig" not in env:
        raise PolicyViolation("a2a", "unsigned handoff rejected")
    body = {k: v for k, v in env.items() if k != "sig"}
    expected = hmac.new(key or a2a_key(), _canonical(body).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(env["sig"])):
        raise PolicyViolation("a2a", "bad signature (tampered or forged handoff)")
    if env.get("to") != recipient:
        raise PolicyViolation("a2a", f"handoff addressed to {env.get('to')}, not {recipient}")
    if (env.get("from"), recipient) not in ALLOWED_HANDOFFS:
        raise PolicyViolation("a2a", "sender not allowed to hand off to this agent")
    if time.time() - int(env.get("iat", 0)) > HANDOFF_TTL_S:
        raise PolicyViolation("a2a", "handoff expired")
    if not replay.check_and_add(str(env.get("nonce"))):
        raise PolicyViolation("a2a", "replayed handoff rejected")
    return env
