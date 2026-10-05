"""Read-only analysis of IOS-style configs. Pure functions: no I/O, no device access."""

from __future__ import annotations

import difflib
import re

_ACL_HDR = re.compile(r"^ip access-list extended (\S+)", re.I)
_ACE = re.compile(r"^\s*(?:(\d+)\s+)?(permit|deny)\s+(\S+)\s+(.*)$", re.I)


def parse_acls(text: str) -> dict[str, list[dict]]:
    acls: dict[str, list[dict]] = {}
    current: str | None = None
    for raw in text.splitlines():
        if m := _ACL_HDR.match(raw.strip()):
            current = m.group(1)
            acls[current] = []
            continue
        if current is None:
            continue
        if not raw.startswith(" ") or raw.strip() == "!":
            current = None
            continue
        if m := _ACE.match(raw):
            seq, action, proto, rest = m.groups()
            acls[current].append({
                "seq": int(seq) if seq else None,
                "action": action.lower(),
                "proto": proto.lower(),
                "match": rest.replace(" log", "").strip(),
                "log": rest.rstrip().endswith(" log") or rest.strip() == "log",
                "line": raw.strip(),
            })
    return acls


def lint(text: str) -> list[dict]:
    findings: list[dict] = []

    def add(sev: str, rule: str, msg: str, line: str = "") -> None:
        findings.append({"severity": sev, "rule": rule, "message": msg, "line": line})

    for name, aces in parse_acls(text).items():
        any_any = next((i for i, a in enumerate(aces) if a["action"] == "permit" and a["proto"] == "ip"
                        and a["match"] == "any any"), None)
        if any_any is not None:
            add("high", "ACL-ANY-ANY", f"{name}: 'permit ip any any' allows all traffic", aces[any_any]["line"])
            for shadowed in aces[any_any + 1:]:
                add("medium", "ACL-SHADOWED", f"{name}: entry is unreachable (shadowed by any/any)", shadowed["line"])
        if aces and not (aces[-1]["action"] == "deny" and aces[-1]["log"]):
            add("low", "ACL-NO-DENY-LOG", f"{name}: no explicit 'deny ip any any log' at the end")

    for line in text.splitlines():
        s = line.strip()
        if re.match(r"transport input .*\btelnet\b", s, re.I):
            add("high", "MGMT-TELNET", "Telnet enabled on VTY lines (cleartext management)", s)
        if re.match(r"snmp-server community (public|private)\b", s, re.I):
            add("high", "SNMP-DEFAULT-COMMUNITY", "Default SNMP community string", "snmp-server community <REDACTED>")
        if re.match(r"enable password\b", s, re.I):
            add("high", "WEAK-ENABLE", "'enable password' used instead of 'enable secret'", "enable password <REDACTED>")
    if re.search(r"^line vty", text, re.M) and not re.search(r"^ip ssh version 2", text, re.M):
        add("medium", "SSH-V2-MISSING", "'ip ssh version 2' not set")
    return findings


def diff(a_text: str, b_text: str, a_name: str = "a", b_name: str = "b") -> str:
    return "".join(difflib.unified_diff(
        a_text.splitlines(keepends=True), b_text.splitlines(keepends=True), a_name, b_name, n=1))
