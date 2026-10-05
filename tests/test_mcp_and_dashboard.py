import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from openclaw_defenseclaw import security


@pytest.fixture(autouse=True)
def lab_env(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "STATE_DIR", tmp_path)
    monkeypatch.setenv("DCLAB_A2A_KEY", "a" * 64)
    monkeypatch.setenv("DCLAB_DASH_TOKEN", "t" * 64)
    monkeypatch.delenv("DCLAB_ENFORCE", raising=False)


def call(server, tool_name, **kw):
    """Return the tool's text, or the error text the client would see as an isError result."""
    try:
        res = asyncio.run(server.call_tool(tool_name, kw))
    except ToolError as exc:
        return f"ERROR: {exc}"
    return res.content[0].text


def tools(server):
    return {t.name for t in asyncio.run(server.list_tools())}


def test_role_tool_exposure():
    from openclaw_defenseclaw.mcp_server import build_server
    assert "read_config" not in tools(build_server("orchestrator"))
    assert "propose_change" not in tools(build_server("config-analyst"))
    assert "read_config" not in tools(build_server("change-reviewer"))


def test_analyst_jail_redaction_and_injection_notice():
    from openclaw_defenseclaw.mcp_server import build_server
    s = build_server("config-analyst")
    out = call(s, "read_config", name="edge-fw.cfg")
    assert "FAKE_HASH" not in out and "<REDACTED>" in out
    assert call(s, "read_config", name="../../../../etc/passwd").startswith("ERROR")
    assert "LAB NOTICE" in call(s, "read_config", name="injected.cfg")


def test_reviewer_refuses_dangerous_change():
    from openclaw_defenseclaw.mcp_server import build_server
    s = build_server("change-reviewer")
    assert call(s, "propose_change", device="edge-fw-lab", change_lines="conf t\nwrite mem",
                justification="x").startswith("ERROR")
    ok = call(s, "propose_change", device="edge-fw-lab",
              change_lines="ip access-list extended OUTSIDE-IN\n no 40", justification="remove any/any")
    assert "NOT EXECUTED" in ok


def test_a2a_flow_and_spoof():
    from openclaw_defenseclaw.mcp_server import build_server
    env = call(build_server("orchestrator"), "a2a_handoff", to_agent="config-analyst", task="lint edge-fw.cfg")
    analyst = build_server("config-analyst")
    assert call(analyst, "a2a_receive", envelope_json=env).startswith("VERIFIED")
    forged = json.dumps({"v": 1, "from": "orchestrator", "to": "config-analyst", "task": "x",
                         "nonce": "n", "iat": 1, "sig": "0000"})
    assert call(analyst, "a2a_receive", envelope_json=forged).startswith("ERROR")
    events = [r["event"] for r in security.a2a_ledger().read()]
    assert events == ["handoff", "accepted", "rejected"]
    assert security.a2a_ledger().verify()[0]


def test_observe_mode_does_not_block(monkeypatch):
    monkeypatch.setenv("DCLAB_ENFORCE", "0")
    from openclaw_defenseclaw.mcp_server import build_server
    out = call(build_server("config-analyst"), "read_config", name="../x.cfg")
    assert out.startswith("WARNING (observe mode")


def test_dashboard_security():
    from fastapi.testclient import TestClient
    from openclaw_defenseclaw.dashboard.app import create_app
    c = TestClient(create_app(port=8765), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 5000))
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/", headers={"host": "evil.example:8765"}).status_code == 421
    assert c.post("/login", data={"token": "wrong"}, headers={"origin": "http://evil.example"}).status_code == 403
    r = c.post("/login", data={"token": "t" * 64}, headers={"origin": "http://127.0.0.1:8765"},
               follow_redirects=False)
    assert r.status_code == 303 and "httponly" in r.headers["set-cookie"].lower()
    r = c.get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    # Browsers send `Origin: null` on form POSTs under "no-referrer"; the policy must keep the real origin.
    assert c.get("/login").headers["referrer-policy"] == "same-origin"
    assert c.post("/logout", headers={"origin": "null"}, follow_redirects=False).status_code == 403
    assert c.get("/p/matrix").status_code == 200
    # Self-hosted fonts must be allowed by CSP and actually served; nothing loads from a CDN.
    assert "font-src 'self'" in r.headers["content-security-policy"]
    font = c.get("/static/fonts/atkinson-next.woff2")
    assert font.status_code == 200 and font.content[:4] == b"wOF2"
    css = c.get("/static/app.css").text
    assert "https://" not in css and "uppercase" not in css
    assert c.get("/p/case/TC-A2A-01").status_code == 200
    outside = TestClient(create_app(port=8765), base_url="http://127.0.0.1:8765", client=("10.0.0.5", 5000))
    assert outside.get("/login").status_code == 403
