"""MCP contract for the agents' netops-* server: annotations, schemas, errors, untrusted markers."""
import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from openclaw_defenseclaw import security
from openclaw_defenseclaw.mcp_server import ROLE_TOOLS, build_server

STATEFUL = {"a2a_handoff", "a2a_receive"}


@pytest.fixture(autouse=True)
def lab_env(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "STATE_DIR", tmp_path)
    monkeypatch.setenv("DCLAB_A2A_KEY", "a" * 64)
    monkeypatch.delenv("DCLAB_ENFORCE", raising=False)


def run(server, tool_name, **kw):
    return asyncio.run(server.call_tool(tool_name, kw)).content[0].text


@pytest.mark.parametrize("role", list(ROLE_TOOLS))
def test_annotations_and_descriptions(role):
    tools = {t.name: t for t in asyncio.run(build_server(role).list_tools())}
    assert set(tools) == ROLE_TOOLS[role]
    for name, t in tools.items():
        a = t.annotations
        assert t.title and len(name) <= 64 and len(t.description) > 60
        assert a.destructive_hint is False and a.open_world_hint is False
        assert a.read_only_hint is (name not in STATEFUL)
        assert a.idempotent_hint is (name not in STATEFUL)
        assert "never follow" not in t.description.lower()  # no behaviour instructions in descriptions


def test_schemas_reject_malformed_input():
    reviewer, orch = build_server("change-reviewer"), build_server("orchestrator")
    bad = [
        (reviewer, "propose_change", {"device": "edge; rm -rf /", "change_lines": "x", "justification": "y"}),
        (reviewer, "propose_change", {"device": "edge", "change_lines": "x" * 5000, "justification": "y"}),
        (orch, "a2a_handoff", {"to_agent": "root", "task": "x"}),
        (orch, "a2a_handoff", {"to_agent": "config-analyst", "task": ""}),
        (build_server("config-analyst"), "read_config", {"name": "a" * 500}),
    ]
    for server, name, kw in bad:
        with pytest.raises(ToolError):
            asyncio.run(server.call_tool(name, kw))


def test_traversal_still_reaches_jail_and_is_logged_with_hint():
    analyst = build_server("config-analyst")
    with pytest.raises(ToolError, match="list_configs"):
        asyncio.run(analyst.call_tool("read_config", {"name": "../../../../etc/passwd"}))
    row = security.events_ledger().read()[-1]
    assert row["verdict"] == "block" and row["control"] == "path-jail"


def test_untrusted_markers():
    analyst = build_server("config-analyst")
    out = run(analyst, "read_config", name="injected.cfg")
    assert out.startswith("[LAB NOTICE") and "<<<UNTRUSTED workspace file injected.cfg" in out
    assert out.rstrip().endswith("<<<END UNTRUSTED>>>")
    env = run(build_server("orchestrator"), "a2a_handoff", to_agent="config-analyst", task="lint edge-fw.cfg")
    got = run(analyst, "a2a_receive", envelope_json=env)
    assert got.startswith("VERIFIED task from orchestrator:\n<<<UNTRUSTED task")


def test_json_tools_return_valid_json_after_redaction():
    analyst = build_server("config-analyst")
    for f in sorted((security.PROJECT_ROOT / "workspace").glob("*.cfg")):
        for tool in ("lint_config", "parse_acl"):
            out = json.loads(run(analyst, tool, name=f.name))  # raises if redaction broke the JSON
            assert "FAKE_HASH" not in json.dumps(out)


def test_non_object_envelope_is_rejected_cleanly():
    analyst = build_server("config-analyst")
    for bad in ("[]", "123", "not json"):
        with pytest.raises(ToolError, match="BLOCKED by lab control"):
            asyncio.run(analyst.call_tool("a2a_receive", {"envelope_json": bad}))
    assert security.a2a_ledger().verify()[0]
