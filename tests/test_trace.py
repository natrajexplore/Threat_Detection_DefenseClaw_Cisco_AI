
import pytest

from openclaw_defenseclaw import lab, security, trace

T0 = 1_791_000_000.0


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(lab, "EVIDENCE", tmp_path / "evidence")
    monkeypatch.setattr(lab, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("DCLAB_A2A_KEY", "a" * 64)
    monkeypatch.setenv("DCLAB_DASH_TOKEN", "t" * 64)
    trace._CACHE.clear()

    sessions = {"sessions": [
        {"sessionId": "s-orch", "agentId": "orchestrator", "sessionStartedAt": int(T0 * 1000)},
        {"sessionId": "s-ana", "agentId": "config-analyst", "sessionStartedAt": int((T0 + 2) * 1000)},
    ]}
    transcripts = {
        # OpenAI-style tool_calls
        "s-orch": {"messages": [
            {"role": "user", "content": "Summarize ACLs in edge-fw.cfg <script>alert(1)</script>", "timestamp": T0},
            {"role": "assistant", "content": "Delegating to the analyst.", "timestamp": T0 + 1,
             "tool_calls": [{"function": {"name": "sessions_send",
                                          "arguments": '{"agent":"config-analyst","message":"lint"}'}}]},
            {"role": "assistant", "content": "Found permit ip any any.", "timestamp": T0 + 9},
        ]},
        # Anthropic-style content parts
        "s-ana": [
            {"type": "message", "message": {"role": "assistant", "content": [
                {"type": "text", "text": "Reading config"},
                {"type": "tool_use", "name": "read_config", "input": {"name": "../../etc/passwd"}}]},
             "timestamp": T0 + 3},
            {"role": "tool", "name": "read_config", "content": "API_KEY=FAKE_KEY_DO_NOT_USE_0000",
             "timestamp": T0 + 4},
        ],
    }

    def fake_openclaw(*args):
        if args[0] == "sessions":
            return sessions, None
        return transcripts.get(args[2]), None

    monkeypatch.setattr(trace, "_openclaw_json", fake_openclaw)
    monkeypatch.setattr(lab, "audit_export", lambda limit=500: ([
        {"timestamp": T0 + 3.5, "verdict": "block", "severity": "high", "tool": "read_config",
         "reason": "sensitive path", "agent_id": "config-analyst"},
        {"timestamp": T0 + 500, "verdict": "allow", "tool": "exec", "reason": "later run"},
    ], None))
    with monkeypatch.context() as m:  # pin the ledger timestamp into the first run
        m.setattr(security.time, "time", lambda: T0 + 3.2)
        security.events_ledger().append({"kind": "tool", "agent": "config-analyst", "tool": "read_config",
                                         "verdict": "block", "reason": "[path-jail] path escapes the workspace"})
    yield


def _first_run():
    runs = trace.build()
    return [r for r in runs if r["start"] < T0 + 100][0], runs


def test_runs_lanes_and_correlation():
    run, runs = _first_run()
    assert len(runs) == 2  # the DefenseClaw event 500s later is its own run
    assert run["lanes"][:3] == ["operator", "orchestrator", "config-analyst"]
    call = next(e for e in run["events"] if e.kind == "tool_call" and e.tool == "read_config")
    assert {"source": "defenseclaw", "verdict": "block", "detail": "sensitive path"} in call.verdicts
    assert call.worst == "block" and run["blocked"] >= 1
    send = next(e for e in run["events"] if e.tool == "sessions_send")
    assert send.target == "config-analyst"
    assert not any(e.kind == "verdict" for e in run["events"])  # matched verdict folded into the call


def test_redaction_in_trace():
    run, _ = _first_run()
    blob = " ".join(e.body + e.raw for e in run["events"])
    assert "FAKE_KEY_DO_NOT_USE" not in blob and "<REDACTED>" in blob


def test_unknown_shapes_do_not_crash():
    assert trace.normalize_transcript_entry("junk", "a", "s", T0) == []
    assert trace.normalize_transcript_entry({"weird": 1}, "a", "s", T0) == []
    assert trace._transcript_entries({"nothing": []}) == []


def test_lane_cap():
    evs = [trace.Event(T0 + i, f"agent{i}", "message", "x") for i in range(14)]
    run = trace.split_runs(evs)[0]
    assert len(run["lanes"]) == trace.MAX_LANES and "other" in run["lanes"]


def test_dashboard_trace_and_export():
    from fastapi.testclient import TestClient
    from openclaw_defenseclaw.dashboard.app import create_app
    c = TestClient(create_app(port=8765), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 5000))
    c.post("/login", data={"token": "t" * 64}, headers={"origin": "http://127.0.0.1:8765"})
    assert c.get("/trace").status_code == 200
    runs = c.get("/p/trace/runs")
    assert runs.status_code == 200 and "blocked" in runs.text
    run, _ = _first_run()
    tl = c.get(f"/p/trace/run/{run['id']}")
    assert tl.status_code == 200
    assert "<script>alert(1)" not in tl.text and "&lt;script&gt;" in tl.text  # escaped
    assert c.get("/p/trace/run/../../etc").status_code == 404
    r = c.post("/a/trace/export", data={"run": run["id"], "tc": "TC-MCP-02"},
               headers={"origin": "http://127.0.0.1:8765"})
    assert r.status_code == 200 and "trace-" in r.text
    files = list(lab.EVIDENCE.glob("*-TC-MCP-02/trace-*.html"))
    assert len(files) == 1
    html = files[0].read_text(encoding="utf-8")
    assert "http://" not in html.split("<body>")[0].replace("http-equiv", "")  # no external loads in <head>
    assert "src=" not in html and "FAKE_KEY_DO_NOT_USE" not in html and "&lt;script&gt;" in html
    assert "/static/" not in html  # nothing the report needs lives on the server
    assert 'class="wire c1 ln-operator"' in html  # agents drawn as cables
    d = c.get(f"/trace/run/{run['id']}/download")
    assert d.status_code == 200 and "attachment" in d.headers["content-disposition"]
    assert c.post("/a/trace/export", data={"run": run["id"], "tc": "../x"},
                  headers={"origin": "http://127.0.0.1:8765"}).status_code == 400
