"""Readiness view, results tally, 404 page, favicon and copy rules."""
import pathlib

import pytest
from fastapi.testclient import TestClient

from openclaw_defenseclaw import lab, security

ORIGIN = {"origin": "http://127.0.0.1:8765"}
TEMPLATES = pathlib.Path(lab.__file__).parent / "dashboard" / "templates"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(lab, "RESULTS", tmp_path / "results.json")
    monkeypatch.setenv("DCLAB_DASH_TOKEN", "t" * 64)
    monkeypatch.setattr(lab, "health", lambda: {
        "gateway :18970": True, "guardrail :4000": True, "defenseclaw CLI": True,
        "openclaw CLI": True, "lab ledger chain": True, "a2a ledger chain": True})
    from openclaw_defenseclaw.dashboard.app import create_app
    c = TestClient(create_app(port=8765), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 5000))
    c.post("/login", data={"token": "t" * 64}, headers=ORIGIN)
    return c


def test_readiness_reflects_real_state(client):
    steps = lab.readiness()
    states = [s["state"] for s in steps]
    assert states[:3] == ["done", "done", "done"]
    assert states[3] == "todo" and set(states[4:]) == {"waiting"}  # nothing recorded yet
    security.events_ledger().append({"kind": "tool", "agent": "config-analyst", "tool": "lint_config", "verdict": "allow"})
    assert lab.readiness()[3]["state"] == "done"
    html = client.get("/p/readiness").text
    assert "steps complete" in html and 'aria-current="step"' in html


def test_results_tally_counts_recorded_results(client, tmp_path):
    (tmp_path / "results.json").write_text(
        '{"TC-SEC-01": {"observe": {"result": "Pass"}, "action": {"result": "Gap"}}}', encoding="utf-8")
    html = client.get("/p/matrix").text
    total = len(lab.catalog())
    assert f"1 pass, 0 fail, 0 gap, {total - 1} not run" in html
    assert f"0 pass, 0 fail, 1 gap, {total - 1} not run" in html


def test_html_404_for_pages_plain_for_partials(client):
    page = client.get("/no-such-page")
    assert page.status_code == 404 and "Page not found" in page.text and "<code>/no-such-page</code>" in page.text
    part = client.get("/p/does-not-exist")
    assert part.status_code == 404 and "<html" not in part.text


def test_favicon_and_meta(client):
    assert client.get("/static/favicon.svg").status_code == 200
    html = client.get("/").text
    assert 'rel="icon" href="/static/favicon.svg"' in html and 'name="description"' in html


def test_no_em_dashes_in_ui_copy():
    for f in TEMPLATES.glob("*.html"):
        assert "—" not in f.read_text(encoding="utf-8"), f.name
