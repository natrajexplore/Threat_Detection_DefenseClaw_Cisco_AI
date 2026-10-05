"""UX/accessibility guarantees from the ui-ux-pro-max review (WCAG 2.2 AA oriented)."""
import re

import pytest
from fastapi.testclient import TestClient

from openclaw_defenseclaw import security

ORIGIN = {"origin": "http://127.0.0.1:8765"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "STATE_DIR", tmp_path)
    monkeypatch.setenv("DCLAB_DASH_TOKEN", "t" * 64)
    from openclaw_defenseclaw.dashboard.app import create_app
    c = TestClient(create_app(port=8765), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 5000))
    return c


def login(c):
    c.post("/login", data={"token": "t" * 64}, headers=ORIGIN)


def test_skip_link_and_main_landmark(client):
    login(client)
    for path in ("/", "/trace"):
        html = client.get(path).text
        assert '<a class="skip" href="#main">' in html and 'id="main"' in html


def test_login_supports_password_managers_and_links_error(client):
    html = client.get("/login").text
    assert 'autocomplete="current-password"' in html and 'autocomplete="off"' not in html
    err = client.get("/login?error=1").text
    assert 'aria-invalid="true"' in err and 'id="token-error"' in err and "token-error" in err.split('aria-describedby="')[1]


def test_htmx_history_cache_disabled(client):
    assert '"historyCacheSize":0' in client.get("/login").text


def test_status_lights_state_in_words_not_colour_only(client):
    login(client)
    html = client.get("/p/health").text
    states = re.findall(r'<span class="state">([^<]+)</span>', html)
    assert states and all(s.strip() for s in states)
    assert {"up", "down"} & set(states) or {"installed", "missing"} & set(states)


def test_polling_panels_are_not_live_regions(client):
    login(client)
    html = client.get("/").text
    assert 'id="health" hx-get="/p/health" hx-trigger="load, every 5s">' in html  # no aria-live on a 5 s poll


def test_evidence_form_has_visible_labels(client):
    login(client)
    html = client.get("/p/case/TC-SEC-01").text
    for fid in ("ev-mode", "ev-result", "ev-notes"):
        assert f'<label for="{fid}">' in html
    assert 'hx-disabled-elt="find button"' in html


def test_trace_deep_link_is_validated(client):
    login(client)
    assert 'data-initial-run="1791000000"' in client.get("/trace?run=1791000000").text
    bad = client.get('/trace?run="><script>alert(1)</script>').text
    assert 'data-initial-run=""' in bad and "<script>alert(1)" not in bad
