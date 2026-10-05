"""Local NetOps security dashboard (FastAPI + HTMX). Loopback-only, token-gated."""

from __future__ import annotations

import base64
import datetime as dt
import hmac
import ipaddress
import os
import re
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import lab, trace
from ..security import a2a_ledger, events_ledger

HERE = Path(__file__).parent
COOKIE = "dclab_session"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")


def _fmt_ts(v: float) -> str:
    return dt.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_hms(v: float) -> str:
    return dt.datetime.fromtimestamp(v).strftime("%H:%M:%S")


def _add_filters(env: Environment) -> Environment:
    env.filters["ts"] = _fmt_ts
    env.filters["hms"] = _fmt_hms
    return env


def _inline_fonts(css: str) -> str:
    """Swap /static/fonts/*.woff2 URLs for data: URIs so the offline report keeps its typography."""
    def repl(m: re.Match) -> str:
        data = (HERE / "static" / "fonts" / m.group(1)).read_bytes()
        return f'url("data:font/woff2;base64,{base64.b64encode(data).decode()}")'
    return re.sub(r'url\("/static/fonts/([A-Za-z0-9._-]+\.woff2)"\)', repl, css)


def render_trace_report(run: dict, tc: str = "") -> str:
    """Self-contained offline HTML report (inline CSS/JS/fonts, no network, redacted content)."""
    env = _add_filters(Environment(loader=FileSystemLoader(HERE / "templates"),
                                   autoescape=select_autoescape(["html"])))
    return env.get_template("trace_export.html").render(
        run=run, tc=tc, exportable=False, live=False, cases=[],
        generated=_fmt_ts(time.time()),
        css=_inline_fonts((HERE / "static" / "app.css").read_text(encoding="utf-8")),
        js=(HERE / "static" / "trace.js").read_text(encoding="utf-8").replace("</", "<\\/"))


def save_trace_report(run: dict, tc: str = "") -> Path:
    if tc and not lab.TC_ID.match(tc):
        raise ValueError("bad test id")
    if tc:
        lab.case(tc)
        out = lab.EVIDENCE / f"{dt.date.today():%Y-%m-%d}-{tc}"
    else:
        out = lab.EVIDENCE / "traces"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"trace-{run['id']}.html"
    path.write_text(render_trace_report(run, tc), encoding="utf-8")
    return path


def create_app(port: int = 8765) -> FastAPI:
    token = os.environ["DCLAB_DASH_TOKEN"]
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")  # autoescape on for .html
    _add_filters(tpl.env)

    def authed(request: Request) -> bool:
        return hmac.compare_digest(request.cookies.get(COOKIE, ""), token)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        client = request.client.host if request.client else ""
        try:
            loopback = ipaddress.ip_address(client).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            return Response("loopback only", status_code=403)
        if request.headers.get("host", "") not in allowed_hosts:  # DNS-rebinding guard
            return Response("bad host", status_code=421)
        if request.method == "POST" and request.headers.get("origin") not in allowed_origins:
            return Response("bad origin", status_code=403)  # CSRF guard (plus SameSite=Strict)
        public = request.url.path.startswith("/static") or request.url.path == "/login"
        if not public and not authed(request):
            if request.headers.get("hx-request"):
                return Response(status_code=401, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", status_code=303)
        resp = await call_next(request)
        resp.headers.update({
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            # Not "no-referrer": with that policy browsers send `Origin: null` on form POSTs
            # (login/logout), which the Origin check above rightly rejects.
            "Referrer-Policy": "same-origin",
            "Cache-Control": "no-store",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        return resp

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, error: str = ""):
        return tpl.TemplateResponse(request, "login.html", {"error": error})

    @app.post("/login")
    def login(token_in: str = Form(alias="token")):
        if not hmac.compare_digest(token_in.strip(), token):
            return RedirectResponse("/login?error=1", status_code=303)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=8 * 3600)
        return resp

    @app.post("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return tpl.TemplateResponse(request, "index.html", {"cases": lab.catalog()})

    @app.get("/p/health", response_class=HTMLResponse)
    def p_health(request: Request):
        return tpl.TemplateResponse(request, "_health.html", {
            "health": lab.health(), "canary": lab.canary_status(),
            "enforce": os.environ.get("DCLAB_ENFORCE", "1") != "0"})

    @app.get("/p/verdicts", response_class=HTMLResponse)
    def p_verdicts(request: Request):
        events, err = lab.audit_export(limit=60)
        rows = [lab.summarize_event(e) for e in reversed(events)]
        return tpl.TemplateResponse(request, "_verdicts.html", {"rows": rows, "error": err})

    @app.get("/p/lab", response_class=HTMLResponse)
    def p_lab(request: Request):
        return tpl.TemplateResponse(request, "_lab.html", {"rows": list(reversed(events_ledger().read(60)))})

    @app.get("/p/a2a", response_class=HTMLResponse)
    def p_a2a(request: Request):
        return tpl.TemplateResponse(request, "_a2a.html", {"rows": a2a_ledger().read(40)})

    @app.get("/p/matrix", response_class=HTMLResponse)
    def p_matrix(request: Request):
        return tpl.TemplateResponse(request, "_matrix.html", {"cases": lab.catalog(), "results": lab.results()})

    @app.get("/p/case/{tc_id}", response_class=HTMLResponse)
    def p_case(request: Request, tc_id: str):
        try:
            c = lab.case(tc_id)
        except KeyError:
            return HTMLResponse("unknown test", status_code=404)
        return tpl.TemplateResponse(request, "_case.html", {"c": c})

    @app.post("/a/canary", response_class=HTMLResponse)
    def a_canary(request: Request):
        lab.canary_create()
        return p_health(request)

    @app.post("/a/evidence/{tc_id}", response_class=HTMLResponse)
    def a_evidence(request: Request, tc_id: str, mode: str = Form(...), result: str = Form(""),
                   notes: str = Form("")):
        if mode not in ("observe", "action") or result not in ("", "Pass", "Fail", "Gap"):
            return HTMLResponse("bad input", status_code=400)
        try:
            out = lab.capture_evidence(tc_id, mode, result or None, notes[:500])
        except (KeyError, ValueError) as exc:
            return HTMLResponse(f"error: {exc}", status_code=400)
        return tpl.TemplateResponse(request, "_saved.html", {"path": out.relative_to(lab.PROJECT_ROOT)})

    # ------------------------------------------------------------ conversation trace

    run_id_rx = re.compile(r"^\d{1,12}$")

    @app.get("/trace", response_class=HTMLResponse)
    def trace_page(request: Request, run: str = ""):
        # Deep link (/trace?run=<id>); anything that isn't a plain run id is ignored.
        initial = run if run_id_rx.match(run) else ""
        return tpl.TemplateResponse(request, "trace.html", {"live": True, "initial_run": initial})

    @app.get("/p/trace/runs", response_class=HTMLResponse)
    def p_trace_runs(request: Request):
        errors: list[str] = []
        runs = trace.build(errors)
        return tpl.TemplateResponse(request, "_trace_runs.html", {"runs": runs[:50], "errors": errors})

    @app.get("/p/trace/run/{run_id}", response_class=HTMLResponse)
    def p_trace_run(request: Request, run_id: str):
        run = trace.run_by_id(run_id) if run_id_rx.match(run_id) else None
        if run is None:
            return HTMLResponse("<p class='muted'>Run not found (it may have rolled into a newer run).</p>",
                                status_code=404)
        return tpl.TemplateResponse(request, "_trace_timeline.html",
                                    {"run": run, "exportable": True, "cases": lab.catalog()})

    @app.post("/a/trace/export", response_class=HTMLResponse)
    def a_trace_export(request: Request, run: str = Form(...), tc: str = Form("")):
        found = trace.run_by_id(run) if run_id_rx.match(run) else None
        if found is None:
            return HTMLResponse("run not found", status_code=404)
        try:
            path = save_trace_report(found, tc)
        except (KeyError, ValueError) as exc:
            return HTMLResponse(f"error: {exc}", status_code=400)
        return tpl.TemplateResponse(request, "_trace_saved.html", {"path": path.relative_to(lab.PROJECT_ROOT)})

    @app.get("/trace/run/{run_id}/download")
    def trace_download(run_id: str):
        found = trace.run_by_id(run_id) if run_id_rx.match(run_id) else None
        if found is None:
            return HTMLResponse("run not found", status_code=404)
        return Response(render_trace_report(found), media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="netops-trace-{run_id}.html"'})

    return app
