"""Local NetOps security dashboard (FastAPI + HTMX). Loopback-only, token-gated."""

from __future__ import annotations

import hmac
import ipaddress
import os
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import lab
from ..security import a2a_ledger, events_ledger

HERE = Path(__file__).parent
COOKIE = "dclab_session"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")


def create_app(port: int = 8765) -> FastAPI:
    token = os.environ["DCLAB_DASH_TOKEN"]
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")  # autoescape on for .html

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
            "Referrer-Policy": "no-referrer",
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

    return app
