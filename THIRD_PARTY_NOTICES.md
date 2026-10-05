# Third-party notices

This project's own code and docs are MIT-licensed (see [`LICENSE`](LICENSE)).

## Bundled in this repository

### htmx 2.0.4
- File: `src/openclaw_defenseclaw/dashboard/static/htmx.min.js` (vendored unmodified so the dashboard loads no scripts from a CDN)
- Source: https://github.com/bigskysoftware/htmx
- License: Zero-Clause BSD (0BSD)

```
Zero-Clause BSD
=============

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono
- Files: `src/openclaw_defenseclaw/dashboard/static/fonts/atkinson-next.woff2`, `atkinson-mono.woff2` (Latin subset, unmodified, self-hosted so the dashboard's CSP can block all external loads)
- Source: https://github.com/googlefonts/atkinson-hyperlegible-next and https://github.com/googlefonts/atkinson-hyperlegible-next-mono (Braille Institute of America)
- License: SIL Open Font License 1.1. Full text in [`fonts/OFL.txt`](src/openclaw_defenseclaw/dashboard/static/fonts/OFL.txt) (Next) and [`fonts/OFL-mono.txt`](src/openclaw_defenseclaw/dashboard/static/fonts/OFL-mono.txt) (Mono)
- Copyright 2020-2024 The Atkinson Hyperlegible Next Project Authors; Copyright 2020-2024 The Atkinson Hyperlegible Mono Project Authors

## Installed separately (not distributed here)

These are installed by `uv sync` or the setup scripts from their own sources, under their own licenses. This repository does not redistribute them:

| Component | Used for | License (per upstream) |
|---|---|---|
| Cisco DefenseClaw | Governance layer under test | Apache-2.0 |
| OpenClaw | Agent runtime under test | See https://docs.openclaw.ai |
| Python packages (`mcp`, `fastapi`, `uvicorn`, `jinja2`, `python-multipart`, `pytest`, `httpx` and their dependencies) | Lab tooling and tests | Each package's own license; see `uv.lock` for exact versions |
| nvm, Node.js, uv | Toolchain installed by `scripts/lab-user-setup.sh` | Each project's own license |
