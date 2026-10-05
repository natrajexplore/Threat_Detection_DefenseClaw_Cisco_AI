# Requirements

## 1. Platform

| Item | Requirement | Notes |
|---|---|---|
| OS | **Linux x86_64 / arm64** (this lab: Ubuntu 26.04 LTS VM; 22.04/24.04 also fine) or macOS Apple Silicon | DefenseClaw does **not** support Intel Macs. On native Windows the OpenClaw proxy connector is unsupported — use a Linux VM. |
| CPU / RAM | 4 vCPU, 8 GB RAM minimum (16 GB if running Splunk/OTel in Docker) | |
| Disk | 30 GB+ | Docker images for observability add several GB |
| Network | Outbound HTTPS to your LLM provider and GitHub; **no inbound exposure** of OpenClaw | Keep OpenClaw bound to localhost |
| Isolation | Dedicated VM with snapshots | Attack tests run here only |
| User | Non-root user | DefenseClaw is per-user by design; root install discouraged |

## 2. Software

| Component | Version | Purpose |
|---|---|---|
| OpenClaw | Current release (2026.6.8+ handled by DefenseClaw's undici interception) | The agent runtime being protected |
| Node.js + npm | **24.16+ or 26.1+** (26 recommended, per docs.openclaw.ai/install) | OpenClaw runtime + DefenseClaw TS plugin |
| Lab tooling (`dclab`) | Python 3.11+ via `uv`; deps: `mcp` 2.x, FastAPI, uvicorn, Jinja2 | NetOps MCP apps, evidence capture, dashboard |
| DefenseClaw | Latest release | Governance: Python CLI, Go gateway, OpenClaw plugin, scanners |
| `uv` | Auto-installed by DefenseClaw installer | Provides DefenseClaw's Python runtime |
| git | any recent | Repo + optional source build |
| Docker | optional | Splunk / observability bundles |
| `jq` | any | Reading audit exports |
| `cosign` ≥ 2.0 | optional | Installer verifies release signature when present |

Source build only (not needed for normal install): Python 3.10–3.13, Go 1.26.4+, GNU Make.

## 3. Accounts & secrets

- LLM provider API key (OpenAI / Anthropic / Bedrock / Azure OpenAI / OpenAI-compatible).
- Optional: a second key/model for DefenseClaw's **LLM judge** (contextual detection).
- Optional: Splunk instance or HEC token (Docker bundle is fine for a lab).
- Store all secrets in `.env` (git-ignored) or DefenseClaw's own credential setup — never in the repo.

## 4. Functional requirements

| ID | Requirement |
|---|---|
| FR-01 | OpenClaw agent can read files in `workspace/` and answer config questions. |
| FR-02 | All LLM requests from OpenClaw route through the DefenseClaw guardrail proxy (`:4000`). |
| FR-03 | Every tool call is inspected by the DefenseClaw gateway (`before_tool_call` → `:18970`) before execution. |
| FR-04 | Skills and MCP servers are scanned before being trusted; malicious ones are rejected or quarantined. |
| FR-05 | Observe mode logs findings without blocking; action mode blocks/approval-gates them. |
| FR-06 | HITL: `confirm` verdicts surface an approval request inside OpenClaw with deny-on-timeout. |
| FR-07 | All decisions are recorded in the local audit DB and exportable (`defenseclaw-gateway audit export`). |
| FR-08 | (Optional) Events forwarded to Splunk / OTel destination. |
| FR-09 | (Stretch) Custom rules block NetOps-dangerous actions (config changes, reloads, credential file reads). |
| FR-10 | Multi-agent: orchestrator delegates to config-analyst / change-reviewer via signed, allowlisted handoffs; specialists cannot talk to each other directly. |
| FR-11 | Agent-to-app: agents reach NetOps data only through role-bound MCP servers (read-only, path-jailed, redacted, rate-limited). |
| FR-12 | Local dashboard shows posture, DefenseClaw verdicts, A2A handoffs, lab-control decisions and the test matrix, bound to loopback with token auth. |

## 5. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-01 | Fail-closed in action mode: if DefenseClaw is down, risky actions do not proceed. |
| NFR-02 | `defenseclaw doctor` passes (incl. "OpenClaw interception") before any test session. |
| NFR-03 | Reproducible: setup documented end-to-end; VM snapshot before Phase 3. |
| NFR-04 | No real secrets, IPs, or production configs anywhere in the repo or evidence. |
| NFR-05 | Latency overhead of guardrail measured and recorded (before/after). |

## 6. Skills you'll use / learn

Linux admin, Node/npm basics, YAML/JSON config, OPA-style policy concepts, LLM threat categories (prompt injection, tool abuse, exfiltration), Splunk/OTel basics, writing a security findings report.
