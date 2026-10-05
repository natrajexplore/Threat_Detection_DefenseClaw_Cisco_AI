# DefenseClaw × OpenClaw Security Lab

A hands-on project that deploys an **OpenClaw** AI agent and secures it with **Cisco DefenseClaw**, then proves the controls work by running controlled attack scenarios (malicious skills, unsafe MCP servers, prompt injection, dangerous shell commands, secret exfiltration) and capturing the evidence.

> Use case: a **multi-agent NetOps Assistant**. An *orchestrator* delegates over signed, allowlisted handoffs to a read-only *config-analyst* and a draft-only *change-reviewer*. The agents reach data only through role-bound **NetOps MCP apps**. DefenseClaw governs everything they load, say, and execute, and a local dashboard shows it live.
>
> **Running the team demo? Start at [`docs/DEMO_RUNBOOK.md`](docs/DEMO_RUNBOOK.md).**

## Why this project

OpenClaw moved AI from "chat" to "act": it connects a model to tools, skills, MCP servers, and a live workspace. That power created a real attack surface (exposed instances, malicious third-party skills, prompt injection). DefenseClaw is Cisco's open-source governance layer for OpenClaw: it scans capabilities before use, inspects runtime traffic, enforces policy, and exports audit evidence (including to Splunk).

This lab shows you can **deploy, harden, attack, and evidence** an agentic AI runtime — a strong portfolio piece for AI-security / Zero Trust roles.

## Goals

1. Run a working OpenClaw agent (baseline, unprotected) in an isolated VM.
2. Install DefenseClaw, attach it to OpenClaw, start in **observe** mode.
3. Execute a defined attack test plan and record what was *seen*.
4. Switch to **action** mode with fail-closed + human-in-the-loop (HITL) and record what was *blocked*.
5. Export telemetry (local audit DB → optional Splunk/OTel) and build a findings report.
6. (Stretch) Write custom policy/rules for network-ops specific risks.

## Repository layout

```
defenseclaw-openclaw-lab/
├── README.md                 ← you are here
├── AGENTS.md                 ← rules for any AI coding agent working in this repo
├── ROADMAP.md                ← phases, milestones, deliverables
├── docs/
│   ├── REQUIREMENTS.md       ← hardware, software, accounts, functional/non-functional reqs
│   ├── ARCHITECTURE.md       ← components, data flow, ports, trust boundaries
│   ├── SETUP.md              ← step-by-step build guide
│   ├── THREAT_MODEL.md       ← assets, threats, controls mapping
│   ├── TEST_PLAN.md          ← attack scenarios, expected results, evidence checklist
│   └── DEMO_RUNBOOK.md       ← VM → working lab → 25-min team demo
├── agents/                   ← orchestrator / config-analyst / change-reviewer personas + openclaw.netops.json5
├── scripts/                  ← vm-bootstrap.sh (root, once) + lab-user-setup.sh (lab user)
├── src/openclaw_defenseclaw/ ← `dclab` CLI, NetOps MCP server, security controls, dashboard
├── tests/                    ← unit tests for controls, MCP roles, dashboard hardening
├── workspace/                ← sample (sanitized, RFC 5737 IPs, fake secrets) configs the agents read
├── test-cases/               ← catalog.json + inert fixtures (skills, MCP stubs)
├── policies/                 ← custom DefenseClaw policy / rule overrides (stretch)
├── evidence/                 ← audit exports, screenshots, TUI captures
└── report/                   ← final findings report
```

## Quick start (Ubuntu 26.04 VM; full steps in `docs/DEMO_RUNBOOK.md`)

```bash
sudo bash scripts/vm-bootstrap.sh          # creates non-root 'netops' login, ufw deny-inbound
# log in as netops, repo at ~/defenseclaw-openclaw-lab
bash scripts/lab-user-setup.sh             # Node 26, OpenClaw, uv, dclab, DefenseClaw, .env (600), canaries
openclaw onboard --install-daemon          # loopback bind + token auth
defenseclaw quickstart --connector openclaw --mode observe --scanner local
uv run dclab preflight                     # all PASS before testing
uv run dclab dashboard                     # http://127.0.0.1:8765
```

`dclab` commands: `preflight`, `canary [--verify]`, `cases`, `show <TC>`, `evidence <TC> --mode observe|action [--result]`, `trace [--export RUN|latest --tc TC]`, `ledger`, `genkey`, `mcp --role <agent>`, `observe`, `dashboard`.

**Lab Observer (`dclab observe`)** is a read-only MCP server that lets Claude Code query lab status, test results, evidence, conversation runs and verdicts over SSH stdio. See `docs/DEMO_RUNBOOK.md` §4.

The dashboard's **Conversation trace** view shows each run end to end: operator → orchestrator → specialists → NetOps apps, with the DefenseClaw and lab-control verdict on every tool call. It has a step-by-step **replay** mode for live demos and **exports a single offline HTML report** for the team. See `docs/DEMO_RUNBOOK.md` §4.

Manual DefenseClaw-only path (from `docs/SETUP.md`):

```bash
# 1. OpenClaw installed and working (baseline) — see docs/SETUP.md §2
# 2. Install DefenseClaw (macOS arm64 / Linux x86_64|arm64)
curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash
# 3. First run, guarding OpenClaw, observe mode
defenseclaw quickstart --connector openclaw --mode observe
# 4. Verify
defenseclaw doctor
defenseclaw tui
```

## References

- DefenseClaw repo: https://github.com/cisco-ai-defense/defenseclaw
- DefenseClaw docs: https://cisco-ai-defense.github.io/defenseclaw/docs/
- OpenClaw integration guide: https://cisco-ai-defense.github.io/defenseclaw/docs/openclaw/
- Cisco blog — OpenClaw security + hands-on lab: https://blogs.cisco.com/ai/openclaw-ai-agent-security

## Status

| Phase | Status |
|---|---|
| 0 – Prep & isolated VM | ☐ |
| 1 – OpenClaw baseline | ☐ |
| 2 – DefenseClaw observe | ☐ |
| 3 – Attack tests (observe) | ☐ |
| 4 – Action mode + HITL | ☐ |
| 5 – Observability | ☐ |
| 6 – Custom policy (stretch) | ☐ |
| 7 – Report & publish | ☐ |

## License

Lab code/docs: your choice (MIT suggested). DefenseClaw itself is Apache-2.0 (Cisco).
