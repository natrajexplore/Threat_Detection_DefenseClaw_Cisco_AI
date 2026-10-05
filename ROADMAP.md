# Roadmap

| Phase | Goal | Key tasks | Deliverable | Est. |
|---|---|---|---|---|
| 0 | Prep | Build Ubuntu VM (snapshot it), install Node.js, git, Docker (optional), get an LLM API key | Clean VM snapshot | 0.5 day |
| 1 | OpenClaw baseline | Install + onboard OpenClaw, create NetOps agent, point it at `workspace/` | Working unprotected agent + baseline notes | 0.5–1 day |
| 2 | DefenseClaw observe | Install DefenseClaw, `quickstart --connector openclaw --mode observe`, `doctor` green | First-run report, doctor output | 0.5 day |
| 3 | Attack in observe | Build inert fixtures, run TEST_PLAN categories, record detections | Observe-mode results table | 1–2 days |
| 4 | Enforce | Switch to action, fail-closed, HITL on; rerun all tests | Action-mode results table, block evidence | 1 day |
| 5 | Observability | Audit export, optional Splunk/OTel destination via Docker bundle | Dashboard screenshot / exported events | 1 day |
| 6 | Custom policy (stretch) | Rules for NetOps risks (e.g. block `write mem`, `conf t`, `reload`, credential files) | `policies/` + tests | 1–2 days |
| 7 | Report & publish | Findings report, architecture diagram, LinkedIn post / GitHub README polish | `report/FINDINGS.md`, post | 1 day |

## Milestones
- **M1**: Agent answers questions about `workspace/` configs (baseline).
- **M2**: Every agent LLM call and tool call shows up in `defenseclaw tui`.
- **M3**: ≥1 attack per category detected in observe.
- **M4**: Same attacks blocked or approval-gated in action mode.
- **M5**: Evidence exported and report published.
