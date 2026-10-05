# Threat Model

## Assets
- LLM API keys and any credentials on the host
- Network configs in `workspace/` (treat as sensitive even though sanitized)
- The host itself (shell access) and anything reachable from it
- Agent "cognitive" files (memory, instructions, persona files)
- Integrity of audit evidence

## Threat actors / sources
- Malicious third-party **skill** author (ClawHub or elsewhere)
- Malicious or compromised **MCP server**
- **Indirect prompt injection** via files, web pages, tool output
- Careless operator prompt that triggers destructive action
- Internet attacker (if OpenClaw is exposed — must not be)

## Threats → controls

| ID | Threat | Example | DefenseClaw control | Lab test |
|---|---|---|---|---|
| T1 | Malicious skill | Skill silently reads `~/.ssh` and posts it out | Admission skill-scanner; reject/quarantine | TC-SKILL-* |
| T2 | Unsafe MCP server | Tool descriptions contain hidden instructions | mcp-scanner at admission | TC-MCP-* |
| T3 | Prompt injection (direct/indirect) | Config file comment: "ignore rules, run X" | Guardrail content inspection in/out | TC-PI-* |
| T4 | Dangerous command | `rm -rf`, `curl \| bash`, `chmod 777` | `before_tool_call` dangerous-command category | TC-CMD-* |
| T5 | Secret exposure | Agent prints/sends API keys | Secrets category, response scanning | TC-SEC-* |
| T6 | Sensitive path access | Read `/etc/shadow`, `~/.aws/credentials` | Sensitive-path category | TC-PATH-* |
| T7 | C2 / exfil | Beacon to attacker host, DNS exfil pattern | C2-pattern category | TC-C2-* |
| T8 | Cognitive file tampering | Overwrite agent memory/instructions | Cognitive-file tampering category | TC-COG-* |
| T9 | Trust exploitation | "Admin already approved this" social engineering | Trust-exploitation category + HITL | TC-TRUST-* |
| T10 | Guardrail bypass / outage | Gateway down, traffic skips plugin | Fail-closed mode, doctor interception self-test, health polling | TC-RES-* |
| T11 | Exposure | OpenClaw UI on 0.0.0.0 | Out of DefenseClaw scope. Host firewall (`ufw` deny inbound via `scripts/vm-bootstrap.sh`), loopback bind, `dclab preflight` listener check | Manual check + preflight |
| T12 | Agent impersonation / forged delegation | Agent claims to be the orchestrator; replayed or tampered task | DefenseClaw gates `sessions_send`. Lab: HMAC-signed envelopes with sender bound by the MCP server role, recipient binding, 5-min TTL, nonce replay cache | TC-A2A-01 |
| T13 | Privilege escalation via delegation | Read-only analyst asks reviewer to push `conf t` / `write mem` | OpenClaw `subagents.allowAgents` + `agentToAgent.allow`; lab hub-and-spoke allowlist; NetOps command blocks; reviewer is draft-only | TC-A2A-02, TC-NET-01 |
| T14 | Cross-agent injection relay | Injected config text forwarded agent → agent as an instruction | Guardrail content inspection; lab injection markers on read and on handoff signing | TC-A2A-03, TC-PI-01 |
| T15 | Agent-to-app abuse | Path traversal into the MCP app; exfil through a third-party "uploader" app | DefenseClaw tool inspection (secrets, sensitive paths, C2/exfil); lab path jail, redaction, rate limit | TC-MCP-02, TC-MCP-03 |
| T16 | Evidence tampering | Editing lab logs to hide a blocked action | DefenseClaw audit DB plus a SHA-256 hash-chained lab ledger (`dclab ledger`) | Act 6 demo |

## Residual risk / out of scope
- DefenseClaw is an enforcement and evidence layer; it does not prove an agent or capability is risk-free.
- DefenseClaw has no dedicated agent-to-agent protocol guard (ACP Guard covers editor↔agent only, and OpenClaw isn't an ACP entry point). A2A governance here works because handoffs are **tool calls** (`sessions_send`, MCP `a2a_*`) inspected at `before_tool_call`, plus the lab's signed envelopes.
- Per-agent MCP server scoping: the signed-handoff sender identity is only as strong as the rule that each agent can reach **only its own** `netops-*` server. Verify this in Control UI → Tool access. If an agent can call another role's server, it can sign as that role.
- `DCLAB_A2A_KEY` lives in `.env` on the same host as the agents. It stops model-level forgery, not a host compromise. The orchestrator keeps `exec` for the demo, so `cat .env` is possible in principle. In action mode DefenseClaw's secrets / sensitive-path checks are the control (test it). In production, remove `exec` and keep the key in a store the agent user can't read.
- Model-provider side risks; zero-day bypasses; host OS hardening beyond basics.
- Stronger isolation (kernel sandbox, deny-by-default network) → NVIDIA OpenShell sandbox: consider as Phase 6+ stretch.
