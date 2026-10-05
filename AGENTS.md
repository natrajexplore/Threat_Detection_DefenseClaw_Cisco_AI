# AGENTS.md — Rules for AI coding agents in this repo

These rules apply to Claude Code, Codex, OpenClaw, or any agent editing this repository.

## Context
- This is a **security lab**. The goal is to demonstrate DefenseClaw controlling an OpenClaw agent.
- Source of truth for DefenseClaw commands/config: https://cisco-ai-defense.github.io/defenseclaw/docs/ — check it before writing commands. Do not invent CLI flags.

## Hard rules
1. **Never** put real credentials, API keys, device IPs, hostnames, or customer configs in the repo. Use `.env` (git-ignored) and sanitized samples in `workspace/`.
2. Attack fixtures in `test-cases/` must be **inert**: they target disposable paths (e.g. `/tmp/dc-lab-canary/`), fake secrets (`FAKE_KEY_DO_NOT_USE_...`), and non-routable/loopback endpoints. No working malware, no real exfil endpoints.
3. Do not disable or bypass DefenseClaw (e.g. hook-contract drift overrides, removing the plugin) except inside a test step that explicitly documents why, and re-enable immediately.
4. Do not run the lab on a production or corporate machine. VM/sandbox only.
5. Every test run must write evidence to `evidence/<date>-<test-id>/`.

## Conventions
- Markdown docs in `docs/`, one topic per file.
- Test IDs: `TC-<category>-<nn>` (e.g. `TC-SKILL-01`). Keep `docs/TEST_PLAN.md` in sync.
- Commit messages: `<area>: <change>` (e.g. `tests: add TC-MCP-02 unsafe MCP stub`).

## Definition of done for a test case
- Fixture exists in `test-cases/`
- Expected result written in TEST_PLAN.md (observe + action)
- Evidence captured (audit export snippet + screenshot/TUI capture)
- Result row updated (Pass / Fail / Gap)
