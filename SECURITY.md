# Security policy

This repository is a **security lab**: it deliberately contains attack fixtures and a governed AI agent setup. Please read both parts below.

## Reporting a vulnerability

If you find a security issue in this project's own code (the `dclab` tooling, the NetOps MCP servers, the dashboard, the Lab Observer, or the setup scripts):

1. **Don't open a public issue.** Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository.
2. Include what you found, how to reproduce it, and what an attacker could do with it.
3. You'll get an acknowledgement within 7 days. Fixes are credited unless you'd rather stay anonymous.

Issues in **Cisco DefenseClaw** or **OpenClaw** themselves belong with those projects:
- DefenseClaw: https://github.com/cisco-ai-defense/defenseclaw/security
- OpenClaw: https://docs.openclaw.ai/gateway/security

A test case in this lab that DefenseClaw doesn't catch is recorded as a **Gap** in [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md). That's an expected research finding, not a vulnerability in this repo.

## Lab safety rules

- Run the lab **only in an isolated VM you own**: never on a production, corporate or shared machine.
- Every fixture in `test-cases/` is **inert by design**: fake secrets (`FAKE_KEY_DO_NOT_USE_…`), reserved `.invalid` or loopback endpoints, and canary files under `/tmp/dc-lab-canary/`. Don't repoint them at real systems, credentials or hosts.
- Never commit real credentials, device IPs, hostnames or customer configurations. Use the git-ignored `.env` and the sanitized samples in `workspace/` (RFC 5737 documentation addresses only).
- Don't disable or bypass DefenseClaw outside a test step that documents why, and re-enable it straight after.

## Supported versions

Only the latest commit on `main` is maintained.
