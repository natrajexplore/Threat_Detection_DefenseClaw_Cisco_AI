# Setup Guide

> Commands for DefenseClaw are taken from the official docs (Oct 2026). Re-check
> https://cisco-ai-defense.github.io/defenseclaw/docs/ before running — the project moves fast.
> OpenClaw install steps change between releases; follow the official OpenClaw docs for §2.

> **Fast path:** `sudo bash scripts/vm-bootstrap.sh`, then as the `netops` user run
> `bash scripts/lab-user-setup.sh`, then follow `docs/DEMO_RUNBOOK.md`. The sections below are the manual equivalent.

## 0. Prepare the VM

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git curl jq
# Docker (optional, for Splunk/OTel in Phase 5)
# Install Node.js at the version your OpenClaw release requires (e.g. via nvm)
```

- Create a **non-root** user for the lab.
- Take a VM snapshot: `00-clean`.

## 1. Clone this repo

```bash
git clone https://github.com/<you>/defenseclaw-openclaw-lab.git
cd defenseclaw-openclaw-lab
cp .env.example .env   # add your LLM key here; .env is git-ignored
```

## 2. OpenClaw baseline (unprotected)

1. Install OpenClaw per its official docs and complete onboarding (model provider + API key).
2. Ensure the OpenClaw gateway/UI listens on **localhost only**.
3. Create a "NetOps assistant" agent; give it file-read access to `./workspace/` and a shell tool.
4. Sanity test: *"Summarize the ACLs in workspace/edge-fw.cfg"*.
5. Record baseline: what tools it can call, what it did without any guardrail → `evidence/baseline/`.
6. Snapshot: `01-openclaw-baseline`.

## 3. Install DefenseClaw

```bash
curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash
defenseclaw --version
```

The installer verifies checksums (and the Sigstore signature if `cosign` ≥ 2.0 is present), installs `uv`, and creates `~/.defenseclaw/`.

## 4. First run — attach to OpenClaw in observe mode

Option A (guided):
```bash
defenseclaw init
```
Note: OpenClaw is a *proxy* connector, so the wizard may point you to `defenseclaw setup openclaw` instead of including it in the observe-all set.

Option B (scripted, recommended for this lab):
```bash
defenseclaw quickstart --connector openclaw --mode observe --scanner local
```

Expect a first-run report with `status ok`, `gateway running on 127.0.0.1:18970`, audit DB at `~/.defenseclaw/audit.db`.

Alternative plugin path (if your gateway is already running): install the ClawHub plugin
```bash
openclaw plugins install clawhub:@defenseclaw/openclaw-plugin
```
and set `sidecarHost=127.0.0.1`, `sidecarPort=18970`, `guardrailPort=4000` in OpenClaw plugin settings.

## 5. Verify interception

```bash
defenseclaw doctor            # must show OpenClaw interception OK
defenseclaw doctor --passive  # no billable probes
```
If agent turns work but doctor says traffic is **not intercepted**, restart OpenClaw so the plugin reloads, then rerun doctor.

Open the live dashboard and send a prompt through OpenClaw:
```bash
defenseclaw tui
```
You should see the LLM call and any tool calls appear. Snapshot: `02-defenseclaw-observe`.

## 6. Run attack tests (observe) → `docs/TEST_PLAN.md`

Export evidence after each test:
```bash
mkdir -p evidence/$(date +%F)-TC-XXX
defenseclaw-gateway audit export --output - | tail -n 200 | jq . > evidence/$(date +%F)-TC-XXX/audit.json
```

## 7. Switch to enforcement

```bash
defenseclaw quickstart --connector openclaw --mode action --fail-mode closed \
  --human-approval --hilt-min-severity medium --force
defenseclaw doctor
```
(Optional) add the LLM judge with `--with-judge` once you have a judge model configured. Full tuning: `defenseclaw setup guardrail` (see Guardrail setup docs). Rerun the whole test plan.

## 8. Observability (optional)

- Configure an explicit destination (Splunk / OTel / JSONL) in the v8 observability config — JSONL is no longer an implicit mirror.
- Use the Docker Splunk bundle for a local lab. Screenshot dashboards into `evidence/observability/`.

## 9. Teardown

```bash
defenseclaw uninstall --dry-run   # preview
defenseclaw uninstall             # reversible; restores openclaw.json
```
Or simply revert the VM snapshot.

## Troubleshooting

| Symptom | Check |
|---|---|
| `status needs_attention` on first run | Follow the exact next command printed (missing key, port in use) |
| Port 18970 / 4000 in use | `ss -ltnp \| grep -E '18970\|4000'` |
| Calls not in TUI | `defenseclaw doctor`; restart OpenClaw; confirm plugin entry in `~/.openclaw/openclaw.json` |
| Action connector downgraded to observe | Installed OpenClaw version not mapped to a known hook contract — upgrade DefenseClaw/OpenClaw rather than forcing drift override |
