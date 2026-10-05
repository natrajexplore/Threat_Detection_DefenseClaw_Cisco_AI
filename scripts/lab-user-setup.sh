#!/usr/bin/env bash
# Step 2 of 2 — run as the lab user (NOT root) from the repo root:
#   bash scripts/lab-user-setup.sh
# Installs Node (via nvm, user-local), OpenClaw, uv, the lab tooling and DefenseClaw.
# Interactive steps (OpenClaw onboarding, provider API key) are printed for you to run.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE_MAJOR="${NODE_MAJOR:-26}"   # OpenClaw requires Node 24.16+ or 26.1+ (docs.openclaw.ai/install)

if [[ $EUID -eq 0 ]]; then echo "Run as the lab user, not root." >&2; exit 1; fi
cd "$REPO"

echo "==> Node.js $NODE_MAJOR via nvm (user-local, no sudo)"
export NVM_DIR="$HOME/.nvm"
if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi
# shellcheck disable=SC1091
. "$NVM_DIR/nvm.sh"
nvm install "$NODE_MAJOR"
nvm alias default "$NODE_MAJOR"
node --version

echo "==> OpenClaw"
if ! command -v openclaw >/dev/null; then
  npm install -g openclaw@latest --allow-scripts=openclaw
fi
openclaw --version

echo "==> uv + lab tooling"
if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
uv sync
uv run pytest -q

echo "==> Lab secrets (.env, mode 600)"
if [[ ! -f .env ]]; then
  cp .env.example .env
  sed -i "s/^DCLAB_A2A_KEY=.*/DCLAB_A2A_KEY=$(uv run dclab genkey)/" .env
  sed -i "s/^DCLAB_DASH_TOKEN=.*/DCLAB_DASH_TOKEN=$(uv run dclab genkey)/" .env
  sed -i "s#^DCLAB_WORKSPACE=.*#DCLAB_WORKSPACE=$REPO/workspace#" .env
  echo "    created .env with fresh A2A key + dashboard token"
fi
chmod 600 .env

echo "==> Canaries"
uv run dclab canary

echo "==> DefenseClaw (official installer; verifies checksums, cosign signature if present)"
if ! command -v defenseclaw >/dev/null; then
  curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash
  export PATH="$HOME/.local/bin:$PATH"
fi
defenseclaw --version || true

cat <<EOF

Automated part done. Now run these interactive steps (see docs/DEMO_RUNBOOK.md §2-§4):

  openclaw onboard --install-daemon      # pick your model provider + key; bind gateway to LOOPBACK, token auth
  openclaw gateway status                # confirm 127.0.0.1
  # merge agents/openclaw.netops.json5 into ~/.openclaw/openclaw.json, copy agent personas, restart gateway
  defenseclaw quickstart --connector openclaw --mode observe --scanner local
  defenseclaw doctor
  uv run dclab preflight
EOF
