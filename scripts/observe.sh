#!/usr/bin/env bash
# Launch the read-only Lab Observer MCP server (stdio) for Claude Code.
# Called over SSH, which starts a non-interactive shell without the user's PATH,
# so set it explicitly. stdout is the MCP channel: nothing else may print to it.
set -euo pipefail
cd "$(dirname "$0")/.."
export NVM_DIR="$HOME/.nvm"
# shellcheck disable=SC1091
[[ -s "$NVM_DIR/nvm.sh" ]] && . "$NVM_DIR/nvm.sh" >/dev/null 2>&1
export PATH="$HOME/.local/bin:$PATH"
exec uv run --quiet dclab observe
