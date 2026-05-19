#!/usr/bin/env bash
# dev-local.sh — build reins and wire it to a local Watchtower instance
# Usage: ./scripts/dev-local.sh [--no-hooks] [--base-url http://localhost:5174]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REINS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_URL="http://localhost:5174"
INSTALL_HOOKS=true

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --no-hooks) INSTALL_HOOKS=false; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

cd "$REINS_DIR"

echo "▶ Building..."
npm run build

echo "▶ Smoke-testing CLI..."
node dist/cli/index.js --help > /dev/null && echo "  CLI OK"

echo "▶ Setting local env..."
export REINS_INTERNAL=1
export REINS_INTERNAL_BASE_URL_LOCAL="$BASE_URL"
echo "  REINS_INTERNAL=1"
echo "  REINS_INTERNAL_BASE_URL_LOCAL=$BASE_URL"

echo "▶ Pointing reins at local Watchtower..."
node dist/cli/index.js internal-base-url local 2>/dev/null || \
  echo "  (internal-base-url command not available — skipping)"

echo "▶ Clearing stale credentials (switching to local)..."
node -e "
  const fs = require('fs-extra');
  const os = require('os');
  const path = require('path');

  // Resolve config path the same way data-dir does
  const openclawHome = process.env.OPENCLAW_HOME
    || (fs.existsSync(path.join(os.homedir(), '.openclaw')) ? path.join(os.homedir(), '.openclaw') : null)
    || (fs.existsSync(path.join(os.homedir(), '.claude'))   ? path.join(os.homedir(), '.claude')   : null)
    || path.join(os.homedir(), '.openclaw');

  const configPath = path.join(openclawHome, 'reins', 'config.json');
  const authPath   = path.join(openclawHome, 'reins', 'auth-session.json');

  if (fs.existsSync(configPath)) {
    const cfg = fs.readJsonSync(configPath);
    if (cfg.watchtower) {
      delete cfg.watchtower.apiKey;
      delete cfg.watchtower.connectedAt;
      delete cfg.watchtower.email;
    }
    fs.writeJsonSync(configPath, cfg, { spaces: 2 });
    console.log('  Cleared apiKey from', configPath);
  }

  if (fs.existsSync(authPath)) {
    fs.removeSync(authPath);
    console.log('  Removed auth session:', authPath);
  }
"

if $INSTALL_HOOKS; then
  echo "▶ Installing hooks into ~/.claude/settings.json..."
  node -e "
    const { installClaudeCodeHooks } = require('./dist/lib/hook-installer');
    installClaudeCodeHooks({ global: true }).then(r => {
      console.log('  Installed to:', r.installedPaths.join(', ') || 'none');
      console.log('  Already installed:', r.alreadyInstalled);
    });
  "
fi

echo ""
echo "✓ Ready. Restart Claude Code to pick up the new hooks."
echo ""
echo "  Next steps:"
echo "    node dist/cli/index.js init        # authenticate against $BASE_URL"
echo "    node dist/cli/index.js status      # verify connection"
echo "    reins audit -n 5                   # view recent decisions"
