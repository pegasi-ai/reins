#!/bin/bash
set -e

CLAWREINS_DIR="${HOME}/.openclaw/clawreins"
POLICY_FILE="${CLAWREINS_DIR}/policy.json"

# ─── First-run auto-configuration ────────────────────────────────────────────
if [ ! -f "${POLICY_FILE}" ]; then
  echo "🦞 ClawReins: first run — applying '${CLAWREINS_POLICY}' policy..."
  mkdir -p "${CLAWREINS_DIR}"

  case "${CLAWREINS_POLICY}" in
    permissive)
      FS_WRITE="ALLOW"
      FS_DELETE="ASK"
      SHELL_ACTION="ASK"
      ;;
    strict)
      FS_WRITE="ASK"
      FS_DELETE="DENY"
      SHELL_ACTION="DENY"
      ;;
    *)  # balanced (default)
      FS_WRITE="ASK"
      FS_DELETE="DENY"
      SHELL_ACTION="ASK"
      ;;
  esac

  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  cat > "${POLICY_FILE}" <<EOF
{
  "version": "1.0.0",
  "defaultAction": "ASK",
  "modules": {
    "FileSystem": {
      "read":   { "action": "ALLOW",       "description": "Safe read-only" },
      "write":  { "action": "${FS_WRITE}", "description": "Needs approval" },
      "delete": { "action": "${FS_DELETE}","description": "Destructive op" }
    },
    "Shell": {
      "bash": { "action": "${SHELL_ACTION}", "description": "RCE risk" },
      "exec": { "action": "${SHELL_ACTION}", "description": "RCE risk" }
    },
    "Browser": {
      "navigate":   { "action": "ASK",   "description": "Browser navigation" },
      "screenshot": { "action": "ALLOW", "description": "Safe screenshot" },
      "click":      { "action": "ASK",   "description": "Browser interaction" },
      "type":       { "action": "ASK",   "description": "Browser input" },
      "evaluate":   { "action": "ASK",   "description": "JS execution" }
    },
    "Network": {
      "fetch":   { "action": "ASK", "description": "Outbound request" },
      "request": { "action": "ASK", "description": "Outbound request" }
    },
    "Gateway": {
      "sendMessage": { "action": "ASK", "description": "Message sending" }
    }
  },
  "createdAt": "${NOW}",
  "updatedAt": "${NOW}"
}
EOF

  # Initialize OpenClaw (non-interactive, skip daemon)
  openclaw onboard --install-daemon 2>/dev/null || true

  # Register ClawReins plugin
  openclaw plugins install --link /app 2>/dev/null || true

  echo "✅ ClawReins ready (policy: ${CLAWREINS_POLICY})"
  echo "   Audit log → ${CLAWREINS_DIR}/decisions.jsonl"
  echo ""
fi

exec openclaw "$@"
