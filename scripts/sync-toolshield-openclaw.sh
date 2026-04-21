#!/usr/bin/env bash
set -euo pipefail

TOOLSHIELD_DIR="${TOOLSHIELD_DIR:-$HOME/ToolShield}"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
AGENTS_FILE="${AGENTS_FILE:-$OPENCLAW_HOME/workspace/AGENTS.md}"
MODEL="${TOOLSHIELD_MODEL:-claude-sonnet-4.5}"
DO_BACKUP=1
UNLOAD_FIRST=1
IMPORT_ALL=1
EXP_FILES=()

usage() {
  cat <<'EOF'
Sync ToolShield experiences into OpenClaw AGENTS.md (idempotent by default).

Usage:
  sync-toolshield-openclaw.sh [options]

Options:
  --toolshield-dir <dir>   Path to ToolShield repo (default: ~/ToolShield)
  --agents-file <path>     Target AGENTS.md path (default: ~/.openclaw/workspace/AGENTS.md)
  --model <name>           Bundled ToolShield model (default: claude-sonnet-4.5)
  --exp-file <name|path>   Import one experience (repeatable); disables --all
  --all                    Import all bundled experiences for --model (default)
  --append                 Skip unload; append to existing guidelines
  --no-backup              Skip AGENTS.md / policy.json backup
  -h, --help               Show this help

Environment overrides:
  TOOLSHIELD_DIR, OPENCLAW_HOME, AGENTS_FILE, TOOLSHIELD_MODEL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --toolshield-dir)
      TOOLSHIELD_DIR="${2:-}"
      shift 2
      ;;
    --agents-file)
      AGENTS_FILE="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
      ;;
    --exp-file)
      EXP_FILES+=("${2:-}")
      IMPORT_ALL=0
      shift 2
      ;;
    --all)
      IMPORT_ALL=1
      shift
      ;;
    --append)
      UNLOAD_FIRST=0
      shift
      ;;
    --no-backup)
      DO_BACKUP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -d "$TOOLSHIELD_DIR" ]]; then
  echo "ToolShield repo not found: $TOOLSHIELD_DIR" >&2
  echo "Clone it first, e.g.: git clone https://github.com/CHATS-lab/ToolShield.git ~/ToolShield" >&2
  exit 1
fi

if ! command -v python >/dev/null 2>&1; then
  echo "python is required to run ToolShield CLI." >&2
  exit 1
fi

mkdir -p "$(dirname "$AGENTS_FILE")"
touch "$AGENTS_FILE"

POLICY_FILE="$OPENCLAW_HOME/reins/policy.json"
if [[ "$DO_BACKUP" -eq 1 ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  BACKUP_DIR="$OPENCLAW_HOME/reins/backups/$TS"
  mkdir -p "$BACKUP_DIR"

  cp "$AGENTS_FILE" "$BACKUP_DIR/AGENTS.md.before"
  if [[ -f "$POLICY_FILE" ]]; then
    cp "$POLICY_FILE" "$BACKUP_DIR/policy.json.before"
  fi
  echo "Checkpoint backup: $BACKUP_DIR"
fi

run_toolshield() {
  (
    cd "$TOOLSHIELD_DIR"
    python -m toolshield.cli "$@"
  )
}

if [[ "$UNLOAD_FIRST" -eq 1 ]]; then
  run_toolshield unload --agent openclaw --source_location "$AGENTS_FILE" || true
fi

if [[ "$IMPORT_ALL" -eq 1 ]]; then
  run_toolshield import --all --model "$MODEL" --agent openclaw --source_location "$AGENTS_FILE"
else
  if [[ "${#EXP_FILES[@]}" -eq 0 ]]; then
    echo "No experiences specified. Use --all or --exp-file." >&2
    exit 1
  fi
  for exp_file in "${EXP_FILES[@]}"; do
    run_toolshield import --exp-file "$exp_file" --model "$MODEL" --agent openclaw --source_location "$AGENTS_FILE"
  done
fi

echo "ToolShield sync complete."
echo "AGENTS file: $AGENTS_FILE"
echo "Next step: openclaw restart"
