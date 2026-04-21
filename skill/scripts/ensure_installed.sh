#!/bin/bash
# Reins install checker
# Usage: bash skill/scripts/ensure_installed.sh
# Installs @pegasi/reins globally and runs non-interactive init if not already present.

set -euo pipefail

if command -v reins &> /dev/null; then
    CMD=$(command -v reins)
    echo "Reins is installed: $($CMD --version)"
    exit 0
fi

echo "Reins not found. Installing @pegasi/reins..."
npm install -g @pegasi/reins

echo "Running non-interactive setup..."
reins init \
    --non-interactive \
    --security-level balanced \
    --modules FileSystem,Shell,Browser

echo "Reins installed: $(reins --version)"
echo "Run 'reins init' for full interactive setup including Watchtower connection."
