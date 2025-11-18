#!/usr/bin/env bash
set -euo pipefail
BASE="/opt/security-audit"
CFG="$BASE/config.json"
if [ ! -f "$CFG" ]; then
  echo "Please create $CFG and configure settings." >&2
  exit 1
fi
python3 "$BASE/reporting/run_full_scan.py" --config "$CFG"
