#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source deploy/scripts/lib.sh
load_env

DAYS="${1:-${STATS_DAYS:-7}}"
LOG_DIR="${STATS_LOG_DIR:-$ROOT_DIR/logs}"
mkdir -p "$LOG_DIR"

OUT="$LOG_DIR/stats-last.json"
compose exec -T api python -m services.api.app.maintenance stats --days "$DAYS" | tee "$OUT"
