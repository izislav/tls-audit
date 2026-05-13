#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: bash deploy/scripts/restore-postgres.sh /path/to/backup.sql.gz" >&2
  exit 2
fi

BACKUP_FILE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "Backup file not found: $BACKUP_FILE" >&2
  exit 2
fi

# shellcheck disable=SC1091
source deploy/scripts/lib.sh
load_env

POSTGRES_DB="${POSTGRES_DB:-tls_audit}"
POSTGRES_USER="${POSTGRES_USER:-tls_audit}"

gunzip -c "$BACKUP_FILE" | compose exec -T postgres psql \
  -v ON_ERROR_STOP=1 \
  -U "$POSTGRES_USER" \
  "$POSTGRES_DB"
