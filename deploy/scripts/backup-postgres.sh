#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source deploy/scripts/lib.sh
load_env

POSTGRES_DB="${POSTGRES_DB:-tls_audit}"
POSTGRES_USER="${POSTGRES_USER:-tls_audit}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/tls-audit-$STAMP.sql.gz"
TMP="$BACKUP_DIR/.tls-audit-$STAMP.sql.gz.tmp"

mkdir -p "$BACKUP_DIR"
trap 'rm -f "$TMP"' EXIT

compose exec -T postgres pg_dump \
  --no-owner \
  --no-privileges \
  -U "$POSTGRES_USER" \
  "$POSTGRES_DB" | gzip -9 > "$TMP"

mv "$TMP" "$OUT"
trap - EXIT

find "$BACKUP_DIR" -type f -name 'tls-audit-*.sql.gz' -mtime "+$BACKUP_RETENTION_DAYS" -delete

echo "$OUT"
