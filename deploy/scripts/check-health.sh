#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source deploy/scripts/lib.sh
load_env

PUBLIC_URL="${HEALTHCHECK_PUBLIC_URL:-${PUBLIC_BASE_URL:-https://tlsaudit.ru}}"
LOCAL_HEALTH_URL="${HEALTHCHECK_LOCAL_URL:-http://127.0.0.1:8000/health}"
DISK_WARN_PERCENT="${DISK_WARN_PERCENT:-85}"
CERT_WARN_DAYS="${CERT_WARN_DAYS:-21}"
QUEUE_WARN_DEPTH="${QUEUE_WARN_DEPTH:-25}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
BACKUP_WARN_HOURS="${BACKUP_WARN_HOURS:-30}"
LOG_DIR="${HEALTHCHECK_LOG_DIR:-$ROOT_DIR/logs}"

mkdir -p "$LOG_DIR"

critical_count=0
warning_count=0
messages=()

add_issue() {
  local severity="$1"
  local message="$2"
  messages+=("$severity: $message")
  if [[ "$severity" == "critical" ]]; then
    critical_count=$((critical_count + 1))
  else
    warning_count=$((warning_count + 1))
  fi
}

notify() {
  local text="$1"
  if [[ -n "${ALERT_EMAIL_TO:-}" && -n "${SMTP_URL:-}" ]]; then
    local from="${ALERT_EMAIL_FROM:-tls-audit@localhost}"
    local subject="TLS Audit healthcheck"
    local curl_args=(
      -fsS
      --max-time 15
      --url "$SMTP_URL"
      --mail-from "$from"
      --mail-rcpt "$ALERT_EMAIL_TO"
      --upload-file -
    )
    if [[ -n "${SMTP_USER:-}" ]]; then
      curl_args+=(--user "$SMTP_USER:${SMTP_PASSWORD:-}")
    fi
    {
      printf 'From: TLS Audit <%s>\r\n' "$from"
      printf 'To: %s\r\n' "$ALERT_EMAIL_TO"
      printf 'Subject: %s\r\n' "$subject"
      printf 'Content-Type: text/plain; charset=UTF-8\r\n'
      printf '\r\n'
      printf '%s\n' "$text"
    } | curl "${curl_args[@]}" >/dev/null || true
  fi
}

http_code="$(
  curl -fsS --max-time 12 -o /dev/null -w "%{http_code}" "$PUBLIC_URL/" 2>/dev/null || true
)"
if [[ "$http_code" != "200" ]]; then
  add_issue "critical" "public URL $PUBLIC_URL/ returned ${http_code:-no response}"
fi

health_body="$(curl -fsS --max-time 8 "$LOCAL_HEALTH_URL" 2>/dev/null || true)"
if [[ "$health_body" != *'"status":"ok"'* ]]; then
  add_issue "critical" "local health endpoint is not OK: ${health_body:-no response}"
fi
if [[ "$health_body" != *'"database":"enabled"'* ]]; then
  add_issue "warning" "database archive is not reported as enabled: ${health_body:-no response}"
fi

for service in api worker redis postgres; do
  cid="$(compose ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$cid" ]]; then
    add_issue "critical" "container for service '$service' is missing"
    continue
  fi
  state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
  if [[ "$state" != "healthy" && "$state" != "running" ]]; then
    add_issue "critical" "service '$service' state is ${state:-unknown}"
  fi
done

disk_percent="$(df -P "$ROOT_DIR" | awk 'NR == 2 {gsub("%", "", $5); print $5}')"
if [[ -n "$disk_percent" && "$disk_percent" -ge "$DISK_WARN_PERCENT" ]]; then
  add_issue "warning" "disk usage for $ROOT_DIR is ${disk_percent}%"
fi

domain="$(
  printf '%s' "$PUBLIC_URL" \
    | sed -E 's#^https?://##; s#/.*$##; s#:.*$##'
)"
if [[ -n "$domain" ]]; then
  not_after="$(
    openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null \
      | openssl x509 -noout -enddate 2>/dev/null \
      | sed 's/^notAfter=//'
  )"
  if [[ -z "$not_after" ]]; then
    add_issue "critical" "cannot read TLS certificate expiry for $domain"
  else
    expiry_ts="$(date -u -d "$not_after" +%s 2>/dev/null || date -u -j -f "%b %e %T %Y %Z" "$not_after" +%s 2>/dev/null || true)"
    now_ts="$(date -u +%s)"
    if [[ -z "$expiry_ts" ]]; then
      add_issue "warning" "cannot parse TLS certificate expiry for $domain: $not_after"
    else
      cert_days=$(((expiry_ts - now_ts) / 86400))
      if [[ "$cert_days" -lt "$CERT_WARN_DAYS" ]]; then
        add_issue "warning" "TLS certificate for $domain expires in $cert_days days"
      fi
    fi
  fi
fi

queue_depth="$(
  compose exec -T redis redis-cli LLEN "${SCAN_QUEUE_NAME:-tls-audit:scan-jobs}" 2>/dev/null || true
)"
if [[ "$queue_depth" =~ ^[0-9]+$ && "$queue_depth" -gt "$QUEUE_WARN_DEPTH" ]]; then
  add_issue "warning" "scan queue depth is $queue_depth"
fi

if [[ ! -d "$BACKUP_DIR" ]]; then
  add_issue "warning" "backup directory does not exist: $BACKUP_DIR"
else
  latest_backup="$(find "$BACKUP_DIR" -type f -name 'tls-audit-*.sql.gz' -print 2>/dev/null | sort | tail -n 1)"
  if [[ -z "$latest_backup" ]]; then
    add_issue "warning" "no Postgres backup found in $BACKUP_DIR"
  else
    backup_ts="$(stat -c %Y "$latest_backup" 2>/dev/null || stat -f %m "$latest_backup" 2>/dev/null || true)"
    now_ts="$(date -u +%s)"
    if [[ "$backup_ts" =~ ^[0-9]+$ ]]; then
      backup_age_hours=$(((now_ts - backup_ts) / 3600))
      if [[ "$backup_age_hours" -gt "$BACKUP_WARN_HOURS" ]]; then
        add_issue "warning" "latest backup is ${backup_age_hours}h old: $latest_backup"
      fi
    else
      add_issue "warning" "cannot read latest backup timestamp: $latest_backup"
    fi
  fi
fi

status="ok"
if [[ "$critical_count" -gt 0 ]]; then
  status="critical"
elif [[ "$warning_count" -gt 0 ]]; then
  status="warning"
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  printf 'timestamp=%s\n' "$timestamp"
  printf 'status=%s\n' "$status"
  printf 'critical=%s\n' "$critical_count"
  printf 'warning=%s\n' "$warning_count"
  if [[ "${#messages[@]}" -gt 0 ]]; then
    printf '%s\n' "${messages[@]}"
  else
    printf 'message=all checks passed\n'
  fi
} | tee "$LOG_DIR/health-last.txt"

if [[ "$status" != "ok" ]]; then
  notify "TLS Audit healthcheck: $status"$'\n'"$(printf '%s\n' "${messages[@]}")"
fi

if [[ "$critical_count" -gt 0 ]]; then
  exit 2
fi
