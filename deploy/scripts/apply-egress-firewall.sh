#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source deploy/scripts/lib.sh
load_env

NETWORK_NAME="${DOCKER_EGRESS_NETWORK:-${COMPOSE_PROJECT_NAME:-tls-audit}_default}"
COMMENT_PREFIX="tls-audit-egress"

if [[ "${1:-}" == "--clear" ]]; then
  clear_rules() {
    while iptables -S DOCKER-USER 2>/dev/null | grep -F "$COMMENT_PREFIX" >/dev/null; do
      local rule
      rule="$(iptables -S DOCKER-USER | grep -F "$COMMENT_PREFIX" | head -n 1)"
      # Convert "-A DOCKER-USER ..." to "-D DOCKER-USER ...".
      iptables ${rule/-A /-D }
    done
  }
  clear_rules
  exit 0
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required" >&2
  exit 2
fi

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  echo "Docker network not found: $NETWORK_NAME" >&2
  exit 2
fi

SUBNET="$(
  docker network inspect "$NETWORK_NAME" \
    --format '{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}}{{end}}{{end}}'
)"

if [[ -z "$SUBNET" ]]; then
  echo "Cannot determine subnet for Docker network: $NETWORK_NAME" >&2
  exit 2
fi

iptables -N DOCKER-USER 2>/dev/null || true

while iptables -S DOCKER-USER 2>/dev/null | grep -F "$COMMENT_PREFIX" >/dev/null; do
  rule="$(iptables -S DOCKER-USER | grep -F "$COMMENT_PREFIX" | head -n 1)"
  iptables ${rule/-A /-D }
done

add_rule() {
  iptables -A DOCKER-USER "$@" -m comment --comment "$COMMENT_PREFIX"
}

# Keep internal Redis/Postgres/API traffic inside the Compose network working.
add_rule -s "$SUBNET" -d "$SUBNET" -j RETURN

for destination in \
  0.0.0.0/8 \
  10.0.0.0/8 \
  100.64.0.0/10 \
  127.0.0.0/8 \
  169.254.0.0/16 \
  172.16.0.0/12 \
  192.0.0.0/24 \
  192.168.0.0/16 \
  198.18.0.0/15 \
  224.0.0.0/4 \
  240.0.0.0/4; do
  add_rule -s "$SUBNET" -d "$destination" -j REJECT
done

echo "Applied Docker egress firewall for $NETWORK_NAME ($SUBNET)"
