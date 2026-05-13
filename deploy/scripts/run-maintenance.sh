#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# shellcheck disable=SC1091
source deploy/scripts/lib.sh

bash deploy/scripts/backup-postgres.sh
compose exec -T api python -m services.api.app.maintenance cleanup
