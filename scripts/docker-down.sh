#!/usr/bin/env bash
# Stop the keyref-server started by scripts/docker-up.sh.
# Data survives in the named volume keyref-data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker compose -f "$ROOT/docker-compose.yml" down
