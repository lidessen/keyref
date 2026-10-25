#!/usr/bin/env bash
# Build the keyref-server image and start it with docker compose.
#
#   scripts/docker-up.sh      # build + up -d + status
#   scripts/docker-down.sh    # stop (or: docker compose down)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="docker compose -f $ROOT/docker-compose.yml"

command -v docker >/dev/null 2>&1 || {
  echo "error: docker is not installed or not on PATH" >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  echo "error: the docker daemon is not running (start Docker Desktop first)" >&2
  exit 1
}

echo "==> building image (first build downloads the Go base image)"
$COMPOSE build

echo "==> starting keyref-server"
$COMPOSE up -d
$COMPOSE ps

PORT="${KEYREF_PORT:-8080}"
echo
echo "==> server: http://127.0.0.1:$PORT/v1/healthz"
echo "    CLI:    KEYREF_SERVER=http://127.0.0.1:$PORT keyref pair"
echo "    stop:   $COMPOSE down (data persists in volume keyref-data)"
