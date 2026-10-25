#!/usr/bin/env bash
# Build and run keyref-server locally in development mode: plain HTTP,
# no quotas (self-hosted behaviour, design §10.4).
#
#   scripts/run-server.sh                           # listen on 127.0.0.1:8080
#   KEYREF_LISTEN=127.0.0.1:9000 scripts/run-server.sh
#   KEYREF_ENFORCE_QUOTAS=1 scripts/run-server.sh   # hosted behaviour
#   scripts/run-server.sh backup --out /tmp/backup.db
#
# Point the CLI at it:
#   KEYREF_SERVER=http://127.0.0.1:8080 keyref pair
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV_DIR="${KEYREF_DEV_DIR:-$HOME/.keyref-dev}"
mkdir -p "$DEV_DIR"

echo "==> building keyref-server"
go build -C "$ROOT/server" -o "$DEV_DIR/keyref-server" ./cmd/keyref-server

export KEYREF_DATA="${KEYREF_DATA:-$DEV_DIR/data}"
export KEYREF_LISTEN="${KEYREF_LISTEN:-127.0.0.1:8080}"
mkdir -p "$KEYREF_DATA"

PORT="${KEYREF_LISTEN##*:}"
echo "==> keyref-server on http://127.0.0.1:$PORT (data: $KEYREF_DATA)"
echo "    CLI: KEYREF_SERVER=http://127.0.0.1:$PORT"
exec "$DEV_DIR/keyref-server" "$@"
