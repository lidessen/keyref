#!/usr/bin/env bash
# Simulator UI end-to-end: starts a real keyref-server (quota-enforcing,
# so vault creation also exercises PoW) on a fixed loopback port, then runs
# the XCUITest target that drives the actual app UI against it.
#
#   scripts/dev/ui-test.sh
#
# The UI test hardcodes http://127.0.0.1:18080 (the simulator shares the
# host network namespace); the port is checked before starting.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT=18080
ONLY="${1:-KeyrefUIAutomationTests/KeyrefFlowUITests}"
TMP="$(mktemp -d)"
SRV_PID=""

cleanup() {
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

if ! command -v go >/dev/null 2>&1; then
  echo "error: go toolchain not found (needed for the real server)" >&2
  exit 1
fi
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "error: 127.0.0.1:$PORT is already in use" >&2
  exit 1
fi

echo "==> building keyref-server"
(cd "$ROOT" && go build -C server -o "$TMP/keyref-server" ./cmd/keyref-server)

echo "==> starting keyref-server on 127.0.0.1:$PORT (KEYREF_ENFORCE_QUOTAS=1)"
KEYREF_DATA="$TMP/data" KEYREF_ENFORCE_QUOTAS=1 "$TMP/keyref-server" \
  serve --listen "127.0.0.1:$PORT" >"$TMP/server.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:$PORT/v1/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "error: server exited during startup" >&2
    cat "$TMP/server.log" >&2
    exit 1
  fi
  sleep 0.2
done

echo "==> running the app UI flow in the simulator"
"$ROOT/scripts/dev/xcodebuild.sh" \
  -project "$ROOT/ios/Keyref.xcodeproj" \
  -scheme KeyrefUIAutomation \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -only-testing:"$ONLY" \
  test
