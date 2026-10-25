#!/usr/bin/env bash
# Build the keyref CLI and install it into a directory on your PATH.
#
#   scripts/install-cli.sh                          # install to /usr/local/bin
#   KEYREF_BIN_DIR="$HOME/.local/bin" scripts/install-cli.sh
#
# Afterwards point it at a server and pair:
#   keyref server set http://127.0.0.1:8080         # local dev server
#   keyref pair
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${KEYREF_BIN_DIR:-/usr/local/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> building keyref CLI"
go build -C "$ROOT/cli" -trimpath -o "$TMP/keyref" ./cmd/keyref

echo "==> installing to $BIN_DIR/keyref"
mkdir -p "$BIN_DIR"
if [ -w "$BIN_DIR" ]; then
  install -m 0755 "$TMP/keyref" "$BIN_DIR/keyref"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "$TMP/keyref" "$BIN_DIR/keyref"
else
  echo "error: $BIN_DIR is not writable and sudo is unavailable" >&2
  echo "       rerun with KEYREF_BIN_DIR=\"\$HOME/.local/bin\" $0" >&2
  exit 1
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    echo "warning: $BIN_DIR is not on your PATH; add it, e.g.:" >&2
    echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc" >&2
    ;;
esac

echo "==> done: $(command -v keyref || echo "$BIN_DIR/keyref")"
