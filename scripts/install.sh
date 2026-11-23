#!/usr/bin/env bash
set -euo pipefail

REF="${KEYREF_REF:-main}"
export KEYREF_BIN_DIR="${KEYREF_BIN_DIR:-$HOME/.local/bin}"

case "$REF" in
  *[!a-zA-Z0-9._-]*)
    echo 'error: KEYREF_REF must be a branch, tag, or commit without slashes' >&2
    exit 1
    ;;
esac

for tool in curl tar go; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is required to install keyref from source" >&2
    exit 1
  fi
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TMP="$(cd "$TMP" && pwd -P)"

curl --fail --silent --show-error --location --proto '=https' \
  "https://codeload.github.com/lidessen/keyref/tar.gz/$REF" -o "$TMP/source.tar.gz"
mkdir "$TMP/source"
tar -xzf "$TMP/source.tar.gz" -C "$TMP/source" --strip-components=1

KEYREF_BUILD_VERSION="$REF" GOWORK="$TMP/source/go.work" \
  bash "$TMP/source/scripts/install-cli.sh"
