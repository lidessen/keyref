#!/usr/bin/env bash
# Build the published CLI assets and their SHA-256 manifest from this checkout.
set -euo pipefail

if [[ $# -lt 2 || ! "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "usage: $0 vX.Y.Z OUTPUT_DIR [darwin/amd64 darwin/arm64 linux/amd64 linux/arm64]" >&2
  exit 2
fi
version="$1"
mkdir -p "$2"
output_dir="$(cd "$2" && pwd -P)"
shift 2
if [[ $# -eq 0 ]]; then
  set -- darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
fi
root="$(cd "$(dirname "$0")/.." && pwd -P)"
export GOWORK="$root/go.work"

assets=()
for platform in "$@"; do
  case "$platform" in
    darwin/amd64|darwin/arm64|linux/amd64|linux/arm64) ;;
    *) echo "unsupported release platform: $platform" >&2; exit 2 ;;
  esac
  asset="keyref-${platform/\//-}"
  CGO_ENABLED=0 GOOS="${platform%/*}" GOARCH="${platform#*/}" \
    go build -C "$root/cli" -mod=readonly -trimpath -ldflags "-s -w -X main.version=$version" \
    -o "$output_dir/$asset" ./cmd/keyref
  assets+=("$asset")
done

cd "$output_dir"
if command -v sha256sum >/dev/null; then
  sha256sum "${assets[@]}" > SHA256SUMS
else
  shasum -a 256 "${assets[@]}" > SHA256SUMS
fi
