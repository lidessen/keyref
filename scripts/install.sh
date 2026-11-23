#!/usr/bin/env bash
set -euo pipefail

export KEYREF_BIN_DIR="${KEYREF_BIN_DIR:-$HOME/.local/bin}"
fail() { echo "keyref installer: $*" >&2; exit 1; }
download() {
  curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 90 "$@"
}

# Keep source builds available for development refs.
if [[ -n "${KEYREF_REF:-}" ]]; then
  [[ -z "${KEYREF_VERSION:-}" ]] || fail 'choose either KEYREF_VERSION or KEYREF_REF'
  [[ "$KEYREF_REF" =~ ^[a-zA-Z0-9._-]+$ ]] || fail 'invalid KEYREF_REF'
  command -v go >/dev/null || fail 'Go is required for a source install'
  work_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir"' EXIT
  work_dir="$(cd "$work_dir" && pwd -P)"
  download "https://codeload.github.com/lidessen/keyref/tar.gz/$KEYREF_REF" -o "$work_dir/source.tar.gz"
  mkdir "$work_dir/source"
  tar -xzf "$work_dir/source.tar.gz" -C "$work_dir/source" --strip-components=1
  KEYREF_BUILD_VERSION="$KEYREF_REF" GOWORK="$work_dir/source/go.work" \
    bash "$work_dir/source/scripts/install-cli.sh"
  exit
fi

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail 'supported systems are macOS and Linux' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail 'supported architectures are amd64 and arm64' ;;
esac

release_root=https://github.com/lidessen/keyref/releases
if [[ -n "${KEYREF_VERSION:-}" ]]; then
  [[ "$KEYREF_VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'KEYREF_VERSION must be a stable vX.Y.Z tag'
  release_url="$release_root/download/$KEYREF_VERSION"
else
  # Resolve latest once so both downloads refer to the same release.
  latest="$(download --head --output /dev/null --write-out '%{url_effective}' "$release_root/latest")"
  tag="${latest#"$release_root/tag/"}"
  [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'no stable Keyref release found'
  release_url="$release_root/download/$tag"
fi

mkdir -p "$KEYREF_BIN_DIR"
bin_dir="$(cd "$KEYREF_BIN_DIR" && pwd -P)"
target="$bin_dir/keyref"
work_dir="$(mktemp -d "$bin_dir/.keyref-install.XXXXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
asset="keyref-$os-$arch"
download --max-filesize 65536 "$release_url/SHA256SUMS" -o "$work_dir/SHA256SUMS"
expected="$(awk -v asset="$asset" 'NF == 2 && $2 == asset { print $1 }' "$work_dir/SHA256SUMS")"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "missing or invalid SHA-256 for $asset"
download --max-filesize 67108864 "$release_url/$asset" -o "$work_dir/keyref"
if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$work_dir/keyref")"
else
  actual="$(shasum -a 256 "$work_dir/keyref")"
fi
[[ -s "$work_dir/keyref" && "${actual%% *}" == "$expected" ]] || fail "SHA-256 verification failed for $asset"

[[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] || fail "$target is not a regular executable path"
chmod 0755 "$work_dir/keyref"
mv -f "$work_dir/keyref" "$target"
printf 'Installed keyref to %s\n' "$target"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) printf 'Add %s to PATH to run keyref by name.\n' "$bin_dir" >&2 ;;
esac
