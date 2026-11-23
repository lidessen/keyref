#!/usr/bin/env bash
# Exercise the public installer against locally built release assets.
set -euo pipefail
: "${1:?usage: test-install.sh ASSET_DIR vX.Y.Z}" "${2:?release version required}"
root="$(cd "$(dirname "$0")/.." && pwd -P)"
export RELEASE_FIXTURE_DIR="$(cd "$1" && pwd -P)"
export RELEASE_FIXTURE_TAG="$2"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir "$work_dir/mock-bin"
cat > "$work_dir/mock-bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
release=https://github.com/lidessen/keyref/releases
for arg in "$@"; do
  case "$arg" in
    "$release/latest")
      printf '%s/tag/%s' "$release" "$RELEASE_FIXTURE_TAG"
      exit 0
      ;;
    "$release/download/$RELEASE_FIXTURE_TAG/"*) asset="${arg##*/}" ;;
  esac
done
dest="${!#}"
if [[ "${CORRUPT_RELEASE_FIXTURE:-}" == 1 && "$asset" == keyref-* ]]; then
  printf bad-binary > "$dest"
else
  cp "$RELEASE_FIXTURE_DIR/$asset" "$dest"
fi
MOCK
chmod +x "$work_dir/mock-bin/curl"
export PATH="$work_dir/mock-bin:$PATH"
export KEYREF_BIN_DIR="$work_dir/bin"
unset KEYREF_REF KEYREF_VERSION

bash "$root/scripts/install.sh"
[[ "$("$KEYREF_BIN_DIR/keyref" --version)" == "keyref $RELEASE_FIXTURE_TAG" ]]
"$KEYREF_BIN_DIR/keyref" update --help
if CORRUPT_RELEASE_FIXTURE=1 KEYREF_VERSION="$RELEASE_FIXTURE_TAG" bash "$root/scripts/install.sh"; then
  echo 'installer accepted a corrupted release asset' >&2
  exit 1
fi
[[ "$("$KEYREF_BIN_DIR/keyref" --version)" == "keyref $RELEASE_FIXTURE_TAG" ]]
