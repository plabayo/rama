#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_ROOT="$(cd "$ROOT_DIR/../../../.." && pwd)"
APP_DIR="$ROOT_DIR/tproxy_app"
SPEC_PATH="$APP_DIR/Project.dist.yml"
WORKSPACE_CARGO_TOML="$ROOT_DIR/../../../../Cargo.toml"
DERIVED_DATA_PATH="${RAMA_TPROXY_DERIVED_DATA_PATH:-$ROOT_DIR/.xcode-derived/tproxy-app-dist}"
TEAM_ID="${RAMA_TPROXY_DEVELOPMENT_TEAM:-ADPG6C355H}"
CONTAINER_SIGNING_IDENTITY="${RAMA_TPROXY_CONTAINER_SIGNING_IDENTITY:-Developer ID Application}"
EXT_SIGNING_IDENTITY="${RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY:-$CONTAINER_SIGNING_IDENTITY}"
CONTAINER_PROFILE_SPECIFIER="${RAMA_TPROXY_CONTAINER_PROFILE_SPECIFIER:-Rama Transparent Proxy Example (Host)}"
EXT_PROFILE_SPECIFIER="${RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER:-Rama Transparent Proxy Example (Extension)}"
CONTAINER_PROFILE_PATH="${RAMA_TPROXY_CONTAINER_PROFILE_PATH:-}"
EXT_PROFILE_PATH="${RAMA_TPROXY_EXTENSION_PROFILE_PATH:-}"
PROFILE_INSTALL_DIR="${HOME}/Library/MobileDevice/Provisioning Profiles"

workspace_version="$(
  sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$WORKSPACE_CARGO_TOML" | head -n1
)"
git_short_sha="${RAMA_TPROXY_GIT_SHORT_SHA:-$(git -C "$ROOT_DIR/../../../../" rev-parse --short=12 HEAD 2>/dev/null || true)}"
git_head="$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ ! "$git_head" =~ ^[0-9a-f]{40,64}$ ]]; then
  git_head="unavailable"
fi
if git_status="$(git -C "$SOURCE_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null)"; then
  if [[ -n "$git_status" ]]; then
    git_dirty=1
  else
    git_dirty=0
  fi
else
  git_dirty="unavailable"
fi

ISOLATED_BUILD_ROOT=""
ISOLATED_SOURCE_ROOT=""
cleanup_isolated_source() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$ISOLATED_BUILD_ROOT" ]]; then
    chmod -R u+w "$ISOLATED_BUILD_ROOT" >/dev/null 2>&1 || true
    rm -rf "$ISOLATED_BUILD_ROOT"
  fi
  exit "$status"
}
trap cleanup_isolated_source EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Clean distribution builds protect a head-pinned archive's files and directory
# entries against writes and atomic replacement, retaining writable generated
# roots. Owner-controlled permissions are a local integrity guard, not remote
# authentication. Dirty/source-archive builds remain available for iteration,
# but carry dirty/unavailable metadata and cannot pass signed evidence.
if [[ "$git_dirty" == 0 ]]; then
  ISOLATED_BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rama-tproxy-source.XXXXXX")"
  ISOLATED_SOURCE_ROOT="$ISOLATED_BUILD_ROOT/source"
  mkdir "$ISOLATED_SOURCE_ROOT"
  git -C "$SOURCE_ROOT" archive "$git_head" | tar -x -C "$ISOLATED_SOURCE_ROOT"
  find "$ISOLATED_SOURCE_ROOT" -type f -exec chmod a-w {} +
  ISOLATED_ROOT="$ISOLATED_SOURCE_ROOT/ffi/apple/examples/transparent_proxy"
  APP_DIR="$ISOLATED_ROOT/tproxy_app"
  SPEC_PATH="$APP_DIR/Project.dist.yml"
  # XcodeGen replaces the project directory, so complete it before protecting
  # its parent. All compiler output stays inside generated writable roots.
  xcodegen generate --spec "$SPEC_PATH"
  mkdir -p "$ISOLATED_ROOT/tproxy_rs/target" \
    "$ISOLATED_SOURCE_ROOT/.build" "$ISOLATED_SOURCE_ROOT/.swiftpm"
  find "$ISOLATED_SOURCE_ROOT" -type d -exec chmod a-w {} +
  chmod -R u+w "$ISOLATED_ROOT/tproxy_rs/target" \
    "$APP_DIR/RamaTransparentProxyExample.xcodeproj" \
    "$ISOLATED_SOURCE_ROOT/.build" "$ISOLATED_SOURCE_ROOT/.swiftpm"
  chmod a-w "$ISOLATED_BUILD_ROOT"
fi

BUILD_ROOT="$(cd "$APP_DIR/.." && pwd)"
RUST_TARGET_DIR="$BUILD_ROOT/tproxy_rs/target"
(
  cd "$BUILD_ROOT/tproxy_rs"
  CARGO_TARGET_DIR="$RUST_TARGET_DIR" cargo build --locked --release --target aarch64-apple-darwin
  CARGO_TARGET_DIR="$RUST_TARGET_DIR" cargo build --locked --release --target x86_64-apple-darwin
  mkdir -p "$RUST_TARGET_DIR/universal"
  /usr/bin/lipo -create \
    -output "$RUST_TARGET_DIR/universal/librama_tproxy_example.a" \
    "$RUST_TARGET_DIR/aarch64-apple-darwin/release/librama_tproxy_example.a" \
    "$RUST_TARGET_DIR/x86_64-apple-darwin/release/librama_tproxy_example.a"
  /usr/bin/lipo "$RUST_TARGET_DIR/universal/librama_tproxy_example.a" \
    -verify_arch arm64 x86_64
)

if [ -z "$workspace_version" ]; then
  echo "Failed to read workspace.package.version from $WORKSPACE_CARGO_TOML" >&2
  exit 1
fi

if [ -n "$git_short_sha" ]; then
  default_marketing_version="${workspace_version}+${git_short_sha}"
else
  default_marketing_version="$workspace_version"
fi

marketing_version="${RAMA_TPROXY_MARKETING_VERSION:-$default_marketing_version}"
current_project_version="${RAMA_TPROXY_CURRENT_PROJECT_VERSION:-$(
  printf '%s' "$workspace_version" | sed -E '
    s/^[^0-9]*//
    s/[-.]?(alpha|beta|rc)[.-]?([0-9]+)$/.\2/
    s/[^0-9.].*$//
  '
)}"

if [ -z "$current_project_version" ]; then
  echo "Failed to derive CURRENT_PROJECT_VERSION from workspace version: $workspace_version" >&2
  exit 1
fi

install_profile_if_needed() {
  local profile_path="$1"
  if [ -z "$profile_path" ]; then
    return 0
  fi
  if [ ! -f "$profile_path" ]; then
    echo "Provisioning profile not found: $profile_path" >&2
    exit 1
  fi

  mkdir -p "$PROFILE_INSTALL_DIR"

  local decoded_plist
  decoded_plist="$(mktemp)"
  /usr/bin/openssl smime -inform der -verify -noverify -in "$profile_path" > "$decoded_plist" 2>/dev/null

  local uuid
  uuid="$(/usr/libexec/PlistBuddy -c 'Print :UUID' "$decoded_plist")"
  cp "$profile_path" "$PROFILE_INSTALL_DIR/$uuid.provisionprofile"
  rm -f "$decoded_plist"
}

install_profile_if_needed "$CONTAINER_PROFILE_PATH"
install_profile_if_needed "$EXT_PROFILE_PATH"

cd "$APP_DIR"
mkdir -p "$DERIVED_DATA_PATH"
if [[ -z "$ISOLATED_SOURCE_ROOT" ]]; then
  xcodegen generate --spec "$SPEC_PATH"
fi
cmd=(
  xcodebuild
  -project RamaTransparentProxyExample.xcodeproj
  -scheme RamaTransparentProxyExampleContainer
  -configuration Release
  -derivedDataPath "$DERIVED_DATA_PATH"
  RAMA_TPROXY_DEVELOPMENT_TEAM="$TEAM_ID"
  RAMA_TPROXY_CONTAINER_SIGNING_IDENTITY="$CONTAINER_SIGNING_IDENTITY"
  RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY="$EXT_SIGNING_IDENTITY"
  RAMA_TPROXY_CONTAINER_PROFILE_SPECIFIER="$CONTAINER_PROFILE_SPECIFIER"
  RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER="$EXT_PROFILE_SPECIFIER"
  RAMA_TPROXY_MARKETING_VERSION="$marketing_version"
  RAMA_TPROXY_CURRENT_PROJECT_VERSION="$current_project_version"
  RAMA_TPROXY_GIT_HEAD="$git_head"
  RAMA_TPROXY_GIT_DIRTY="$git_dirty"
  clean build
)
"${cmd[@]}"

if [[ "$git_dirty" == 0 ]]; then
  post_git_head="$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || true)"
  post_git_status="$(git -C "$SOURCE_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null || true)"
  if [[ "$post_git_head" != "$git_head" || -n "$post_git_status" ]]; then
    echo "Source repository head/clean state changed during the isolated build" >&2
    exit 1
  fi

fi
