#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_ROOT="$(cd "$ROOT_DIR/../../../.." && pwd)"
APP_DIR="$ROOT_DIR/tproxy_app"
SPEC_PATH="$APP_DIR/Project.yml"
DERIVED_DATA_PATH="${RAMA_TPROXY_DERIVED_DATA_PATH:-$ROOT_DIR/.xcode-derived/tproxy-app-dev}"
ISOLATE_CACHE="${RAMA_TPROXY_ISOLATED_CACHE:-0}"
HOME_DIR="${RAMA_TPROXY_HOME_DIR:-$HOME}"
TEAM_ID="${RAMA_TPROXY_DEVELOPMENT_TEAM:-ADPG6C355H}"
CONTAINER_SIGNING_IDENTITY="${RAMA_TPROXY_CONTAINER_SIGNING_IDENTITY:-Apple Development}"
EXT_SIGNING_IDENTITY="${RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY:-$CONTAINER_SIGNING_IDENTITY}"
CONTAINER_PROFILE_SPECIFIER="${RAMA_TPROXY_CONTAINER_PROFILE_SPECIFIER:-}"
EXT_PROFILE_SPECIFIER="${RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER:-}"
BUILD_VERSION="${RAMA_TPROXY_CURRENT_PROJECT_VERSION:-$(date +%Y%m%d%H%M%S)}"
SKIP_CODESIGNING="${RAMA_TPROXY_SKIP_CODESIGNING:-0}"
CONFIGURATION="${RAMA_TPROXY_CONFIGURATION:-Debug}"
case "$CONFIGURATION" in
  Debug) RUST_PROFILE=debug; RUST_PROFILE_ARGS=(--profile dev) ;;
  Release) RUST_PROFILE=release; RUST_PROFILE_ARGS=(--release) ;;
  *) echo "RAMA_TPROXY_CONFIGURATION must be Debug or Release" >&2; exit 1 ;;
esac

# Embed the exact source state in both bundles.  A non-git source archive is
# still buildable for normal development, but signed evidence rejects the
# explicit `unavailable` values.
GIT_HEAD="$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ ! "$GIT_HEAD" =~ ^[0-9a-f]{40,64}$ ]]; then
  GIT_HEAD="unavailable"
fi
if GIT_STATUS="$(git -C "$SOURCE_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null)"; then
  if [[ -n "$GIT_STATUS" ]]; then
    GIT_DIRTY=1
  else
    GIT_DIRTY=0
  fi
else
  GIT_DIRTY="unavailable"
fi

# A clean signed build compiles a head-pinned archive whose files and directory
# entries are protected against in-place writes and atomic replacement. Only
# generated output roots stay writable. These local permissions are an integrity
# guard, not authentication against an actor able to change their owner's mode
# bits or replace the toolchain. Dirty/non-git builds remain in-place and are
# explicitly ineligible for the shared signed evidence envelope.
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

if [[ "$GIT_DIRTY" == 0 ]]; then
  ISOLATED_BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rama-tproxy-source.XXXXXX")"
  ISOLATED_SOURCE_ROOT="$ISOLATED_BUILD_ROOT/source"
  mkdir "$ISOLATED_SOURCE_ROOT"
  git -C "$SOURCE_ROOT" archive "$GIT_HEAD" | tar -x -C "$ISOLATED_SOURCE_ROOT"
  find "$ISOLATED_SOURCE_ROOT" -type f -exec chmod a-w {} +
  ISOLATED_ROOT="$ISOLATED_SOURCE_ROOT/ffi/apple/examples/transparent_proxy"
  APP_DIR="$ISOLATED_ROOT/tproxy_app"
  SPEC_PATH="$APP_DIR/Project.yml"
  # XcodeGen replaces the project directory, so finish that preparation before
  # protecting its parent. Cargo/Xcode write only into these generated roots.
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
  CARGO_TARGET_DIR="$RUST_TARGET_DIR" cargo build --locked "${RUST_PROFILE_ARGS[@]}" --target aarch64-apple-darwin
  CARGO_TARGET_DIR="$RUST_TARGET_DIR" cargo build --locked "${RUST_PROFILE_ARGS[@]}" --target x86_64-apple-darwin
  mkdir -p "$RUST_TARGET_DIR/universal"
  /usr/bin/lipo -create \
    -output "$RUST_TARGET_DIR/universal/librama_tproxy_example.a" \
    "$RUST_TARGET_DIR/aarch64-apple-darwin/$RUST_PROFILE/librama_tproxy_example.a" \
    "$RUST_TARGET_DIR/x86_64-apple-darwin/$RUST_PROFILE/librama_tproxy_example.a"
  /usr/bin/lipo "$RUST_TARGET_DIR/universal/librama_tproxy_example.a" \
    -verify_arch arm64 x86_64
)

cd "$APP_DIR"
mkdir -p "$DERIVED_DATA_PATH"
if [[ "$ISOLATE_CACHE" == "1" ]]; then
  mkdir -p "$HOME_DIR"
fi
if [[ -z "$ISOLATED_SOURCE_ROOT" ]]; then
  xcodegen generate --spec "$SPEC_PATH"
fi

cmd=(
  xcodebuild
  -project RamaTransparentProxyExample.xcodeproj
  -scheme RamaTransparentProxyExampleContainer
  -configuration "$CONFIGURATION"
  -derivedDataPath "$DERIVED_DATA_PATH"
  RAMA_TPROXY_CURRENT_PROJECT_VERSION="$BUILD_VERSION"
  RAMA_TPROXY_GIT_HEAD="$GIT_HEAD"
  RAMA_TPROXY_GIT_DIRTY="$GIT_DIRTY"
)

if [[ "$SKIP_CODESIGNING" == "1" ]]; then
  cmd+=(
    CODE_SIGNING_ALLOWED=NO
    CODE_SIGNING_REQUIRED=NO
    CODE_SIGN_STYLE=Manual
  )
else
  cmd+=(
    -allowProvisioningUpdates
    RAMA_TPROXY_DEVELOPMENT_TEAM="$TEAM_ID"
    RAMA_TPROXY_CONTAINER_SIGNING_IDENTITY="$CONTAINER_SIGNING_IDENTITY"
    RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY="$EXT_SIGNING_IDENTITY"
  )

  if [[ -n "$CONTAINER_PROFILE_SPECIFIER" ]]; then
    cmd+=(RAMA_TPROXY_CONTAINER_PROFILE_SPECIFIER="$CONTAINER_PROFILE_SPECIFIER")
  fi
  if [[ -n "$EXT_PROFILE_SPECIFIER" ]]; then
    cmd+=(RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER="$EXT_PROFILE_SPECIFIER")
  fi
fi

cmd+=(clean build)
if [[ "$ISOLATE_CACHE" == "1" ]]; then
  env HOME="$HOME_DIR" \
    CFFIXED_USER_HOME="$HOME_DIR" \
    XDG_CACHE_HOME="$HOME_DIR/.cache" \
    CLANG_MODULE_CACHE_PATH="$DERIVED_DATA_PATH/ModuleCache.noindex" \
    SWIFT_MODULECACHE_PATH="$DERIVED_DATA_PATH/SwiftModuleCache" \
    "${cmd[@]}"
else
  "${cmd[@]}"
fi

if [[ "$GIT_DIRTY" == 0 ]]; then
  POST_GIT_HEAD="$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || true)"
  POST_GIT_STATUS="$(git -C "$SOURCE_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null || true)"
  if [[ "$POST_GIT_HEAD" != "$GIT_HEAD" || -n "$POST_GIT_STATUS" ]]; then
    echo "Source repository head/clean state changed during the isolated build" >&2
    exit 1
  fi

fi
