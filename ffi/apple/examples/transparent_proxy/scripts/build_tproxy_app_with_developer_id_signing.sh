#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$ROOT_DIR/tproxy_app"
SPEC_PATH="$APP_DIR/Project.dist.yml"
DERIVED_DATA_PATH="${RAMA_TPROXY_DERIVED_DATA_PATH:-$ROOT_DIR/.xcode-derived/tproxy-app-dist}"
TEAM_ID="${RAMA_TPROXY_DEVELOPMENT_TEAM:-ADPG6C355H}"
HOST_SIGNING_IDENTITY="${RAMA_TPROXY_HOST_SIGNING_IDENTITY:-Developer ID Application}"
EXT_SIGNING_IDENTITY="${RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY:-$HOST_SIGNING_IDENTITY}"
HOST_PROFILE_SPECIFIER="${RAMA_TPROXY_HOST_PROFILE_SPECIFIER:-Rama Transparent Proxy Example (Host)}"
EXT_PROFILE_SPECIFIER="${RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER:-Rama Transparent Proxy Example (Extension)}"
HOST_PROFILE_PATH="${RAMA_TPROXY_HOST_PROFILE_PATH:-}"
EXT_PROFILE_PATH="${RAMA_TPROXY_EXTENSION_PROFILE_PATH:-}"
PROFILE_INSTALL_DIR="${HOME}/Library/MobileDevice/Provisioning Profiles"

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

install_profile_if_needed "$HOST_PROFILE_PATH"
install_profile_if_needed "$EXT_PROFILE_PATH"

cd "$APP_DIR"
xcodegen generate --spec "$SPEC_PATH"
xcodebuild   -project RamaTransparentProxyExample.xcodeproj   -scheme RamaTransparentProxyExampleHost   -configuration Release   -derivedDataPath "$DERIVED_DATA_PATH"   RAMA_TPROXY_DEVELOPMENT_TEAM="$TEAM_ID"   RAMA_TPROXY_HOST_SIGNING_IDENTITY="$HOST_SIGNING_IDENTITY"   RAMA_TPROXY_EXTENSION_SIGNING_IDENTITY="$EXT_SIGNING_IDENTITY"   RAMA_TPROXY_HOST_PROFILE_SPECIFIER="$HOST_PROFILE_SPECIFIER"   RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER="$EXT_PROFILE_SPECIFIER"   clean build
