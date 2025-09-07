#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Config / defaults
# -----------------------------
KEYCHAIN_NAME="${KEYCHAIN_NAME:-ramabuild.keychain-db}"   # modern suffix -db
KEYCHAIN_PATH="$HOME/Library/Keychains/$KEYCHAIN_NAME"
KEYCHAIN_PASSWORD="${KEYCHAIN_PASSWORD:-}"
CERT_P12_B64="${MACOS_CERT_P12:-}"                        # base64 p12 (optional)
CERT_P12_PASS="${MACOS_CERT_PASSWORD:-}"                  # p12 password (optional)
CERT_COMMON_NAME="${MACOS_CERT_COMMON_NAME:-plabayo.tech}" # default as requested
RUNNER_TEMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"

# Target triple: $1 > $CARGO_BUILD_TARGET > infer from arch
if [[ $# -ge 1 && -n "${1:-}" ]]; then
  TARGET="$1"
elif [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
  TARGET="$CARGO_BUILD_TARGET"
else
  case "$(uname -m)" in
    x86_64)  TARGET="x86_64-apple-darwin" ;;
    arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
    *) echo "Unsupported arch $(uname -m). Provide a target triple as arg 1."; exit 1 ;;
  esac
fi

BIN="target/${TARGET}/release/rama"
ZIP="rama-${TARGET}.zip"

# Notary credentials (API key mode)
AC_API_KEY_ID="${AC_API_KEY_ID:-}"
AC_API_ISSUER_ID="${AC_API_ISSUER_ID:-}"
AC_API_KEY="${AC_API_KEY:-}"

# -----------------------------
# Helpers
# -----------------------------
log() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  rm -f cert.p12 key.p8 2>/dev/null || true
}
trap cleanup EXIT

# -----------------------------
# Keychain: create only if needed
# -----------------------------
log "Preparing keychain: $KEYCHAIN_PATH"
if [ "$KEYCHAIN_NAME" = "login.keychain-db" ]; then
    log "Nothing to do for login.keychain-db"
else
    if [[ ! -f "$KEYCHAIN_PATH" ]]; then
        security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
    else
        log "Keychain already exists; reusing"
    fi

    # Make it default and unlocked for this session
    security default-keychain -s "$KEYCHAIN_PATH"
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
    security set-keychain-settings "$KEYCHAIN_PATH"
fi

# -----------------------------
# Import signing identity (if provided)
# -----------------------------
if [[ -n "$CERT_P12_B64" ]]; then
  log "Importing Developer ID .p12 into keychain ${KEYCHAIN_PATH}"
  printf "%s" "$CERT_P12_B64" | base64 --decode > cert.p12
  security import cert.p12 -k "$KEYCHAIN_PATH" -P "${CERT_P12_PASS}" -T /usr/bin/codesign
  # allow non-interactive use by codesign and notarytool
  if [ "$KEYCHAIN_NAME" = "login.keychain-db" ]; then
      security set-key-partition-list -S apple-tool:,apple: -s "$KEYCHAIN_PATH"
  else
      security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
  fi
else
  log "No MACOS_CERT_P12 provided; skipping import (assuming identity already in keychain)"
fi

# -----------------------------
# Build
# -----------------------------
log "Building release for ${TARGET}"
cargo build --release -p rama-cli --target "${TARGET}"

# -----------------------------
# Codesign
# -----------------------------
log "Codesigning ${BIN} with '${CERT_COMMON_NAME}'"
codesign --force --timestamp --options runtime --sign "${CERT_COMMON_NAME}" --keychain "${KEYCHAIN_PATH}" "${BIN}"
codesign --verify --strict --keychain "${KEYCHAIN_PATH}" --verbose=4 "${BIN}"

# -----------------------------
# Prepare zip for notarization
# -----------------------------
log "Creating zip for notarization: ${ZIP}"
(
  cd "target/${TARGET}/release"
  ditto -c -k --sequesterRsrc "rama" "${ZIP}"
)

# -----------------------------
# Notarize (API key mode)
# -----------------------------
if [[ -n "$AC_API_KEY_ID" && -n "$AC_API_ISSUER_ID" && -n "$AC_API_KEY" ]]; then
  log "Submitting to notarytool using API key"
  umask 077
  printf "%s" "${AC_API_KEY}" > key.p8

  # run submit non-fatally so set -e doesn't kill the script
  set +e
  REQ_OUT=$(xcrun notarytool submit "target/${TARGET}/release/${ZIP}" \
    --key key.p8 \
    --key-id "${AC_API_KEY_ID}" \
    --issuer "${AC_API_ISSUER_ID}" 2>&1)
  SUBMIT_STATUS=$?
  set -e

  log "notarytool submit output:"
  printf '%s\n' "$REQ_OUT"

  if [[ $SUBMIT_STATUS -ne 0 ]]; then
    echo "notarytool submit failed with exit code $SUBMIT_STATUS"
    echo "Tip: exit 69 often means auth or connectivity issues. Check AC_API_* values and network."
    exit $SUBMIT_STATUS
  fi

  # extract request id (tolerant of leading spaces and CRLF)
  REQ_ID=$(printf '%s\n' "$REQ_OUT" | tr -d '\r' \
           | sed -n 's/^[[:space:]]*id:[[:space:]]*\([0-9a-fA-F-]\{36\}\)$/\1/p' \
           | head -n1)

  if [[ -z "$REQ_ID" ]]; then
    echo "Could not extract request id from submit output above."
    exit 1
  fi
  log "request id: ${REQ_ID}"

  # Poll until Accepted or Invalid
  while true; do
    log "Poll..."
    set +e
    LOG_OUT=$(xcrun notarytool log "$REQ_ID" \
      --key key.p8 \
      --issuer "${AC_API_ISSUER_ID}" \
      --key-id "${AC_API_KEY_ID}" 2>&1)
    LOG_STATUS=$?
    set -e

    printf '%s\n' "$LOG_OUT"

    if [[ $LOG_STATUS -ne 0 ]]; then
      echo "notarytool log failed with exit code $LOG_STATUS — retrying in 30s"
      sleep 30
      continue
    fi

    if echo "$LOG_OUT" | grep -q "\"status\":[[:space:]]*\"Accepted"; then
      log "Stapling ticket to binary"
      # After notarization Accepted
      case "$BIN" in
        *.dmg|*.pkg)  xcrun stapler staple -v "$BIN"; xcrun stapler validate "$BIN" ;;
        *)
          echo "Note: stapling is not supported for a raw CLI binary. Skipping stapler for ${BIN}."
          ;;
      esac
      break
    elif echo "$LOG_OUT" | grep -q "^\"status\":[[:space:]]*\"Invalid"; then
      echo "❌ Notarization Invalid — see issues above."
      exit 1
    fi

    echo "Still in progress... retrying in 30s"
    sleep 30
  done
else
  log "No API key creds found. Set AC_API_KEY_ID, AC_API_ISSUER_ID, AC_API_KEY to enable notarization."
  log "Skipping notarization step."
fi

log "Gatekeeper assessment (simulate downloaded file)"
xattr -w com.apple.quarantine "0081;$(date +%s);Safari;00000000" "${BIN}"
if spctl -a -vvv --type execute --ignore-cache --no-cache "${BIN}"; then
  echo "Gatekeeper: accepted (CLI binary)"
else
  echo "Gatekeeper: spctl reported 'not an app' (common for CLIs)."
  echo "For a clean 'accepted' message, notarize & staple a DMG or PKG and assess that artifact."
fi


log "Done ✓"
