#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_SCRIPT="$SCRIPT_DIR/build_tproxy_app_with_developer_id_signing.sh"
DERIVED_DATA_PATH="${RAMA_TPROXY_DERIVED_DATA_PATH:-$ROOT_DIR/.xcode-derived/tproxy-app-dist}"
APP_PATH="${RAMA_TPROXY_DIST_APP_PATH:-$DERIVED_DATA_PATH/Build/Products/Release/RamaTransparentProxyExampleHost.app}"
NOTARY_DIR="${RAMA_TPROXY_NOTARY_DIR:-$DERIVED_DATA_PATH/notarization}"
ZIP_PATH="$NOTARY_DIR/RamaTransparentProxyExampleHost.zip"
SUBMIT_JSON="$NOTARY_DIR/notary-submit.json"
TEAM_ID="${RAMA_TPROXY_DEVELOPMENT_TEAM:-ADPG6C355H}"
KEYCHAIN_PROFILE="${RAMA_TPROXY_NOTARY_KEYCHAIN_PROFILE:-}"
APPLE_ID="${RAMA_TPROXY_NOTARY_APPLE_ID:-}"
PASSWORD="${RAMA_TPROXY_NOTARY_PASSWORD:-}"

"$BUILD_SCRIPT"

if [ ! -d "$APP_PATH" ]; then
  echo "Expected built app at $APP_PATH" >&2
  exit 1
fi

mkdir -p "$NOTARY_DIR"
rm -f "$ZIP_PATH" "$SUBMIT_JSON"

xcrun ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

submit_args=(submit "$ZIP_PATH" --wait --output-format json)
if [ -n "$KEYCHAIN_PROFILE" ]; then
  submit_args+=(--keychain-profile "$KEYCHAIN_PROFILE")
elif [ -n "$APPLE_ID" ] && [ -n "$PASSWORD" ]; then
  submit_args+=(--apple-id "$APPLE_ID" --password "$PASSWORD" --team-id "$TEAM_ID")
else
  cat >&2 <<EOF
Missing notarization credentials.
Provide one of:
  RAMA_TPROXY_NOTARY_KEYCHAIN_PROFILE=<stored notarytool profile>
  RAMA_TPROXY_NOTARY_APPLE_ID=<apple id>
  RAMA_TPROXY_NOTARY_PASSWORD=<app-specific password>
Recommended setup:
  xcrun notarytool store-credentials rama-tproxy-notary     --apple-id <apple-id> --team-id $TEAM_ID --password <app-specific-password>
Then run with:
  RAMA_TPROXY_NOTARY_KEYCHAIN_PROFILE=rama-tproxy-notary
EOF
  exit 1
fi

xcrun notarytool "${submit_args[@]}" | tee "$SUBMIT_JSON"

echo "Verifying signed app before stapling"
codesign --verify --deep --strict --verbose=4 "$APP_PATH"
submission_id="$(plutil -extract id raw -o - "$SUBMIT_JSON" 2>/dev/null || true)"
status="$(plutil -extract status raw -o - "$SUBMIT_JSON" 2>/dev/null || true)"

if [ -z "$submission_id" ]; then
  echo "Could not read notarization submission id from $SUBMIT_JSON" >&2
  exit 1
fi

if [ "$status" != "Accepted" ]; then
  echo "Notarization status: $status" >&2
  echo "Fetching notarization log for $submission_id" >&2
  xcrun notarytool log "$submission_id" ${KEYCHAIN_PROFILE:+--keychain-profile "$KEYCHAIN_PROFILE"} ${APPLE_ID:+--apple-id "$APPLE_ID"} ${PASSWORD:+--password "$PASSWORD"} ${APPLE_ID:+--team-id "$TEAM_ID"}
  exit 1
fi

staple_output="$(xcrun stapler staple "$APP_PATH" 2>&1)" || {
  echo "$staple_output" >&2
  echo "Fetching notarization log for $submission_id" >&2
  if [ -n "$KEYCHAIN_PROFILE" ]; then
    xcrun notarytool log "$submission_id" --keychain-profile "$KEYCHAIN_PROFILE"
  else
    xcrun notarytool log "$submission_id" --apple-id "$APPLE_ID" --password "$PASSWORD" --team-id "$TEAM_ID"
  fi
  exit 1
}

echo "$staple_output"
echo "Verifying signed app after stapling"
codesign --verify --deep --strict --verbose=4 "$APP_PATH"
spctl -a -vv "$APP_PATH"
