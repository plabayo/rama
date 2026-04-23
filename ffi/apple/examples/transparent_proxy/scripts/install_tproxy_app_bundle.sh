#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <dev|dist> <built-app-path> <reset-profile:0|1>" >&2
  exit 1
fi

MODE="$1"
BUILT_APP="$2"
RESET_PROFILE="$3"

INSTALLED_APP="/Applications/RamaTransparentProxyExampleHost.app"
INSTALLED_HELPER_DIR="/Library/PrivilegedHelperTools"

case "$MODE" in
  dev)
    APP_BUNDLE_ID="org.ramaproxy.example.tproxy.dev"
    SERVICE_NAME="org.ramaproxy.example.tproxy.dev.xpc"
    ;;
  dist)
    APP_BUNDLE_ID="org.ramaproxy.example.tproxy.dist"
    SERVICE_NAME="org.ramaproxy.example.tproxy.dist.xpc"
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 1
    ;;
esac

OTHER_SERVICE_NAME=""
if [[ "$SERVICE_NAME" == "org.ramaproxy.example.tproxy.dev.xpc" ]]; then
  OTHER_SERVICE_NAME="org.ramaproxy.example.tproxy.dist.xpc"
else
  OTHER_SERVICE_NAME="org.ramaproxy.example.tproxy.dev.xpc"
fi

INSTALLED_HELPER_APP="$INSTALLED_HELPER_DIR/$SERVICE_NAME.app"
INSTALLED_HELPER_EXECUTABLE="$INSTALLED_HELPER_APP/Contents/MacOS/RamaTransparentProxyExampleXpcService"
INSTALLED_APP_HELPER_BUNDLE="$INSTALLED_APP/Contents/Resources/RamaTransparentProxyExampleXpcService.app"
INSTALLED_DAEMON_TEMPLATE="$INSTALLED_APP/Contents/Library/LaunchDaemons/$SERVICE_NAME.plist"
INSTALLED_DAEMON_PLIST="/Library/LaunchDaemons/$SERVICE_NAME.plist"
OTHER_DAEMON_PLIST="/Library/LaunchDaemons/$OTHER_SERVICE_NAME.plist"

pkill -f '/Applications/RamaTransparentProxyExampleHost.app/Contents/MacOS/RamaTransparentProxyExampleHost' || true
sleep 1
rm -rf "$INSTALLED_APP"
ditto "$BUILT_APP" "$INSTALLED_APP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$BUILT_APP" || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$INSTALLED_APP"

TMP_DAEMON_PLIST="$(mktemp)"
trap 'rm -f "$TMP_DAEMON_PLIST"' EXIT

escaped_helper_path="${INSTALLED_HELPER_EXECUTABLE//\\/\\\\}"
escaped_helper_path="${escaped_helper_path//&/\\&}"
escaped_bundle_id="${APP_BUNDLE_ID//\\/\\\\}"
escaped_bundle_id="${escaped_bundle_id//&/\\&}"
current_user="$(id -un)"
escaped_user_name="${current_user//\\/\\\\}"
escaped_user_name="${escaped_user_name//&/\\&}"

sed \
  -e "s|__PROGRAM__|$escaped_helper_path|g" \
  -e "s|__ASSOCIATED_BUNDLE_IDENTIFIER__|$escaped_bundle_id|g" \
  -e "s|__USER_NAME__|$escaped_user_name|g" \
  "$INSTALLED_DAEMON_TEMPLATE" > "$TMP_DAEMON_PLIST"

export RAMA_TPROXY_SERVICE_NAME="$SERVICE_NAME"
export RAMA_TPROXY_OTHER_SERVICE_NAME="$OTHER_SERVICE_NAME"
export RAMA_TPROXY_INSTALLED_HELPER_APP="$INSTALLED_HELPER_APP"
export RAMA_TPROXY_INSTALLED_APP_HELPER_BUNDLE="$INSTALLED_APP_HELPER_BUNDLE"
export RAMA_TPROXY_INSTALLED_DAEMON_PLIST="$INSTALLED_DAEMON_PLIST"
export RAMA_TPROXY_OTHER_DAEMON_PLIST="$OTHER_DAEMON_PLIST"
export RAMA_TPROXY_TMP_DAEMON_PLIST="$TMP_DAEMON_PLIST"

/usr/bin/osascript <<'APPLESCRIPT'
on run
  set shellCommand to "set -euo pipefail; " & ¬
    "launchctl bootout system/$RAMA_TPROXY_SERVICE_NAME >/dev/null 2>&1 || true; " & ¬
    "launchctl bootout system/$RAMA_TPROXY_OTHER_SERVICE_NAME >/dev/null 2>&1 || true; " & ¬
    "rm -f \"$RAMA_TPROXY_INSTALLED_DAEMON_PLIST\" \"$RAMA_TPROXY_OTHER_DAEMON_PLIST\"; " & ¬
    "rm -rf \"$RAMA_TPROXY_INSTALLED_HELPER_APP\"; " & ¬
    "install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools /Library/LaunchDaemons; " & ¬
    "ditto \"$RAMA_TPROXY_INSTALLED_APP_HELPER_BUNDLE\" \"$RAMA_TPROXY_INSTALLED_HELPER_APP\"; " & ¬
    "chown -R root:wheel \"$RAMA_TPROXY_INSTALLED_HELPER_APP\"; " & ¬
    "install -o root -g wheel -m 644 \"$RAMA_TPROXY_TMP_DAEMON_PLIST\" \"$RAMA_TPROXY_INSTALLED_DAEMON_PLIST\"; " & ¬
    "launchctl bootstrap system \"$RAMA_TPROXY_INSTALLED_DAEMON_PLIST\"; " & ¬
    "launchctl kickstart -k system/$RAMA_TPROXY_SERVICE_NAME"
  do shell script shellCommand with administrator privileges
end run
APPLESCRIPT

if [[ "$RESET_PROFILE" == "1" ]]; then
  open -a "$INSTALLED_APP" --args --reset-profile-on-launch
else
  open "$INSTALLED_APP"
fi
