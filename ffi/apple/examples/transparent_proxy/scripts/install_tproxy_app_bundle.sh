#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <dev|dist> <built-app-path> <reset-profile:0|1>" >&2
  exit 1
fi

MODE="$1"
BUILT_APP="$2"
RESET_PROFILE="$3"

INSTALLED_APP="/Applications/RamaTransparentProxyExampleContainer.app"

case "$MODE" in
  dev|dist)
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 1
    ;;
esac

pkill -f '/Applications/RamaTransparentProxyExampleContainer.app/Contents/MacOS/RamaTransparentProxyExampleContainer' || true
sleep 1
rm -rf "$INSTALLED_APP"
ditto "$BUILT_APP" "$INSTALLED_APP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$BUILT_APP" || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$INSTALLED_APP"

if [[ "$RESET_PROFILE" == "1" ]]; then
  open -a "$INSTALLED_APP" --args --reset-profile-on-launch
else
  open "$INSTALLED_APP"
fi
