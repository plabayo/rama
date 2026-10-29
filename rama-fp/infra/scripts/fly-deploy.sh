#!/usr/bin/env bash
# Run `flyctl deploy` with the given arguments, retrying once when it stalls.
# A remote builder push can hang without ever failing; normal deploys take under two minutes.
set -euo pipefail

limit="${RAMA_FLY_DEPLOY_TIMEOUT_SECS:-480}"

attempt() {
    timeout --kill-after=30s "${limit}s" flyctl deploy "$@"
}

status=0
started=$SECONDS
attempt "$@" || status=$?
# 137 is also a kill from elsewhere, such as the OOM killer; only the watchdog's own expiry is a stall.
if { [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; } && [ $((SECONDS - started)) -ge "$limit" ]; then
    echo "::warning::flyctl deploy stalled; retrying once"
    attempt "$@"
elif [ "$status" -ne 0 ]; then
    exit "$status"
fi
