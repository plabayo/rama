#!/usr/bin/env bash
# Run `flyctl deploy` with the given arguments, retrying once when it stalls.
# A remote builder push can hang without ever failing; normal deploys take under two minutes.
set -euo pipefail

attempt() {
    timeout --kill-after=30s "${RAMA_FLY_DEPLOY_TIMEOUT:-8m}" flyctl deploy "$@"
}

status=0
attempt "$@" || status=$?
if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
    echo "::warning::flyctl deploy stalled; retrying once"
    attempt "$@"
elif [ "$status" -ne 0 ]; then
    exit "$status"
fi
