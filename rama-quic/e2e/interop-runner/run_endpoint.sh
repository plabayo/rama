#!/bin/bash
set -euo pipefail

case "${ROLE:-}" in
    client) binary=rama-quic-interop-client ;;
    server) binary=rama-quic-interop-server ;;
    *) echo "ROLE must be client or server" >&2; exit 1 ;;
esac

# Unknown cases must return 127 even without a running simulator.
"$binary" --check-testcase
/setup.sh
if [[ "$ROLE" == client ]]; then
    /wait-for-it.sh sim:57832 -s -t 30
fi
exec "$binary" "$@"
