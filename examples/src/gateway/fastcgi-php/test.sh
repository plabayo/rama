#!/usr/bin/env bash
# Run both rama-fastcgi-php example harnesses in sequence.
#
# Forwards the mode argument (test|run) to each sub-script; default test.
# Note: in `run` mode the two sub-scripts execute one after the other —
# you'll see the gateway boot, Ctrl-C to stop it, then the migration boots.
# If you want to play with just one, invoke its `run.sh` directly.
#
# Exits 0 on success, 77 if a required dependency (php-fpm, jq) is missing.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-test}"
"$HERE/gateway/run.sh"   "$MODE"
"$HERE/migration/run.sh" "$MODE"
