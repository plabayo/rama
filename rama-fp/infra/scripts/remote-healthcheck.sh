#!/usr/bin/env bash
# One entry point for local runs and scheduled CI; options are documented by --help.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
exec uv run --frozen --project "$root/scripts/ci" python "$(dirname "$0")/remote_healthcheck.py" "$@"
