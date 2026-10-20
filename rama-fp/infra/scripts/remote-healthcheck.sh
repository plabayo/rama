#!/usr/bin/env bash
# One entry point for local runs and scheduled CI; options are documented by --help.
set -euo pipefail
exec python3 "$(dirname "$0")/remote_healthcheck.py" "$@"
