#!/usr/bin/env bash
# Download the locked dependencies of each project directory given, before the checks start.
# A registry or DNS outage then costs a retry here instead of a check an hour into the job.
set -euo pipefail

for project in "$@"; do
  for attempt in 1 2 3 4 5; do
    if cargo fetch --locked --manifest-path "${project}/Cargo.toml"; then
      continue 2
    fi
    echo "cargo fetch failed for ${project} (attempt ${attempt} of 5)"
    if ((attempt < 5)); then sleep $((attempt * 15)); fi
  done
  # CI-retry reruns a job that fails with this message.
  echo "::error::cargo-fetch: could not fetch dependencies of ${project}"
  exit 1
done
