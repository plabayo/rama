#!/usr/bin/env bash
# Mirror the latest completed main push; cancellation must not turn the badge red.
set -euo pipefail

workflow_id=$(jq -r .workflow_run.workflow_id "${GITHUB_EVENT_PATH}")
# Finished main pushes of this repo as `[run_number, run_attempt, conclusion]`.
# shellcheck disable=SC2016 # `$repo` is a jq variable
finished='[.[] | select(.event == "push" and .head_branch == "main"
    and .head_repository.full_name == $repo
    and .status == "completed" and .conclusion != "cancelled")
  | [.run_number, .run_attempt, .conclusion]]'
# The listing can trail this event, so its run counts too.
runs=$(jq -c --arg repo "${GITHUB_REPOSITORY}" "[.workflow_run] | ${finished}" "${GITHUB_EVENT_PATH}")
# The unfiltered listing, newest first: GitHub's branch/event/status filters can lag behind.
for page in {1..10}; do
  for attempt in 1 2 3; do
    listed=$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/${workflow_id}/runs?per_page=100&page=${page}") && break
    [[ ${attempt} == 3 ]] && exit 1
    sleep $((attempt * 10))
  done
  found=$(jq -c --arg repo "${GITHUB_REPOSITORY}" ".workflow_runs | ${finished}" <<<"${listed}")
  runs=$(jq -c --argjson found "${found}" '. + $found' <<<"${runs}")
  # The first page holding one holds the newest; a short page is the last.
  if [[ "${found}" != "[]" ]] || (( $(jq '.workflow_runs | length' <<<"${listed}") < 100 )); then
    break
  fi
done
conclusion=$(jq -r 'max_by(.[0:2]) | .[2] // "unknown"' <<<"${runs}")
echo "newest finished main CI run: ${conclusion}"
[[ "${conclusion}" == "success" ]]
