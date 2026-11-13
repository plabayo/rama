#!/usr/bin/env bash
# Write the cells that failed first in the previous run of this interop job to OUT.
# The runner retries nothing without that record, so a lookup that fails only costs the retry.
set -euo pipefail

backend=$1 group=$2 out=$3
prefix="quic-interop-first-failures-${backend}-${group}-attempt"
api="repos/${GITHUB_REPOSITORY}"

# The newest record of a run, as `attempt<TAB>artifact id`; `below` bounds the attempt.
record_of() {
  local run=$1 below=$2
  # shellcheck disable=SC2016 # `$prefix` and `$below` are jq variables
  gh api --paginate "${api}/actions/runs/${run}/artifacts?per_page=100" \
    | jq -rs --arg prefix "${prefix}" --argjson below "${below}" \
      '[.[].artifacts[] | select(.expired | not) | select(.name | startswith($prefix))
         | [(.name | ltrimstr($prefix) | tonumber), .id] | select(.[0] < $below)]
       | max_by(.[0]) // empty | @tsv'
}

# An earlier attempt of this run comes first, then earlier runs of this workflow on this branch.
candidates=()
if (( GITHUB_RUN_ATTEMPT > 1 )); then
  candidates+=("${GITHUB_RUN_ID} ${GITHUB_RUN_ATTEMPT}")
fi
workflow=$(gh api "${api}/actions/runs/${GITHUB_RUN_ID}" --jq .workflow_id)
branch=${GITHUB_HEAD_REF:-${GITHUB_REF_NAME}}
# A pull request's history is its own repository's: forks reuse branch names.
source=$(jq -r --arg base "${GITHUB_REPOSITORY}" '.pull_request.head.repo.full_name // $base' "${GITHUB_EVENT_PATH}")
# A run can be run again for 30 days and its record is kept for seven more.
since=$(date -u -d '38 days ago' +%Y-%m-%d)
listed=$(gh api --paginate -X GET "${api}/actions/workflows/${workflow}/runs" \
  -f branch="${branch}" -f event="${GITHUB_EVENT_NAME}" -f created=">=${since}" -f per_page=100)
# shellcheck disable=SC2016 # `$number` and `$source` are jq variables
earlier=$(jq -rs --argjson number "${GITHUB_RUN_NUMBER}" --arg source "${source}" \
  '[.[].workflow_runs[] | select(.run_number < $number and .head_repository.full_name == $source)]
   | sort_by(-.run_number) | .[].id' <<<"${listed}")
for run in ${earlier}; do
  candidates+=("${run} 1000000")
done

for candidate in ${candidates[@]+"${candidates[@]}"}; do
  read -r run below <<<"${candidate}"
  found=$(record_of "${run}" "${below}")
  [[ -z "${found}" ]] && continue
  read -r attempt artifact <<<"${found}"
  zip=$(mktemp)
  gh api "${api}/actions/artifacts/${artifact}/zip" >"${zip}"
  unzip -p "${zip}" first-failures.json \
    | jq --arg run "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${run}/attempts/${attempt}" \
      '{run: $run, first_failures: .}' >"${out}"
  rm -f "${zip}"
  echo "previous record: $(jq -c . "${out}")"
  exit 0
done
echo '{"run": null, "first_failures": []}' >"${out}"
echo "no earlier run of this job on ${branch} of ${source} left a record"
