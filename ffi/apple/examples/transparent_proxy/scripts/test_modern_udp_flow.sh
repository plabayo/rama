#!/usr/bin/env bash
# macOS still ships Bash 3.2, where reading a declared-but-empty array under
# `set -u` raises an unbound-variable error. This script deliberately handles
# every command outcome and uses pipefail without nounset for host compatibility.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILT_APP="${1:-$ROOT_DIR/.xcode-derived/tproxy-app-dev/Build/Products/Debug/RamaTransparentProxyExampleContainer.app}"
PROBE="$SCRIPT_DIR/modern_udp_e2e_probe.py"
INSTALLER="$SCRIPT_DIR/install_tproxy_app_bundle.sh"
CONTAINER_LOG="$HOME/Library/Logs/RamaTransparentProxyExampleContainer.log"
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"

# Maintained public protocol endpoints. Override these when a runner's network
# filters a particular anycast service; IP literals keep provider-log assertions
# deterministic and avoid mixing resolver traffic into the target flow.
PASSTHROUGH_DNS="${RAMA_TPROXY_E2E_PASSTHROUGH_DNS:-1.1.1.1}"
INTERCEPT_NTP="${RAMA_TPROXY_E2E_INTERCEPT_NTP:-162.159.200.1}"
BLOCKED_DNS="${RAMA_TPROXY_E2E_BLOCKED_DNS:-8.8.8.8}"
HTTP3_URL="${RAMA_TPROXY_E2E_HTTP3_URL:-https://cloudflare.com/cdn-cgi/trace}"

TMP_DIR="$(mktemp -d /tmp/rama-modern-udp-e2e.XXXXXX)" || {
  echo "could not create modern UDP E2E artifact directory" >&2
  exit 2
}
PROVIDER_LOG="$TMP_DIR/provider.log"
HTTP3_RESULT="$TMP_DIR/http3-result.log"
EVIDENCE_STATUS="$TMP_DIR/udp-evidence-status.tsv"
DIAL9_BASELINE="$TMP_DIR/dial9-baseline.json"
DIAL9_SUMMARY="$TMP_DIR/dial9-evidence.json"

LOG_PID=""
PROFILE_NEEDS_RESTORE=0
PROFILE_RESTORED=1
LOG_STREAM_STARTED=0
LOG_STREAM_ALIVE_END=0
LOG_STREAM_JOINED=0
UDP_PROBE_ATTEMPT_COUNT=0
UDP_PROBE_PASS_COUNT=0
UDP_PRESSURE_LOG_CHECKED=0
RUST_UDP_DROP_TRANSITIONS=0
RUST_UDP_RESUME_TRANSITIONS=0
SWIFT_UDP_STAGING_DROP_SAMPLES=0
DIAL9_BASELINE_READY=0
DIAL9_BASELINE_MAX_INDEX=none
DIAL9_CURRENT_SEGMENT_COUNT=0
DIAL9_REQUIRED_PAIR_COUNT=0
NTP_FLOW_ID=""
MAIN_FINISHED=0
FINALIZING=0
CALLBACK_GENERATION=unknown
CURRENT_PHASE=preflight
ISSUES=()
FAILURES=()
OBSERVED_FAILURES=()

sanitize_diagnostic() {
  local value="$1"
  value="${value//$'\t'/ }"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "$value"
}

add_issue() {
  ISSUES+=("$(sanitize_diagnostic "$1")")
}

add_failure() {
  FAILURES+=("$(sanitize_diagnostic "$1")")
}

write_evidence_status() {
  local complete="$1" passed="$2" exit_code="$3"
  local tmp="$EVIDENCE_STATUS.tmp.$$" value
  {
    printf 'complete\t%s\npassed\t%s\nexit_code\t%s\n' \
      "$complete" "$passed" "$exit_code"
    printf 'udp_probe_attempt_count\t%s\nudp_probe_pass_count\t%s\n' \
      "$UDP_PROBE_ATTEMPT_COUNT" "$UDP_PROBE_PASS_COUNT"
    printf 'udp_pressure_log_checked\t%s\n' "$UDP_PRESSURE_LOG_CHECKED"
    printf 'rust_udp_drop_transitions\t%s\nrust_udp_resume_transitions\t%s\n' \
      "$RUST_UDP_DROP_TRANSITIONS" "$RUST_UDP_RESUME_TRANSITIONS"
    printf 'swift_udp_staging_drop_samples\t%s\n' \
      "$SWIFT_UDP_STAGING_DROP_SAMPLES"
    printf 'log_stream_started\t%s\nlog_stream_alive_end\t%s\nlog_stream_joined\t%s\n' \
      "$LOG_STREAM_STARTED" "$LOG_STREAM_ALIVE_END" "$LOG_STREAM_JOINED"
    printf 'profile_restored\t%s\n' "$PROFILE_RESTORED"
    printf 'callback_generation\t%s\n' "$CALLBACK_GENERATION"
    printf 'dial9_baseline_max_index\t%s\n' "$DIAL9_BASELINE_MAX_INDEX"
    printf 'dial9_required_flow_id\t%s\n' "${NTP_FLOW_ID:-none}"
    printf 'dial9_current_segment_count\t%s\n' "$DIAL9_CURRENT_SEGMENT_COUNT"
    printf 'dial9_required_pair_count\t%s\n' "$DIAL9_REQUIRED_PAIR_COUNT"
    printf 'schema_version\t1\n'
    for value in "${ISSUES[@]}"; do printf 'issue\t%s\n' "$value"; done
    for value in "${FAILURES[@]}"; do printf 'failure\t%s\n' "$value"; done
    for value in "${OBSERVED_FAILURES[@]}"; do
      printf 'observed_failure\t%s\n' "$value"
    done
    printf 'schema_complete\t1\n'
  } > "$tmp" && mv -f "$tmp" "$EVIDENCE_STATUS"
}

ISSUES=("signed UDP E2E did not reach its terminal verdict")
write_evidence_status 0 0 2
ISSUES=()

container_log_line() {
  if [[ -f "$CONTAINER_LOG" ]]; then
    wc -l < "$CONTAINER_LOG" | tr -d ' '
  else
    echo 0
  fi
}

provider_log_line() {
  if [[ -f "$PROVIDER_LOG" ]]; then
    wc -l < "$PROVIDER_LOG" | tr -d ' '
  else
    echo 0
  fi
}

wait_for_connected() {
  local starting_line="$1" connected=0
  for _ in $(seq 1 120); do
    if [[ -f "$CONTAINER_LOG" ]]; then
      if tail -n "+$((starting_line + 1))" "$CONTAINER_LOG" \
        | grep -Fq 'udp_e2e_restart=begin'; then
        # An already-active provider first reports its stale current status.
        # Accept connected only after this launch observed the asynchronous stop
        # complete and then a later transition back to connected.
        if tail -n "+$((starting_line + 1))" "$CONTAINER_LOG" | awk '
          /udp_e2e_restart=begin/ { restart = 1 }
          restart && /status transition .* -> disconnected/ { stopped = 1 }
          stopped && /status transition .* -> connected/ { connected = 1 }
          END { exit connected ? 0 : 1 }
        '; then
          connected=1
          break
        fi
      elif tail -n "+$((starting_line + 1))" "$CONTAINER_LOG" \
        | grep -Eq 'status transition .* -> connected'; then
        connected=1
        break
      fi
    fi
    sleep 0.5
  done
  if [[ "$connected" != 1 ]]; then
    echo "transparent proxy did not reach connected state" >&2
    tail -n 80 "$CONTAINER_LOG" 2>/dev/null || true
    return 1
  fi
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
stop_log_capture() {
  local child_rc=missing
  [[ -n "$LOG_PID" ]] || return 0
  if kill -0 "$LOG_PID" 2>/dev/null; then
    LOG_STREAM_ALIVE_END=1
    kill -TERM "$LOG_PID" 2>/dev/null || true
  else
    add_issue "provider log stream exited before evidence collection"
  fi
  for _ in $(seq 1 50); do
    kill -0 "$LOG_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$LOG_PID" 2>/dev/null; then
    kill -KILL "$LOG_PID" 2>/dev/null || true
    add_issue "provider log stream required forced termination"
  fi
  wait "$LOG_PID" 2>/dev/null
  child_rc=$?
  LOG_STREAM_JOINED=1
  LOG_PID=""
  case "$child_rc" in
    0|143) ;;
    *) add_issue "provider log stream exited with unexpected status $child_rc" ;;
  esac
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
restore_profile() {
  local starting_line
  (( PROFILE_NEEDS_RESTORE == 1 )) || return 0
  PROFILE_RESTORED=0
  starting_line="$(container_log_line)"
  if ! "$INSTALLER" dev "$BUILT_APP" 0 \
    "--udp-passthrough-ports=" \
    "--udp-blocked-endpoints=" \
    > "$TMP_DIR/restore.log" 2>&1
  then
    add_issue "automatic UDP policy restoration failed"
    return 1
  fi
  if ! wait_for_connected "$starting_line"; then
    add_issue "default UDP profile did not reconnect after restoration"
    return 1
  fi
  PROFILE_NEEDS_RESTORE=0
  PROFILE_RESTORED=1
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
collect_dial9_evidence() {
  local metrics
  (( DIAL9_REQUIRED_PAIR_COUNT == 0 )) || return 0
  (( DIAL9_BASELINE_READY == 1 )) || return 0
  if [[ ! "$NTP_FLOW_ID" =~ ^[0-9]+$ ]]; then
    add_issue "fresh NTP decision did not yield one exact flow_id for dial9 correlation"
    return 1
  fi
  # The unprivileged shell intentionally owns the artifact redirections.
  # shellcheck disable=SC2024
  if ! sudo -n "$DIAL9_EVIDENCE_BIN" collect \
    "$DIAL9_DIR" "$DIAL9_BASELINE" "$TMP_DIR/dial9-traces" \
    --wait-seconds 15 --flow-id "$NTP_FLOW_ID" --protocol 2 \
    > "$DIAL9_SUMMARY" 2> "$TMP_DIR/dial9-collect.err"
  then
    add_issue "current-run dial9 UDP flow evidence is unavailable"
    return 1
  fi
  sudo -n chown -R "$(id -u):$(id -g)" \
    "$TMP_DIR/dial9-traces" "$DIAL9_SUMMARY" 2>/dev/null || {
      add_issue "could not transfer dial9 evidence artifact ownership"
      return 1
    }
  metrics="$(/usr/bin/python3 - "$DIAL9_SUMMARY" "$NTP_FLOW_ID" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1]))
    fields = (value["current_segment_count"], value["required_pair_count"])
    if value.get("schema_version") != 1 or value.get("schema_complete") is not True:
        raise ValueError("incomplete schema")
    if not all(isinstance(field, int) and field >= 1 for field in fields):
        raise ValueError("missing current pair")
    if value.get("required_flow_id") != int(sys.argv[2]):
        raise ValueError("required flow identity mismatch")
    if value.get("required_protocol") != 2:
        raise ValueError("required protocol mismatch")
    print(*fields)
except Exception:
    raise SystemExit(2)
PY
)" || {
    add_issue "dial9 evidence summary is malformed or incomplete"
    return 1
  }
  read -r DIAL9_CURRENT_SEGMENT_COUNT DIAL9_REQUIRED_PAIR_COUNT <<< "$metrics"
}

# shellcheck disable=SC2329  # invoked by trap
finalize() {
  local raw_exit="$?" final_exit=2 complete=0 passed=0 value parsed_status
  (( FINALIZING == 0 )) || return
  FINALIZING=1
  trap - EXIT INT TERM
  if (( MAIN_FINISHED == 0 && raw_exit != 0 && ${#ISSUES[@]} == 0 )); then
    add_issue "unhandled command failure in phase $CURRENT_PHASE (exit $raw_exit)"
  fi
  stop_log_capture
  restore_profile || true
  collect_dial9_evidence || true
  if (( UDP_PROBE_ATTEMPT_COUNT != 5 )); then
    add_issue "signed UDP E2E attempted $UDP_PROBE_ATTEMPT_COUNT of 5 required probes"
  fi
  if (( UDP_PRESSURE_LOG_CHECKED != 1 )); then
    add_issue "signed UDP E2E did not validate UDP pressure telemetry"
  fi
  if (( ${#ISSUES[@]} > 0 )); then
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
  elif (( ${#FAILURES[@]} > 0 )); then
    complete=1
    final_exit=1
  elif (( UDP_PROBE_PASS_COUNT != 5 )); then
    add_issue "signed UDP E2E passed $UDP_PROBE_PASS_COUNT of 5 required probes"
  else
    complete=1
    passed=1
    final_exit=0
  fi
  write_evidence_status "$complete" "$passed" "$final_exit"
  parsed_status=$(/usr/bin/python3 "$SCRIPT_DIR/modern_udp_evidence.py" \
    "$EVIDENCE_STATUS" 2>/dev/null) || parsed_status=invalid
  if [[ "$parsed_status" != "$final_exit" ]]; then
    add_issue "terminal UDP evidence status failed strict self-validation"
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
    final_exit=2
    write_evidence_status 0 0 2
  fi
  echo "modern UDP E2E artifacts: $TMP_DIR"
  exit "$final_exit"
}

trap finalize EXIT
trap 'add_issue "signed UDP E2E interrupted by signal"; exit 2' INT TERM

fatal_issue() {
  add_issue "$1"
  echo "$1" >&2
  exit 2
}

run_probe() {
  local description="$1" expected_product_rc="$2"
  shift 2
  local rc=0
  UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
  /usr/bin/python3 "$PROBE" "$@" || rc=$?
  case "$rc" in
    0) UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1)) ;;
    10)
      if [[ "$expected_product_rc" == 10 ]]; then
        add_failure "$description received a valid response despite the block policy"
      else
        add_issue "$description returned an unexpected product-violation outcome"
      fi
      ;;
    *) add_issue "$description failed to produce valid protocol evidence (probe exit $rc)" ;;
  esac
}

decision_records() {
  local starting_line="$1"
  tail -n "+$((starting_line + 1))" "$PROVIDER_LOG" 2>/dev/null | sed -nE \
    's/.*udp_e2e_decision rama_decision=([^ ]+) flow_id=([0-9]+) remote_endpoint=([^ ]+) source_app=([^ ]+).*/\1\t\2\t\3\t\4/p'
}

check_exact_decision() {
  local starting_line="$1" expected="$2" endpoint="$3" source_app="$4" description="$5"
  local action flow_id remote source found=0
  local ids=()
  while IFS=$'\t' read -r action flow_id remote source; do
    [[ "$remote" == "$endpoint" && "$source" == "$source_app" ]] || continue
    found=$((found + 1))
    if [[ "$action" != "$expected" ]]; then
      add_failure "$description recorded rama_decision=$action instead of $expected"
    else
      ids+=("$flow_id")
    fi
  done < <(decision_records "$starting_line")
  if (( found == 0 )); then
    add_issue "missing provider log assertion: $description"
    return 1
  fi
  if (( found != 1 )); then
    add_issue "$description did not have one unambiguous decision record"
    return 1
  fi
  if [[ "$expected" == intercept ]]; then
    if (( ${#ids[@]} != 1 )); then
      add_issue "$description did not have one unambiguous flow_id"
      return 1
    fi
    NTP_FLOW_ID="${ids[0]}"
  fi
}

check_udp_pressure_logs() {
  local metrics status
  metrics="$(/usr/bin/python3 - "$SCRIPT_DIR" "$PROVIDER_LOG" \
    "$UNBLOCKED_LOG_LINE" "$BLOCKED_LOG_LINE" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from soak_pressure_log import summarize_udp_pressure_rows

try:
    with open(sys.argv[2], encoding="utf-8") as provider_log:
        lines = provider_log.read().splitlines()
    unblocked_start = int(sys.argv[3])
    blocked_start = int(sys.argv[4])
    if not 0 <= unblocked_start <= blocked_start <= len(lines):
        raise ValueError("invalid provider log phase boundaries")
    segments = (lines[unblocked_start:blocked_start], lines[blocked_start:])
    summaries = [
        summarize_udp_pressure_rows(
            list(enumerate(segment, start=1)),
            workload_exercised=True,
            mode="stress-only",
        )
        for segment in segments
    ]
    if any(summary["issues"] for summary in summaries):
        status = "INCOMPLETE"
    elif any(summary["failures"] for summary in summaries):
        status = "FAILED"
    else:
        status = "GOOD"
    print(
        status,
        sum(summary["drop_transitions"] for summary in summaries),
        sum(summary["resume_transitions"] for summary in summaries),
        sum(summary["swift_staging_drop_samples"] for summary in summaries),
    )
except Exception:
    raise SystemExit(2)
PY
)" || {
    add_issue "could not parse phase-local UDP pressure telemetry"
    return 1
  }
  read -r status RUST_UDP_DROP_TRANSITIONS RUST_UDP_RESUME_TRANSITIONS \
    SWIFT_UDP_STAGING_DROP_SAMPLES <<< "$metrics"
  if [[ ! "$RUST_UDP_DROP_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$RUST_UDP_RESUME_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$SWIFT_UDP_STAGING_DROP_SAMPLES" =~ ^[0-9]+$ ]]
  then
    add_issue "UDP pressure telemetry verdict returned malformed counters"
    return 1
  fi
  UDP_PRESSURE_LOG_CHECKED=1
  if (( RUST_UDP_DROP_TRANSITIONS > 0 || SWIFT_UDP_STAGING_DROP_SAMPLES > 0 )); then
    add_failure "UDP pressure telemetry recorded ingress loss (Rust drops=$RUST_UDP_DROP_TRANSITIONS, Swift staging samples=$SWIFT_UDP_STAGING_DROP_SAMPLES)"
  fi
  case "$status" in
    GOOD) ;;
    FAILED) ;;
    INCOMPLETE) add_issue "UDP pressure telemetry was redacted or malformed" ;;
    *) add_issue "UDP pressure telemetry verdict was unrecognized"; return 1 ;;
  esac
}

case "$(uname -m)" in
  arm64) DIAL9_EVIDENCE_BIN="$ROOT_DIR/tproxy_rs/target/aarch64-apple-darwin/debug/dial9_evidence" ;;
  x86_64) DIAL9_EVIDENCE_BIN="$ROOT_DIR/tproxy_rs/target/x86_64-apple-darwin/debug/dial9_evidence" ;;
  *) DIAL9_EVIDENCE_BIN="" ;;
esac

[[ "$(uname -s)" == Darwin ]] \
  || fatal_issue "modern UDP Network Extension E2E requires macOS"
MACOS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
CALLBACK_GENERATION=modern
if (( MACOS_MAJOR < 15 )); then
  if [[ "${RAMA_TPROXY_ALLOW_LEGACY_UDP_E2E:-0}" != 1 ]]; then
    fatal_issue "modern UDP Network Extension E2E requires macOS 15 or newer"
  fi
  CALLBACK_GENERATION=legacy
fi
[[ -d "$BUILT_APP" ]] \
  || fatal_issue "signed app not found at $BUILT_APP; build it before running this test"
command -v nscurl >/dev/null \
  || fatal_issue "nscurl is required for the public HTTP/3 UDP/443 probe"
[[ -x "$DIAL9_EVIDENCE_BIN" ]] \
  || fatal_issue "dial9 evidence collector is missing; run just build-tproxy-rs"
sudo -n true 2>/dev/null \
  || fatal_issue "cached sudo credentials are required for root-owned dial9 evidence"

CURRENT_PHASE=dial9-baseline
# The unprivileged shell intentionally owns the artifact redirections.
# shellcheck disable=SC2024
if ! sudo -n "$DIAL9_EVIDENCE_BIN" snapshot "$DIAL9_DIR" --allow-missing \
  > "$DIAL9_BASELINE" 2> "$TMP_DIR/dial9-baseline.err"
then
  fatal_issue "could not capture the pre-run dial9 trace identity"
fi
DIAL9_BASELINE_MAX_INDEX="$(/usr/bin/python3 - "$DIAL9_BASELINE" <<'PY'
import json, sys
value = json.load(open(sys.argv[1])).get("max_index")
print("none" if value is None else value)
PY
)" || fatal_issue "pre-run dial9 identity manifest is malformed"
DIAL9_BASELINE_READY=1

CURRENT_PHASE=log-start
/usr/bin/log stream --level debug --style compact \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"' \
  > "$PROVIDER_LOG" 2>&1 &
LOG_PID=$!
sleep 0.5
if kill -0 "$LOG_PID" 2>/dev/null; then
  LOG_STREAM_STARTED=1
else
  fatal_issue "provider log stream did not stay alive"
fi

# First install an unblocked profile. Besides exercising pass-through and
# intercept, this proves the future blocked endpoint is healthy immediately
# before the block rule is enabled.
CURRENT_PHASE=unblocked-install
UNBLOCKED_CONTAINER_LINE="$(container_log_line)"
PROFILE_NEEDS_RESTORE=1
PROFILE_RESTORED=0
if ! "$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=443" \
  "--udp-blocked-endpoints="
then
  fatal_issue "could not install the unblocked UDP E2E profile"
fi
wait_for_connected "$UNBLOCKED_CONTAINER_LINE" \
  || fatal_issue "unblocked UDP E2E profile did not connect"

# Ignore teardown/startup errors from the provider instance being replaced.
sleep 1
UNBLOCKED_LOG_LINE="$(provider_log_line)"
UDP_ERROR_PROVIDER_LOG_LINE="$UNBLOCKED_LOG_LINE"

CURRENT_PHASE=unblocked-probes
run_probe "pass-through DNS control" none dns --server "$PASSTHROUGH_DNS"
run_probe "intercept NTP control" none ntp --server "$INTERCEPT_NTP"
run_probe "future blocked DNS control" none dns --server "$BLOCKED_DNS"

HTTP3_SEPARATOR='?'
[[ "$HTTP3_URL" == *\?* ]] && HTTP3_SEPARATOR='&'
HTTP3_PROVIDER_LOG_LINE="$(provider_log_line)"
UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
HTTP3_RC=0
nscurl --http3-prior-knowledge -m 15 \
  "${HTTP3_URL}${HTTP3_SEPARATOR}rama_udp_e2e=$(date +%s)-$$" \
  > "$HTTP3_RESULT" 2>&1 || HTTP3_RC=$?
if (( HTTP3_RC == 0 )) && grep -Fq 'http=http/3' "$HTTP3_RESULT"; then
  UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1))
else
  add_issue "public UDP/443 probe did not complete over HTTP/3"
fi

# Reinstall with one exact public DNS endpoint blocked. A new client socket is
# used below, so this must create a fresh NE flow and decision.
CURRENT_PHASE=blocked-install
BLOCKED_CONTAINER_LINE="$(container_log_line)"
if ! "$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=443" \
  "--udp-blocked-endpoints=$BLOCKED_DNS:53"
then
  fatal_issue "could not install the blocked UDP E2E profile"
fi
wait_for_connected "$BLOCKED_CONTAINER_LINE" \
  || fatal_issue "blocked UDP E2E profile did not connect"
BLOCKED_LOG_LINE="$(provider_log_line)"

CURRENT_PHASE=blocked-probe
run_probe "blocked DNS probe" 10 dns --server "$BLOCKED_DNS" \
  --timeout 4 --expect-no-response

# Let os_log and the Rust tracing bridge flush the per-flow decision/service
# records before assertions.
sleep 2
CURRENT_PHASE=log-quiesce
stop_log_capture
CURRENT_PHASE=log-verdicts
check_exact_decision "$UNBLOCKED_LOG_LINE" passthrough "$PASSTHROUGH_DNS:53" \
  com.apple.python3 "Rust pass-through decision for public DNS"
check_exact_decision "$UNBLOCKED_LOG_LINE" intercept "$INTERCEPT_NTP:123" \
  com.apple.python3 "Rust intercept decision for public NTP forwarding"
check_exact_decision "$BLOCKED_LOG_LINE" blocked "$BLOCKED_DNS:53" \
  com.apple.python3 "Rust blocked decision for an exact public DNS endpoint"

HTTP3_FOUND=0
while IFS=$'\t' read -r action _ remote source; do
  [[ "$remote" == *:443 && "$source" == com.apple.nscurl ]] || continue
  HTTP3_FOUND=1
  [[ "$action" == passthrough ]] \
    || add_failure "public HTTP/3 UDP/443 flow recorded rama_decision=$action instead of passthrough"
done < <(decision_records "$HTTP3_PROVIDER_LOG_LINE")
(( HTTP3_FOUND == 1 )) \
  || add_issue "missing provider log assertion: public HTTP/3 UDP/443 pass-through"

# Open/read/write markers are emitted only for errors the provider classifier
# considers unexpected. Benign teardown races have no public marker.
if tail -n "+$((UDP_ERROR_PROVIDER_LOG_LINE + 1))" "$PROVIDER_LOG" | grep -E \
  'flow_callback_error operation=udp_flow\.(open|read|write)' >/dev/null
then
  add_failure "provider emitted an unexpected UDP flow error during the live test"
fi

check_udp_pressure_logs || true

# Collect before restoring again: at this point the NTP provider generation is
# sealed, while the blocked provider's active segment cannot introduce a
# colliding flow ID from a later generation.
CURRENT_PHASE=dial9-verdict
collect_dial9_evidence || true

MAIN_FINISHED=1
CURRENT_PHASE=finalize
echo "$CALLBACK_GENERATION UDP Network Extension E2E probes completed; finalizing evidence"
echo "pass-through DNS=$PASSTHROUGH_DNS:53 intercept NTP=$INTERCEPT_NTP:123 blocked DNS=$BLOCKED_DNS:53 UDP/443=$HTTP3_URL"
exit 0
