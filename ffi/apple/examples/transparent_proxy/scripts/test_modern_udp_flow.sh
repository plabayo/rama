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
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"

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
DIAL9_REQUIRED_CLOSE_REASON=none
DIAL9_REQUIRED_CLOSE_REASON_NAME=none
DIAL9_REQUIRED_CLOSE_AGE_MS=none
DIAL9_CLOSE_AGE_BOUND_MS=0
DIAL9_REQUIRED_BYTES_IN=none
DIAL9_REQUIRED_BYTES_OUT=none
NTP_FLOW_ID=""
PROVIDER_PID=""
PROVIDER_IDENTITY=""
PROVIDER_IDENTITY_STABLE=0
HTTP3_SOURCE_PID=none
HTTP3_FLOW_ID=none
HTTP3_REMOTE_ENDPOINT=none
RUN_UUID=none
PASSTHROUGH_DNS_SOURCE_PID=none
PASSTHROUGH_DNS_FLOW_ID=none
CONTROL_DNS_SOURCE_PID=none
CONTROL_DNS_FLOW_ID=none
NTP_SOURCE_PID=none
BLOCKED_DNS_SOURCE_PID=none
BLOCKED_DNS_FLOW_ID=none
PRESSURE_SOURCE_PID=none
PRESSURE_FLOW_ID=none
PRESSURE_PROBE_ATTEMPTED=0
PRESSURE_PROBE_PASSED=0
PRESSURE_DROP_TRANSITIONS=0
PRESSURE_RESUME_TRANSITIONS=0
PRESSURE_DROP_REASONS=none
PRESSURE_RECOVERED_REASONS=none
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
    printf 'run_uuid\t%s\n' "$RUN_UUID"
    printf 'provider_pid\t%s\nprovider_identity\t%s\nprovider_identity_stable\t%s\n' \
      "${PROVIDER_PID:-none}" "${PROVIDER_IDENTITY:-none}" "$PROVIDER_IDENTITY_STABLE"
    printf 'http3_source_pid\t%s\n' "$HTTP3_SOURCE_PID"
    printf 'http3_flow_id\t%s\nhttp3_remote_endpoint\t%s\n' \
      "$HTTP3_FLOW_ID" "$HTTP3_REMOTE_ENDPOINT"
    printf 'pressure_probe_attempted\t%s\npressure_probe_passed\t%s\n' \
      "$PRESSURE_PROBE_ATTEMPTED" "$PRESSURE_PROBE_PASSED"
    printf 'pressure_drop_transitions\t%s\npressure_resume_transitions\t%s\n' \
      "$PRESSURE_DROP_TRANSITIONS" "$PRESSURE_RESUME_TRANSITIONS"
    printf 'pressure_drop_reasons\t%s\npressure_recovered_reasons\t%s\n' \
      "$PRESSURE_DROP_REASONS" "$PRESSURE_RECOVERED_REASONS"
    printf 'passthrough_dns_source_pid\t%s\npassthrough_dns_flow_id\t%s\n' \
      "$PASSTHROUGH_DNS_SOURCE_PID" "$PASSTHROUGH_DNS_FLOW_ID"
    printf 'control_dns_source_pid\t%s\ncontrol_dns_flow_id\t%s\n' \
      "$CONTROL_DNS_SOURCE_PID" "$CONTROL_DNS_FLOW_ID"
    printf 'ntp_source_pid\t%s\nntp_flow_id\t%s\n' "$NTP_SOURCE_PID" "${NTP_FLOW_ID:-none}"
    printf 'pressure_source_pid\t%s\npressure_flow_id\t%s\n' \
      "$PRESSURE_SOURCE_PID" "$PRESSURE_FLOW_ID"
    printf 'blocked_dns_source_pid\t%s\nblocked_dns_flow_id\t%s\n' \
      "$BLOCKED_DNS_SOURCE_PID" "$BLOCKED_DNS_FLOW_ID"
    printf 'dial9_baseline_max_index\t%s\n' "$DIAL9_BASELINE_MAX_INDEX"
    printf 'dial9_required_flow_id\t%s\n' "${NTP_FLOW_ID:-none}"
    printf 'dial9_current_segment_count\t%s\n' "$DIAL9_CURRENT_SEGMENT_COUNT"
    printf 'dial9_required_pair_count\t%s\n' "$DIAL9_REQUIRED_PAIR_COUNT"
    printf 'dial9_required_close_reason\t%s\n' "$DIAL9_REQUIRED_CLOSE_REASON"
    printf 'dial9_required_close_reason_name\t%s\n' "$DIAL9_REQUIRED_CLOSE_REASON_NAME"
    printf 'dial9_required_close_age_ms\t%s\n' "$DIAL9_REQUIRED_CLOSE_AGE_MS"
    printf 'dial9_close_age_bound_ms\t%s\n' "$DIAL9_CLOSE_AGE_BOUND_MS"
    printf 'dial9_required_bytes_in\t%s\ndial9_required_bytes_out\t%s\n' \
      "$DIAL9_REQUIRED_BYTES_IN" "$DIAL9_REQUIRED_BYTES_OUT"
    printf 'schema_version\t3\n'
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

provider_process_identity() {
  local pid="$1" snapshot digest
  snapshot="$(ps -ww -o pid= -o lstart= -o command= -p "$pid" 2>/dev/null)"
  [[ -n "$snapshot" ]] || return 1
  digest="$(printf '%s' "$snapshot" | shasum -a 256 | awk 'NR == 1 { print $1 }')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

capture_provider_identity() {
  local candidates
  candidates="$(pgrep -f "$PROVIDER_BUNDLE" 2>/dev/null || true)"
  if [[ ! "$candidates" =~ ^[1-9][0-9]*$ ]]; then
    add_issue "signed UDP E2E could not resolve exactly one provider process"
    return 1
  fi
  PROVIDER_PID="$candidates"
  PROVIDER_IDENTITY="$(provider_process_identity "$PROVIDER_PID" || true)"
  if [[ ! "$PROVIDER_IDENTITY" =~ ^[0-9a-f]{64}$ ]]; then
    add_issue "signed UDP E2E could not fingerprint the provider process"
    return 1
  fi
  PROVIDER_IDENTITY_STABLE=1
}

require_provider_identity() {
  local observed
  observed="$(provider_process_identity "$PROVIDER_PID" || true)"
  if [[ "$observed" != "$PROVIDER_IDENTITY" ]]; then
    PROVIDER_IDENTITY_STABLE=0
    add_issue "provider process identity changed during signed UDP evidence collection"
    return 1
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
  local metrics gate_end_monotonic_ms
  (( DIAL9_REQUIRED_PAIR_COUNT == 0 )) || return 0
  (( DIAL9_BASELINE_READY == 1 )) || return 0
  if [[ ! "$NTP_FLOW_ID" =~ ^[0-9]+$ ]]; then
    add_issue "fresh NTP decision did not yield one exact flow_id for dial9 correlation"
    return 1
  fi
  gate_end_monotonic_ms="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')"
  DIAL9_CLOSE_AGE_BOUND_MS=$((gate_end_monotonic_ms - GATE_START_MONOTONIC_MS))
  (( DIAL9_CLOSE_AGE_BOUND_MS > 0 )) || {
    add_issue "signed UDP gate produced an invalid monotonic evidence window"
    return 1
  }
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
  metrics="$(/usr/bin/python3 - "$DIAL9_SUMMARY" "$NTP_FLOW_ID" \
    "$DIAL9_CLOSE_AGE_BOUND_MS" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1]))
    fields = (
        value["current_segment_count"], value["required_pair_count"],
        value["required_close_reason"], value["required_close_age_ms"],
        value["required_bytes_in"], value["required_bytes_out"],
    )
    if value.get("schema_version") != 1 or value.get("schema_complete") is not True:
        raise ValueError("incomplete schema")
    if not all(isinstance(field, int) and field >= 1 for field in fields[:2]):
        raise ValueError("missing current pair")
    if value.get("required_flow_id") != int(sys.argv[2]):
        raise ValueError("required flow identity mismatch")
    if value.get("required_protocol") != 2:
        raise ValueError("required protocol mismatch")
    reason, age_ms, bytes_in, bytes_out = fields[2:]
    reason_name = value.get("required_close_reason_name")
    names = {
        1: "shutdown", 2: "idle_timeout", 3: "peer_eof_left",
        4: "peer_eof_right", 5: "read_error_left", 6: "read_error_right",
        7: "write_error_left", 8: "write_error_right", 9: "peek_timeout",
        10: "handler_deadline", 11: "paused_timeout", 12: "first_byte_timeout",
        13: "max_lifetime", 14: "service_panic",
    }
    if names.get(reason) != reason_name:
        raise ValueError("unknown or mismatched close reason")
    if not isinstance(age_ms, int) or not 0 <= age_ms <= int(sys.argv[3]):
        raise ValueError("invalid close age")
    if not all(isinstance(field, int) and field >= 0 for field in (bytes_in, bytes_out)):
        raise ValueError("invalid NTP byte counters")
    print(fields[0], fields[1], reason, reason_name, age_ms, bytes_in, bytes_out)
except Exception:
    raise SystemExit(2)
PY
)" || {
    add_issue "dial9 evidence summary is malformed or incomplete"
    return 1
  }
  read -r DIAL9_CURRENT_SEGMENT_COUNT DIAL9_REQUIRED_PAIR_COUNT \
    DIAL9_REQUIRED_CLOSE_REASON DIAL9_REQUIRED_CLOSE_REASON_NAME \
    DIAL9_REQUIRED_CLOSE_AGE_MS \
    DIAL9_REQUIRED_BYTES_IN DIAL9_REQUIRED_BYTES_OUT <<< "$metrics"
  if [[ "$DIAL9_REQUIRED_CLOSE_REASON" != 1 \
    || "$DIAL9_REQUIRED_CLOSE_REASON_NAME" != shutdown ]]
  then
    add_failure "NTP Dial9 pair closed with non-benign reason=$DIAL9_REQUIRED_CLOSE_REASON ($DIAL9_REQUIRED_CLOSE_REASON_NAME)"
  fi
  if (( DIAL9_REQUIRED_BYTES_IN < 48 || DIAL9_REQUIRED_BYTES_OUT < 48 )); then
    add_failure "NTP Dial9 pair did not record a complete request and response"
  fi
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
  if (( PRESSURE_PROBE_ATTEMPTED != 1 || PRESSURE_PROBE_PASSED != 1 )); then
    add_issue "signed UDP E2E did not complete the deliberate pressure probe"
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
  LAST_PROBE_LOG_START="$(provider_log_line)"
  /usr/bin/python3 "$PROBE" "$@" &
  LAST_PROBE_PID=$!
  wait "$LAST_PROBE_PID" || rc=$?
  close_probe_decision_window "$LAST_PROBE_LOG_START" "$LAST_PROBE_PID"
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
  local starting_line="$1" ending_line="$2"
  sed -n "$((starting_line + 1)),${ending_line}p" "$PROVIDER_LOG" 2>/dev/null | sed -nE \
    's/.*udp_e2e_decision rama_decision=([^ ]+) flow_id=([0-9]+) remote_endpoint=([^ ]+) source_app=([^ ]+) source_pid=([0-9]+).*/\1\t\2\t\3\t\4\t\5/p'
}

close_probe_decision_window() {
  local starting_line="$1" source_pid="$2" ending_line snapshot="" previous=""
  local stable_ticks=0
  # Require a decision-prefix quiescence interval after the first delivery.
  # This catches delayed duplicate rows without widening the PID window across
  # later probes, where process-id reuse could otherwise create ambiguity.
  for _ in $(seq 1 100); do
    ending_line="$(provider_log_line)"
    snapshot="$(decision_records "$starting_line" "$ending_line" \
      | awk -F '\t' -v pid="$source_pid" '$5 == pid')"
    if [[ -n "$snapshot" ]]; then
      if [[ "$snapshot" == "$previous" ]]; then
        stable_ticks=$((stable_ticks + 1))
      else
        stable_ticks=0
      fi
      if (( stable_ticks >= 10 )); then
        LAST_PROBE_LOG_END="$ending_line"
        return 0
      fi
    else
      stable_ticks=0
    fi
    previous="$snapshot"
    sleep 0.1
  done
  LAST_PROBE_LOG_END="$(provider_log_line)"
}

close_pressure_probe_window() {
  local starting_line="$1" source_pid="$2" endpoint="$3" source_app="$4"
  local ending_line observation terminal flow_id fingerprint previous=""
  local stable_ticks=0
  # A terminal pressure window is one exact PID/app/endpoint decision plus a
  # drop→reason-specific recovery sequence on that decision's flow_id. Keep
  # observing it for one bounded quiescence interval before freezing the end.
  for _ in $(seq 1 150); do
    ending_line="$(provider_log_line)"
    observation="$(/usr/bin/python3 - "$SCRIPT_DIR" "$PROVIDER_LOG" \
      "$starting_line" "$source_pid" "$endpoint" "$source_app" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from modern_udp_evidence import pressure_window_observation

with open(sys.argv[2], encoding="utf-8") as provider_log:
    lines = provider_log.read().splitlines()
result = pressure_window_observation(
    lines, int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]
)
print(
    1 if result["terminal"] else 0,
    result["flow_id"] if result["flow_id"] is not None else "none",
    result["fingerprint"],
)
PY
)" || observation=""
    read -r terminal flow_id fingerprint <<< "$observation"
    if [[ "$terminal" == 1 && "$flow_id" =~ ^[1-9][0-9]*$ \
      && "$fingerprint" =~ ^[0-9a-f]{64}$ ]]
    then
      if [[ "$fingerprint" == "$previous" ]]; then
        stable_ticks=$((stable_ticks + 1))
      else
        stable_ticks=0
      fi
      if (( stable_ticks >= 10 )); then
        PRESSURE_FLOW_ID="$flow_id"
        LAST_PROBE_LOG_END="$ending_line"
        return 0
      fi
    else
      stable_ticks=0
    fi
    previous="$fingerprint"
    sleep 0.1
  done
  LAST_PROBE_LOG_END="$(provider_log_line)"
  add_issue "deliberate UDP pressure flow did not reach a flow-bound terminal recovery window"
  return 1
}

check_exact_decision() {
  local starting_line="$1" ending_line="$2" expected="$3" endpoint="$4"
  local source_app="$5" expected_pid="$6" description="$7" target="$8"
  local action flow_id remote source source_pid found=0 unexpected=0 matching_flow_id=""
  while IFS=$'\t' read -r action flow_id remote source source_pid; do
    [[ "$source_pid" == "$expected_pid" ]] || continue
    if [[ "$remote" != "$endpoint" || "$source" != "$source_app" ]]; then
      unexpected=$((unexpected + 1))
      continue
    fi
    found=$((found + 1))
    matching_flow_id="$flow_id"
    if [[ "$action" != "$expected" ]]; then
      add_failure "$description recorded rama_decision=$action instead of $expected"
    fi
  done < <(decision_records "$starting_line" "$ending_line")
  if (( unexpected > 0 )); then
    add_issue "$description source PID had an unexpected app or endpoint decision"
  fi
  if (( found == 0 )); then
    add_issue "missing provider log assertion: $description"
    return 1
  fi
  if (( found != 1 )); then
    add_issue "$description did not have one unambiguous decision record"
    return 1
  fi
  case "$target" in
    passthrough) PASSTHROUGH_DNS_FLOW_ID="$matching_flow_id" ;;
    control) CONTROL_DNS_FLOW_ID="$matching_flow_id" ;;
    ntp) NTP_FLOW_ID="$matching_flow_id" ;;
    pressure) PRESSURE_FLOW_ID="$matching_flow_id" ;;
    blocked) BLOCKED_DNS_FLOW_ID="$matching_flow_id" ;;
    http3) HTTP3_FLOW_ID="$matching_flow_id"; HTTP3_REMOTE_ENDPOINT="$endpoint" ;;
    *) add_issue "internal decision target is invalid: $target"; return 1 ;;
  esac
}

check_udp_pressure_logs() {
  local metrics status
  metrics="$(/usr/bin/python3 - "$SCRIPT_DIR" "$PROVIDER_LOG" \
    "$UNBLOCKED_LOG_LINE" "$PRESSURE_LOG_LINE" "$PRESSURE_END_LOG_LINE" \
    "$BLOCKED_LOG_LINE" "$PRESSURE_FLOW_ID" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from soak_pressure_log import summarize_udp_pressure_rows

try:
    with open(sys.argv[2], encoding="utf-8") as provider_log:
        lines = provider_log.read().splitlines()
    unblocked_start = int(sys.argv[3])
    pressure_start = int(sys.argv[4])
    pressure_end = int(sys.argv[5])
    blocked_start = int(sys.argv[6])
    pressure_flow_id = int(sys.argv[7])
    if not 0 <= unblocked_start <= pressure_start <= pressure_end <= blocked_start <= len(lines):
        raise ValueError("invalid provider log phase boundaries")
    healthy_segments = (
        lines[unblocked_start:pressure_start],
        lines[pressure_end:blocked_start],
        lines[blocked_start:],
    )
    healthy = [
        summarize_udp_pressure_rows(
            list(enumerate(segment, start=1)),
            workload_exercised=True,
            mode="stress-only",
        )
        for segment in healthy_segments
    ]
    pressure = summarize_udp_pressure_rows(
        list(enumerate(lines[pressure_start:pressure_end], start=1)),
        workload_exercised=True,
        mode="find-ceiling",
        required_flow_id=pressure_flow_id,
    )
    all_summaries = [*healthy, pressure]
    if any(summary["issues"] for summary in all_summaries):
        status = "INCOMPLETE"
    elif (
        any(summary["failures"] for summary in all_summaries)
        or sum(summary["events"] for summary in healthy) != 0
        or not pressure["drop_reasons"]
        or pressure["drop_reasons"] != pressure["recovered_reasons"]
        or pressure["unrecovered"]
    ):
        status = "FAILED"
    else:
        status = "GOOD"
    print(
        status,
        sum(summary["drop_transitions"] for summary in all_summaries),
        sum(summary["resume_transitions"] for summary in all_summaries),
        sum(summary["swift_staging_drop_samples"] for summary in all_summaries),
        pressure["drop_transitions"],
        pressure["resume_transitions"],
        ",".join(pressure["drop_reasons"]) or "none",
        ",".join(pressure["recovered_reasons"]) or "none",
        sum(summary["events"] for summary in healthy),
    )
except Exception:
    raise SystemExit(2)
PY
)" || {
    add_issue "could not parse phase-local UDP pressure telemetry"
    return 1
  }
  read -r status RUST_UDP_DROP_TRANSITIONS RUST_UDP_RESUME_TRANSITIONS \
    SWIFT_UDP_STAGING_DROP_SAMPLES PRESSURE_DROP_TRANSITIONS \
    PRESSURE_RESUME_TRANSITIONS PRESSURE_DROP_REASONS \
    PRESSURE_RECOVERED_REASONS OUTSIDE_PRESSURE_EVENTS <<< "$metrics"
  if [[ ! "$RUST_UDP_DROP_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$RUST_UDP_RESUME_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$SWIFT_UDP_STAGING_DROP_SAMPLES" =~ ^[0-9]+$ \
    || ! "$PRESSURE_DROP_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$PRESSURE_RESUME_TRANSITIONS" =~ ^[0-9]+$ \
    || ! "$OUTSIDE_PRESSURE_EVENTS" =~ ^[0-9]+$ \
    || ! "$PRESSURE_DROP_REASONS" =~ ^(channel_count|flow_bytes|global_bytes)(,(channel_count|flow_bytes|global_bytes))*$ \
    || ! "$PRESSURE_RECOVERED_REASONS" =~ ^(channel_count|flow_bytes|global_bytes)(,(channel_count|flow_bytes|global_bytes))*$ ]]
  then
    add_issue "UDP pressure telemetry verdict returned malformed counters"
    return 1
  fi
  UDP_PRESSURE_LOG_CHECKED=1
  if (( OUTSIDE_PRESSURE_EVENTS != 0 )); then
    add_failure "UDP ingress pressure transitioned outside the deliberate pressure probe"
  fi
  if (( SWIFT_UDP_STAGING_DROP_SAMPLES > 0 )); then
    add_failure "UDP pressure telemetry recorded Swift staging loss (samples=$SWIFT_UDP_STAGING_DROP_SAMPLES)"
  fi
  if [[ "$PRESSURE_DROP_REASONS" != "$PRESSURE_RECOVERED_REASONS" ]]; then
    add_failure "deliberate UDP pressure probe did not recover every pressured reason"
  fi
  case "$status" in
    GOOD) ;;
    FAILED) add_failure "phase-local UDP pressure telemetry failed its transition contract" ;;
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
RUN_UUID="$(/usr/bin/uuidgen | tr '[:upper:]' '[:lower:]')"
[[ "$RUN_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || fatal_issue "could not create a canonical signed UDP run UUID"
GATE_START_MONOTONIC_MS="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')"
[[ "$GATE_START_MONOTONIC_MS" =~ ^[1-9][0-9]*$ ]] \
  || fatal_issue "could not capture the signed UDP monotonic gate start"
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

HTTP3_ENDPOINTS="$TMP_DIR/http3-endpoints.txt"
if ! /usr/bin/python3 - "$HTTP3_URL" > "$HTTP3_ENDPOINTS" <<'PY'
import ipaddress, socket, sys
from urllib.parse import urlsplit

parsed = urlsplit(sys.argv[1])
if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443):
    raise SystemExit(2)
host = parsed.hostname
try:
    addresses = {str(ipaddress.ip_address(host))}
except ValueError:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(host, 443, type=socket.SOCK_DGRAM)
    }
if not addresses:
    raise SystemExit(2)
for address in sorted(addresses):
    ip = ipaddress.ip_address(address)
    print(f"[{ip}]:443" if ip.version == 6 else f"{ip}:443")
PY
then
  fatal_issue "could not resolve the exact HTTP/3 probe endpoints"
fi

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
capture_provider_identity \
  || fatal_issue "unblocked UDP E2E provider identity is unavailable"

# Ignore teardown/startup errors from the provider instance being replaced.
sleep 1
UNBLOCKED_LOG_LINE="$(provider_log_line)"
UDP_ERROR_PROVIDER_LOG_LINE="$UNBLOCKED_LOG_LINE"

CURRENT_PHASE=unblocked-probes
run_probe "pass-through DNS control" none dns --server "$PASSTHROUGH_DNS"
PASSTHROUGH_DNS_SOURCE_PID="$LAST_PROBE_PID"
PASSTHROUGH_DNS_LOG_START="$LAST_PROBE_LOG_START"
PASSTHROUGH_DNS_LOG_END="$LAST_PROBE_LOG_END"
run_probe "intercept NTP control" none ntp --server "$INTERCEPT_NTP"
NTP_SOURCE_PID="$LAST_PROBE_PID"
NTP_LOG_START="$LAST_PROBE_LOG_START"
NTP_LOG_END="$LAST_PROBE_LOG_END"
run_probe "future blocked DNS control" none dns --server "$BLOCKED_DNS"
CONTROL_DNS_SOURCE_PID="$LAST_PROBE_PID"
CONTROL_DNS_LOG_START="$LAST_PROBE_LOG_START"
CONTROL_DNS_LOG_END="$LAST_PROBE_LOG_END"

PRESSURE_LOG_LINE="$(provider_log_line)"
PRESSURE_PROBE_ATTEMPTED=1
PRESSURE_LOG_START="$PRESSURE_LOG_LINE"
/usr/bin/python3 "$PROBE" pressure --server "$INTERCEPT_NTP" \
  --count 512 --payload-bytes 4096 --settle 4 &
PRESSURE_SOURCE_PID=$!
if wait "$PRESSURE_SOURCE_PID"
then
  PRESSURE_PROBE_PASSED=1
else
  add_issue "deliberate UDP pressure burst did not complete"
fi
close_pressure_probe_window "$PRESSURE_LOG_START" "$PRESSURE_SOURCE_PID" \
  "$INTERCEPT_NTP:123" com.apple.python3 || true
PRESSURE_END_LOG_LINE="$LAST_PROBE_LOG_END"

HTTP3_SEPARATOR='?'
[[ "$HTTP3_URL" == *\?* ]] && HTTP3_SEPARATOR='&'
HTTP3_PROVIDER_LOG_LINE="$(provider_log_line)"
UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
HTTP3_RC=0
nscurl --http3-prior-knowledge -m 15 \
  "${HTTP3_URL}${HTTP3_SEPARATOR}rama_udp_e2e_cache_buster=$RUN_UUID" \
  > "$HTTP3_RESULT" 2>&1 &
HTTP3_SOURCE_PID=$!
wait "$HTTP3_SOURCE_PID" || HTTP3_RC=$?
close_probe_decision_window "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_SOURCE_PID"
HTTP3_PROVIDER_LOG_END="$LAST_PROBE_LOG_END"
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
require_provider_identity || true
BLOCKED_LOG_LINE="$(provider_log_line)"

CURRENT_PHASE=blocked-probe
run_probe "blocked DNS probe" 10 dns --server "$BLOCKED_DNS" \
  --timeout 4 --expect-no-response
BLOCKED_DNS_SOURCE_PID="$LAST_PROBE_PID"
BLOCKED_DNS_LOG_START="$LAST_PROBE_LOG_START"
BLOCKED_DNS_LOG_END="$LAST_PROBE_LOG_END"

# Let os_log and the Rust tracing bridge flush the per-flow decision/service
# records before assertions.
sleep 2
CURRENT_PHASE=log-quiesce
stop_log_capture
CURRENT_PHASE=log-verdicts
check_exact_decision "$PASSTHROUGH_DNS_LOG_START" "$PASSTHROUGH_DNS_LOG_END" \
  passthrough "$PASSTHROUGH_DNS:53" com.apple.python3 \
  "$PASSTHROUGH_DNS_SOURCE_PID" "Rust pass-through decision for public DNS" passthrough
check_exact_decision "$NTP_LOG_START" "$NTP_LOG_END" intercept \
  "$INTERCEPT_NTP:123" com.apple.python3 "$NTP_SOURCE_PID" \
  "Rust intercept decision for public NTP forwarding" ntp
check_exact_decision "$CONTROL_DNS_LOG_START" "$CONTROL_DNS_LOG_END" passthrough \
  "$BLOCKED_DNS:53" com.apple.python3 "$CONTROL_DNS_SOURCE_PID" \
  "Rust pre-block control decision for public DNS" control
check_exact_decision "$PRESSURE_LOG_START" "$PRESSURE_END_LOG_LINE" intercept \
  "$INTERCEPT_NTP:123" com.apple.python3 "$PRESSURE_SOURCE_PID" \
  "Rust intercept decision for the deliberate pressure flow" pressure
check_exact_decision "$BLOCKED_DNS_LOG_START" "$BLOCKED_DNS_LOG_END" blocked \
  "$BLOCKED_DNS:53" com.apple.python3 "$BLOCKED_DNS_SOURCE_PID" \
  "Rust blocked decision for an exact public DNS endpoint" blocked

HTTP3_FOUND=0
while IFS=$'\t' read -r action flow_id remote source source_pid; do
  [[ "$source_pid" == "$HTTP3_SOURCE_PID" ]] || continue
  if [[ "$source" != com.apple.nscurl ]] || ! grep -Fqx -- "$remote" "$HTTP3_ENDPOINTS"; then
    add_issue "HTTP/3 source PID produced an unexpected app or remote endpoint record"
    continue
  fi
  HTTP3_FOUND=$((HTTP3_FOUND + 1))
  HTTP3_FLOW_ID="$flow_id"
  HTTP3_REMOTE_ENDPOINT="$remote"
  [[ "$action" == passthrough ]] \
    || add_failure "exact HTTP/3 flow recorded rama_decision=$action instead of passthrough"
done < <(decision_records "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_PROVIDER_LOG_END")
(( HTTP3_FOUND == 1 )) \
  || add_issue "HTTP/3 request did not have one exact PID/endpoint decision record"

# Open/read/write markers are emitted only for errors the provider classifier
# considers unexpected. Benign teardown races have no public marker.
if tail -n "+$((UDP_ERROR_PROVIDER_LOG_LINE + 1))" "$PROVIDER_LOG" | grep -E \
  'flow_callback_error operation=udp_flow\.(open|read|write)' >/dev/null
then
  add_failure "provider emitted an unexpected UDP flow error during the live test"
fi

check_udp_pressure_logs || true
require_provider_identity || true

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
