#!/usr/bin/env bash
# macOS still ships Bash 3.2, where reading a declared-but-empty array under
# `set -u` raises an unbound-variable error. This script deliberately handles
# every command outcome and uses pipefail without nounset for host compatibility.
set -o pipefail

# Python before 3.10 uses a process-relative monotonic epoch on macOS. These
# samples come from separate interpreters, so use the shared kernel clock.
monotonic_ms_now() {
  /usr/bin/python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1_000_000)'
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILT_APP="${1:-$ROOT_DIR/.xcode-derived/tproxy-app-dev/Build/Products/Debug/RamaTransparentProxyExampleContainer.app}"
PROBE_SOURCE="$SCRIPT_DIR/modern_udp_e2e_probe.py"
INSTALLER_SOURCE="$SCRIPT_DIR/install_tproxy_app_bundle.sh"
SIGNED_EVIDENCE_SOURCE="$SCRIPT_DIR/signed_run_evidence.py"
MODERN_EVIDENCE_SOURCE="$SCRIPT_DIR/modern_udp_evidence.py"
SOAK_PRESSURE_SOURCE="$SCRIPT_DIR/soak_pressure_log.py"
PROBE="$PROBE_SOURCE"
INSTALLER="$INSTALLER_SOURCE"
SIGNED_EVIDENCE="$SIGNED_EVIDENCE_SOURCE"
MODERN_EVIDENCE="$MODERN_EVIDENCE_SOURCE"
INSTALLED_APP="/Applications/RamaTransparentProxyExampleContainer.app"
CONTAINER_LOG="$HOME/Library/Logs/RamaTransparentProxyExampleContainer.log"
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"
BUILT_PROVIDER="$BUILT_APP/Contents/Library/SystemExtensions/$PROVIDER_BUNDLE.systemextension"
INSTALLED_PROVIDER="$INSTALLED_APP/Contents/Library/SystemExtensions/$PROVIDER_BUNDLE.systemextension"

# Maintained public protocol endpoints. Override these when a runner's network
# filters a particular anycast service; IP literals keep provider-log assertions
# deterministic and avoid mixing resolver traffic into the target flow.
PASSTHROUGH_DNS="${RAMA_TPROXY_E2E_PASSTHROUGH_DNS:-1.1.1.1}"
INTERCEPT_NTP="${RAMA_TPROXY_E2E_INTERCEPT_NTP:-162.159.200.1}"
BLOCKED_DNS="${RAMA_TPROXY_E2E_BLOCKED_DNS:-8.8.8.8}"
HTTP3_URL="${RAMA_TPROXY_E2E_HTTP3_URL:-https://cloudflare.com/cdn-cgi/trace}"
HTTP3_LIBCURL="${RAMA_TPROXY_E2E_HTTP3_LIBCURL:-}"
ECHO_SOCKET_COUNT="${RAMA_TPROXY_E2E_ECHO_SOCKETS:-128}"
ECHO_DATAGRAMS_PER_SOCKET="${RAMA_TPROXY_E2E_ECHO_DATAGRAMS_PER_SOCKET:-64}"
ECHO_INTERVAL_MS="${RAMA_TPROXY_E2E_ECHO_INTERVAL_MS:-2000}"
ECHO_PAYLOAD_BYTES="${RAMA_TPROXY_E2E_ECHO_PAYLOAD_BYTES:-1200}"
ECHO_CONCURRENCY="${RAMA_TPROXY_E2E_ECHO_CONCURRENCY:-32}"
HTTP3_CONCURRENCY="${RAMA_TPROXY_E2E_HTTP3_CONCURRENCY:-4}"
HTTP3_ROUNDS="${RAMA_TPROXY_E2E_HTTP3_ROUNDS:-3}"
HTTP3_ROUND_INTERVAL="${RAMA_TPROXY_E2E_HTTP3_ROUND_INTERVAL:-1}"
PRESSURE_COUNT="${RAMA_TPROXY_E2E_PRESSURE_COUNT:-512}"
PRESSURE_PAYLOAD_BYTES="${RAMA_TPROXY_E2E_PRESSURE_PAYLOAD_BYTES:-4096}"
PRESSURE_EXPECTED_BYTES=0
CONCURRENT_LOAD_DEADLINE_SECONDS="${RAMA_TPROXY_E2E_CONCURRENT_LOAD_DEADLINE_SECONDS:-180}"
MAX_LOAD_BYTES=268435456

TMP_DIR="$(mktemp -d /tmp/rama-modern-udp-e2e.XXXXXX)" || {
  echo "could not create modern UDP E2E artifact directory" >&2
  exit 2
}
PROVIDER_LOG="$TMP_DIR/provider.log"
HTTP3_RESULTS="$TMP_DIR/http3-results.tsv"
HTTP3_PIDS="$TMP_DIR/http3-pids.tsv"
HTTP3_ROUND_RESULTS="$TMP_DIR/http3-round-results.tsv"
HTTP3_TIMING="$TMP_DIR/http3-timing.tsv"
HTTP3_INTERCEPT_RESULT="$TMP_DIR/http3-intercept-client.json"
HTTP3_INTERCEPT_BODY="$TMP_DIR/http3-intercept-body.txt"
ECHO_READY="$TMP_DIR/controlled-echo-ready.json"
ECHO_CLIENT_RESULT="$TMP_DIR/controlled-echo-client.json"
ECHO_SERVER_RESULT="$TMP_DIR/controlled-echo-server.json"
DIAL9_REQUIREMENTS="$TMP_DIR/dial9-requirements.tsv"
PROVIDER_LOG_PHASES="$TMP_DIR/provider-log-phases.tsv"
PROVIDER_GENERATION_SAMPLES="$TMP_DIR/provider-generation-samples.tsv"
PROVIDER_GENERATION_MONITOR_STOP="$TMP_DIR/.provider-generation-monitor-stop.tmp.$$"
PROVIDER_GENERATION_MONITOR_FAILED="$TMP_DIR/.provider-generation-monitor-failed.tmp.$$"
RESTORE_CONTAINER_LOG="$TMP_DIR/restore-container.log"
RESTORE_RECEIPT="$TMP_DIR/restore-receipt.tsv"
WORKLOAD_CLAIMS="$TMP_DIR/workload-claims.tsv"
EVIDENCE_STATUS="$TMP_DIR/udp-evidence-status.tsv"
COMMON_EVIDENCE_STATUS="$TMP_DIR/evidence-status.tsv"
BOUNDED_CLEANUP_FAILED="$TMP_DIR/.bounded-cleanup-failed"
DIAL9_BASELINE="$TMP_DIR/dial9-baseline.json"
DIAL9_SUMMARY="$TMP_DIR/dial9-evidence.json"
PROBE_RESULTS="$TMP_DIR/udp-probe-results.tsv"
printf 'label\tsource_pid\texit_code\n' > "$PROBE_RESULTS" || exit 2

LOG_PID=""
PROVIDER_GENERATION_MONITOR_PID=""
ECHO_SERVER_PID=""
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
DIAL9_REQUIREMENTS_SHA256=none
DIAL9_REQUIREMENT_COUNT=0
DIAL9_MATCHED_REQUIREMENT_COUNT=0
DIAL9_COLLECTION_ATTEMPTED=0
NTP_FLOW_ID=""
PROVIDER_PID=""
PROVIDER_IDENTITY=""
PROVIDER_PROCESS_IDENTITY=""
PROVIDER_IDENTITY_STABLE=0
PROVIDER_BUILD_IDENTITY=unavailable
PROVIDER_GENERATION_IDENTITY=unavailable
PRODUCER_SOURCES_SHA256=none
SOURCE_GIT_HEAD=unavailable
SOURCE_GIT_DIRTY=unavailable
HTTP3_SOURCE_PID=none
HTTP3_FLOW_ID=none
HTTP3_REMOTE_ENDPOINT=none
HTTP3_REQUEST_COUNT=0
HTTP3_PASS_COUNT=0
HTTP3_FLOW_COUNT=0
HTTP3_DURATION_MS=0
HTTP3_MIN_CONCURRENT=0
HTTP3_INTERCEPT_PASSED=0
HTTP3_INTERCEPT_SOURCE_PID=none
HTTP3_INTERCEPT_FLOW_ID=none
HTTP3_INTERCEPT_PROVIDER_GENERATION=none
HTTP3_INTERCEPT_LOCAL_ENDPOINT=none
HTTP3_INTERCEPT_REMOTE_ENDPOINT=none
ACTIVE_PROBE_PID=""
ACTIVE_ECHO_PID=""
ACTIVE_PRESSURE_PID=""
# Signal authority belongs to a persistent supervisor, independently of the
# command PID recorded in flow evidence. Bash 3.2 supports these indexed arrays.
OWNED_COMMAND_IDENTITIES=()
OWNED_COMMAND_SOURCE_PIDS=()
OWNED_COMMAND_SOURCE_IDENTITIES=()
OWNED_COMMAND_ROLES=()
OWNED_COMMAND_FILES=()
OWNED_COMMAND_SEQUENCE=0
OWNED_COMMAND_PID=""
OWNED_COMMAND_SOURCE_PID=""
RUN_UUID="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')"
RUN_START_EPOCH_MS="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
RUN_END_EPOCH_MS=0
PASSTHROUGH_DNS_SOURCE_PID=none
PASSTHROUGH_DNS_FLOW_ID=none
CONTROL_DNS_SOURCE_PID=none
CONTROL_DNS_FLOW_ID=none
NTP_SOURCE_PID=none
BLOCKED_DNS_SOURCE_PID=none
BLOCKED_DNS_FLOW_ID=none
PRESSURE_SOURCE_PID=none
PRESSURE_FLOW_ID=none
RECOVERY_NTP_SOURCE_PID=none
RECOVERY_NTP_FLOW_ID=none
PRESSURE_PROBE_ATTEMPTED=0
PRESSURE_PROBE_PASSED=0
PRESSURE_DROP_TRANSITIONS=0
PRESSURE_RESUME_TRANSITIONS=0
PRESSURE_DROP_REASONS=none
PRESSURE_RECOVERED_REASONS=none
MAIN_FINISHED=0
FINALIZING=0
CALLBACK_GENERATION=unknown
UNBLOCKED_PROVIDER_GENERATION=none
BLOCKED_PROVIDER_GENERATION=none
ENGINE_GENERATIONS_SHA256=none
CONCURRENT_LOAD_TIMED_OUT=0
ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT=0
ECHO_ENDPOINT=none
ECHO_SOURCE_PID=none
ECHO_FLOW_COUNT=0
ECHO_EXPECTED_COUNT=0
ECHO_EXACT_ECHO_COUNT=0
ECHO_PAYLOAD_SET_SHA256=none
CURRENT_PHASE=preflight
UNBLOCKED_LOG_LINE=0
UDP_ERROR_PROVIDER_LOG_LINE=0
PASSTHROUGH_DNS_LOG_START=0
PASSTHROUGH_DNS_LOG_END=0
NTP_LOG_START=0
NTP_LOG_END=0
CONTROL_DNS_LOG_START=0
CONTROL_DNS_LOG_END=0
PRESSURE_LOG_START=0
PRESSURE_END_LOG_LINE=0
ECHO_LOG_START=0
ECHO_LOG_END=0
RECOVERY_NTP_LOG_START=0
RECOVERY_NTP_LOG_END=0
HTTP3_PROVIDER_LOG_LINE=0
HTTP3_PROVIDER_LOG_END=0
HTTP3_INTERCEPT_LOG_START=0
HTTP3_INTERCEPT_LOG_END=0
BLOCKED_LOG_LINE=0
BLOCKED_DNS_LOG_START=0
BLOCKED_DNS_LOG_END=0
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

# Keep timeout cleanup bound to the exact owned supervisor generation.
# These helpers mirror the stress harness; every descendant must be gone
# before run_bounded returns, including orphaned writers holding output pipes.
bounded_pid_identity() {
  local pid="$1" snapshot digest
  if [[ "${2:-command}" == generation ]]; then
    snapshot="$(ps -ww -o pid= -o lstart= -p "$pid" 2>/dev/null)" || return 1
  else
    snapshot="$(ps -ww -o pid= -o lstart= -o command= -p "$pid" 2>/dev/null)" || return 1
  fi
  [[ -n "$snapshot" ]] || return 1
  digest="$(printf '%s' "$snapshot" | shasum -a 256 | awk 'NR == 1 { print $1 }')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

bounded_owned_job_is_active() {
  jobs -p | grep -Fqx -- "$1"
}

bounded_owned_job_has_exited() {
  local pid="$1" state
  bounded_owned_job_is_active "$pid" || return 0
  state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  # A failed/empty ps result cannot authorize an unbounded wait on a live job.
  [[ "$state" == Z* ]] || { [[ -z "$state" ]] && ! kill -0 "$pid" 2>/dev/null; }
}

bounded_owned_identity_has_exited() {
  local pid="$1" expected_identity="$2" state observed_identity
  observed_identity="$(bounded_pid_identity "$pid" generation || true)"
  if [[ -n "$observed_identity" && "$observed_identity" != "$expected_identity" ]]; then
    return 0
  fi
  state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$state" == Z* ]] && return 0
  # An inspection failure is not proof of exit while the pid is still alive.
  [[ -z "$state" ]] && ! kill -0 "$pid" 2>/dev/null
}

bounded_owned_tree_has_exited() {
  local tree_text="$1" pid identity
  while IFS=$'\t' read -r pid identity; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$identity" =~ ^[0-9a-f]{64}$ ]] || continue
    bounded_owned_identity_has_exited "$pid" "$identity" || return 1
  done <<< "$tree_text"
}

bounded_collect_owned_tree() {
  local pid="$1" expected_identity="$2" child child_identity children child_ppid group
  local failed=0 discovery_rc=0 discovery_deadline="${3:-$((SECONDS + 1))}"
  if [[ "${4:-}" != recursive ]]; then
    local BOUNDED_COLLECT_SEEN=() BOUNDED_COLLECT_COUNT=0
  fi
  [[ "${BOUNDED_COLLECT_SEEN[pid]:-}" != "$expected_identity" ]] || return 0
  BOUNDED_COLLECT_SEEN[pid]="$expected_identity"
  BOUNDED_COLLECT_COUNT=$((BOUNDED_COLLECT_COUNT + 1))
  # Retain every already-stopped identity even when discovery expires, so
  # partial snapshots still carry authority to thaw and kill the root group.
  printf '%s\t%s\n' "$pid" "$expected_identity"
  (( BOUNDED_COLLECT_COUNT <= 128 && SECONDS < discovery_deadline )) || return 1
  # The caller has stopped this generation. Recheck before following a parent
  # pid that might otherwise have exited and been reused during discovery.
  [[ "$(bounded_pid_identity "$pid" generation || true)" == "$expected_identity" ]] || return 1
  group="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$group" == "$pid" ]]; then
    # Capture supervisors own a dedicated group. It also contains descendants
    # whose immediate parents exited before cleanup began.
    children="$(pgrep -g "$pid" 2>/dev/null)" || discovery_rc=$?
  else
    children="$(pgrep -P "$pid" 2>/dev/null)" || discovery_rc=$?
  fi
  # pgrep uses 1 for an empty result; errors must not become a complete tree.
  (( discovery_rc <= 1 )) || failed=1
  while IFS= read -r child; do
    [[ "$child" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$child" != "$pid" ]] || continue
    # The group snapshot also lists members reached through parent links.
    # Those stopped generations must not trigger another recursive traversal.
    [[ -z "${BOUNDED_COLLECT_SEEN[child]:-}" ]] || continue
    (( BOUNDED_COLLECT_COUNT < 128 && SECONDS < discovery_deadline )) || { failed=1; break; }
    child_identity="$(bounded_pid_identity "$child" generation || true)"
    [[ "$child_identity" =~ ^[0-9a-f]{64}$ ]] || continue
    if [[ "$group" == "$pid" ]]; then
      child_ppid="$(ps -o pgid= -p "$child" 2>/dev/null | tr -d '[:space:]')"
    else
      child_ppid="$(ps -o ppid= -p "$child" 2>/dev/null | tr -d '[:space:]')"
    fi
    [[ "$child_ppid" == "$pid" ]] || continue
    if bounded_signal_owned_identity "$child" "$child_identity" STOP; then
      bounded_collect_owned_tree "$child" "$child_identity" "$discovery_deadline" recursive || failed=1
    elif ! bounded_owned_identity_has_exited "$child" "$child_identity"; then
      failed=1
    fi
  done <<< "$children"
  return "$failed"
}

bounded_signal_owned_identity() {
  local pid="$1" expected_identity="$2" signal="$3" observed_identity state attempt target
  observed_identity="$(bounded_pid_identity "$pid" generation || true)"
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  target="$pid"
  if [[ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')" == "$pid" ]]; then
    target="-$pid"
  fi
  if ! kill "-$signal" -- "$target" 2>/dev/null; then
    # Dial9 collection and ownership normalization can have root descendants.
    # Retry only this still-owned generation with the already-cached privilege;
    # a partial group delivery is also checked member by member below.
    observed_identity="$(bounded_pid_identity "$pid" generation || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
    sudo -n /bin/kill "-$signal" -- "$target" 2>/dev/null || return 1
  fi
  [[ "$signal" == STOP ]] || return 0
  # STOP delivery is asynchronous. Confirm it before trusting a child snapshot;
  # a still-running parent could fork after pgrep has already enumerated it.
  for ((attempt=0; attempt<10; attempt++)); do
    observed_identity="$(bounded_pid_identity "$pid" generation || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
    state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$state" == T* || "$state" == Z* ]] && return 0
    sleep 0.01
  done
  # Keep authority only over the generation we stopped; never CONT a changed
  # identity in an attempt to undo a raced STOP.
  observed_identity="$(bounded_pid_identity "$pid" generation || true)"
  [[ "$observed_identity" != "$expected_identity" ]] || kill -CONT -- "$target" 2>/dev/null || true
  return 1
}

# Run only as a background function: exec preserves $! as the owned group
# leader. The optional handshake holds the leaf before exec until both process
# generations are registered; evidence always records that leaf PID.
bounded_command_supervisor() {
  exec /usr/bin/python3 -c '
import os
import signal
import subprocess
import sys
import time

# Own a group without detaching from the authenticated controlling terminal.
# sudo -n must retain the tty credential context checked by preflight.
os.setpgid(0, 0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
leader = os.getpid()
receipt, ready = sys.argv[1:3]
command = sys.argv[3:]
read_gate, write_gate = os.pipe()
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.close(write_gate)
    if os.read(read_gate, 1) != b"1":
        os._exit(125)
    os.close(read_gate)
    try:
        os.execvp(command[0], command)
    except OSError as error:
        print(error, file=sys.stderr)
        os._exit(127)
os.close(read_gate)
if ready:
    with open(ready + ".pid", "x") as output:
        output.write(str(child) + "\n")
    while not os.path.exists(ready + ".release"):
        time.sleep(0.01)
    os.unlink(ready + ".release")
    os.unlink(ready + ".pid")
os.write(write_gate, b"1")
os.close(write_gate)
status = None
while True:
    if status is None:
        exited, observed = os.waitpid(child, os.WNOHANG)
        if exited:
            status = observed
    if status is not None:
        snapshot = subprocess.Popen(
            ["ps", "-axo", "pid=,pgid=,state="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        output, _ = snapshot.communicate()
        if snapshot.returncode == 0:
            members = [row.split() for row in output.splitlines()]
            if not any(
                len(row) == 3 and row[1] == str(leader)
                and row[0] not in (str(leader), str(snapshot.pid))
                and not row[2].startswith("Z")
                for row in members
            ):
                break
    time.sleep(0.1)
result = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
with open(receipt, "w") as output:
    output.write(str(child) + "\t" + str(result) + "\n")
sys.exit(result)
' "$@"
}

bounded_drain_receipt_valid() {
  local receipt="$1" expected_pid="$2" expected_status="$3" value source_pid
  [[ -f "$receipt" && ! -L "$receipt" ]] || return 1
  value="$(cat "$receipt")" || return 1
  source_pid="${value%%$'\t'*}"
  [[ "$source_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -z "$expected_pid" || "$source_pid" == "$expected_pid" ]] || return 1
  [[ "$value" == "$source_pid"$'\t'"$expected_status" ]]
}

run_bounded() {
  local timeout_seconds="$1"; shift
  local pid identity deadline child_rc=0 timed_out=0 tree_text="" tree_pid tree_identity
  local tree_incomplete=0 interrupted=0 saved_int_trap saved_term_trap result receipt
  # Sealing and verification also run through this wrapper. Their transient
  # drain receipt must live outside the recursively sealed evidence tree.
  receipt="$(mktemp /tmp/rama-modern-udp-drain.XXXXXX)" || {
    : > "$BOUNDED_CLEANUP_FAILED"
    return 125
  }
  saved_int_trap="$(trap -p INT)"
  saved_term_trap="$(trap -p TERM)"
  # Complete ownership cleanup before the outer EXIT finalizer can seal files.
  # The existing INT/TERM handlers terminate with these same exit codes.
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  # Keep one owned group leader alive until the command AND its group members
  # exit. A wrapper exiting early cannot orphan a pipe holder outside the tree
  # observed at timeout. The leader ignores TERM so group KILL remains bound to
  # its live generation throughout shutdown; the command gets normal signals.
  bounded_command_supervisor "$receipt" "" "$@" &
  pid="$!"
  identity="$(bounded_pid_identity "$pid" generation || true)"
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline && interrupted == 0 )) && ! bounded_owned_job_has_exited "$pid"; do
    sleep 0.1
  done
  if ! bounded_owned_job_has_exited "$pid"; then
    timed_out=1
    # Discovery consumes the existing TERM grace; it must not delay escalation
    # by starting its own unbounded walk before this watchdog begins.
    deadline=$((SECONDS + 1))
    if [[ "$identity" =~ ^[0-9a-f]{64}$ ]] \
      && bounded_signal_owned_identity "$pid" "$identity" STOP
    then
      tree_text="$(bounded_collect_owned_tree "$pid" "$identity" "$deadline")" || tree_incomplete=1
    elif ! bounded_owned_job_has_exited "$pid"; then
      tree_incomplete=1
    fi
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      bounded_signal_owned_identity "$tree_pid" "$tree_identity" TERM || true
    done <<< "$tree_text"
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      bounded_signal_owned_identity "$tree_pid" "$tree_identity" CONT || true
    done <<< "$tree_text"
    while (( SECONDS < deadline )); do
      if bounded_owned_job_has_exited "$pid" && bounded_owned_tree_has_exited "$tree_text"; then break; fi
      sleep 0.1
    done
  fi
  if (( timed_out )); then
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      bounded_signal_owned_identity "$tree_pid" "$tree_identity" KILL || true
    done <<< "$tree_text"
    deadline=$((SECONDS + 1))
    while (( SECONDS < deadline )); do
      if bounded_owned_job_has_exited "$pid" && bounded_owned_tree_has_exited "$tree_text"; then break; fi
      sleep 0.1
    done
  fi
  # Reap a direct child even when a descendant could not be stopped. A surviving
  # descendant must still fail capture after the direct job has disappeared.
  if bounded_owned_job_has_exited "$pid"; then
    wait "$pid" 2>/dev/null || child_rc=$?
    # A crashed supervisor is not proof that its former group stopped writing.
    if [[ -z "$tree_text" ]] && ! bounded_drain_receipt_valid "$receipt" "" "$child_rc"; then
      tree_incomplete=1
    fi
    /bin/rm -f "$receipt"
  else
    tree_incomplete=1
  fi
  if (( tree_incomplete )) || ! bounded_owned_tree_has_exited "$tree_text"; then
    : > "$BOUNDED_CLEANUP_FAILED"
    result=125
  elif (( timed_out )); then
    result=124
  else
    result="$child_rc"
  fi
  if [[ -n "$saved_int_trap" ]]; then eval "$saved_int_trap"; else trap - INT; fi
  if [[ -n "$saved_term_trap" ]]; then eval "$saved_term_trap"; else trap - TERM; fi
  (( interrupted == 0 )) || exit "$interrupted"
  return "$result"
}

start_owned_command() {
  local role="$1"; shift
  local pid identity source_pid source_identity deadline prefix interrupted=0
  local saved_int_trap saved_term_trap
  saved_int_trap="$(trap -p INT)"
  saved_term_trap="$(trap -p TERM)"
  # A signal between spawn and registration must not bypass the EXIT registry.
  trap 'interrupted=130' INT
  trap 'interrupted=143' TERM
  OWNED_COMMAND_SEQUENCE=$((OWNED_COMMAND_SEQUENCE + 1))
  prefix="$TMP_DIR/.owned-command-$OWNED_COMMAND_SEQUENCE.$$"
  bounded_command_supervisor "$prefix.complete" "$prefix" "$@" &
  pid=$!
  OWNED_COMMAND_PID="$pid"
  OWNED_COMMAND_SOURCE_PID=""
  OWNED_COMMAND_ROLES[pid]="$role"
  OWNED_COMMAND_FILES[pid]="$prefix"
  identity="$(bounded_pid_identity "$pid" generation || true)"
  OWNED_COMMAND_IDENTITIES[pid]="$identity"
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline && interrupted == 0 )); do
    [[ -s "$prefix.pid" ]] && break
    bounded_owned_job_has_exited "$pid" && break
    sleep 0.01
  done
  read -r source_pid < "$prefix.pid" 2>/dev/null || source_pid=""
  if [[ "$source_pid" =~ ^[1-9][0-9]*$ ]]; then
    source_identity="$(bounded_pid_identity "$source_pid" generation || true)"
  fi
  if [[ "$identity" =~ ^[0-9a-f]{64}$ && "$source_identity" =~ ^[0-9a-f]{64}$ \
    && "$(bounded_pid_identity "$pid" generation || true)" == "$identity" \
    && "$(ps -o ppid= -p "$source_pid" 2>/dev/null | tr -d '[:space:]')" == "$pid" ]]
  then
    OWNED_COMMAND_SOURCE_PIDS[pid]="$source_pid"
    OWNED_COMMAND_SOURCE_IDENTITIES[pid]="$source_identity"
    OWNED_COMMAND_SOURCE_PID="$source_pid"
    : > "$prefix.release"
  else
    add_issue "could not bind the owned $role command and supervisor generations"
  fi
  if [[ -n "$saved_int_trap" ]]; then eval "$saved_int_trap"; else trap - INT; fi
  if [[ -n "$saved_term_trap" ]]; then eval "$saved_term_trap"; else trap - TERM; fi
  (( interrupted == 0 )) || exit "$interrupted"
  [[ -n "$OWNED_COMMAND_SOURCE_PID" ]]
}

owned_command_source_is_alive() {
  local source_pid="${OWNED_COMMAND_SOURCE_PIDS[$1]}"
  local expected="${OWNED_COMMAND_SOURCE_IDENTITIES[$1]}" state
  [[ "$source_pid" =~ ^[1-9][0-9]*$ && "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$(bounded_pid_identity "$source_pid" generation || true)" == "$expected" ]] || return 1
  state="$(ps -o state= -p "$source_pid" 2>/dev/null | tr -d '[:space:]')"
  [[ -n "$state" && "$state" != Z* ]] && kill -0 "$source_pid" 2>/dev/null
}

unregister_owned_command() {
  local pid="$1" prefix="${OWNED_COMMAND_FILES[$1]}"
  # Remove signal authority immediately after wait, before inspecting artifacts
  # or joining another worker. Retain an unproven job for finalizer cleanup.
  unset 'OWNED_COMMAND_IDENTITIES[pid]' 'OWNED_COMMAND_SOURCE_PIDS[pid]'
  unset 'OWNED_COMMAND_SOURCE_IDENTITIES[pid]' 'OWNED_COMMAND_ROLES[pid]'
  unset 'OWNED_COMMAND_FILES[pid]'
  [[ -z "$prefix" ]] || /bin/rm -f "$prefix.pid" "$prefix.release"
}

join_owned_command() {
  local pid="$1" deadline="$2" mode="${3:-wait}" grace="${4:-1}"
  local identity="${OWNED_COMMAND_IDENTITIES[$1]}" tree_text="" tree_pid tree_identity
  local prefix="${OWNED_COMMAND_FILES[$1]}" source_pid="${OWNED_COMMAND_SOURCE_PIDS[$1]}"
  local incomplete=0 timed_out=0 child_rc=0 signal
  OWNED_JOIN_REAPED=0
  OWNED_JOIN_FORCED=0
  # A stale application variable or a reaped HTTP/3 entry confers no authority.
  [[ -n "${OWNED_COMMAND_ROLES[pid]}" ]] || return 125
  if [[ "$mode" == wait ]]; then
    while (( SECONDS < deadline )) && ! bounded_owned_job_has_exited "$pid"; do sleep 0.1; done
    bounded_owned_job_has_exited "$pid" || timed_out=1
  fi
  if ! bounded_owned_job_has_exited "$pid"; then
    deadline=$((SECONDS + grace))
    if [[ "$identity" =~ ^[0-9a-f]{64}$ ]] \
      && bounded_signal_owned_identity "$pid" "$identity" STOP
    then
      tree_text="$(bounded_collect_owned_tree "$pid" "$identity" "$deadline")" || incomplete=1
    elif ! bounded_owned_job_has_exited "$pid"; then
      incomplete=1
    fi
    for signal in TERM CONT; do
      while IFS=$'\t' read -r tree_pid tree_identity; do
        [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
        bounded_signal_owned_identity "$tree_pid" "$tree_identity" "$signal" || true
      done <<< "$tree_text"
    done
    while (( SECONDS < deadline )); do
      if bounded_owned_job_has_exited "$pid" && bounded_owned_tree_has_exited "$tree_text"; then break; fi
      sleep 0.1
    done
    if ! bounded_owned_job_has_exited "$pid" || ! bounded_owned_tree_has_exited "$tree_text"; then
      OWNED_JOIN_FORCED=1
      ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT=$((ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT + 1))
      while IFS=$'\t' read -r tree_pid tree_identity; do
        [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
        bounded_signal_owned_identity "$tree_pid" "$tree_identity" KILL || true
      done <<< "$tree_text"
      deadline=$((SECONDS + 1))
      while (( SECONDS < deadline )); do
        if bounded_owned_job_has_exited "$pid" && bounded_owned_tree_has_exited "$tree_text"; then break; fi
        sleep 0.1
      done
    fi
  fi
  if bounded_owned_job_has_exited "$pid"; then
    wait "$pid" 2>/dev/null || child_rc=$?
    unregister_owned_command "$pid"
    OWNED_JOIN_REAPED=1
    if [[ -z "$tree_text" ]] && ! bounded_drain_receipt_valid "$prefix.complete" "$source_pid" "$child_rc"; then
      incomplete=1
    fi
    /bin/rm -f "$prefix.complete"
  else
    incomplete=1
  fi
  if (( incomplete )) || ! bounded_owned_tree_has_exited "$tree_text"; then
    : > "$BOUNDED_CLEANUP_FAILED"
    return 125
  fi
  (( timed_out == 0 && OWNED_JOIN_FORCED == 0 )) || return 124
  return "$child_rc"
}

capture_provider_generation_sample() {
  local mode="$1"
  run_bounded 15 /usr/bin/python3 "$SIGNED_EVIDENCE" capture-provider-generation \
    --identity "$TMP_DIR/provider-identity.tsv" "$mode" "$PROVIDER_GENERATION_SAMPLES" \
    >/dev/null 2>/dev/null
}

start_provider_generation_monitor() {
  /bin/rm -f "$PROVIDER_GENERATION_MONITOR_STOP" "$PROVIDER_GENERATION_MONITOR_FAILED"
  capture_provider_generation_sample --output || {
    add_issue "could not capture the initial canonical provider generation sample"
    return 1
  }
  start_owned_command monitor /usr/bin/python3 -c '
import pathlib, subprocess, sys, time
helper, identity, samples, stop, failed = sys.argv[1:]
while not pathlib.Path(stop).exists():
    time.sleep(2)
    if pathlib.Path(stop).exists():
        break
    try:
        result = subprocess.run(
            [sys.executable, helper, "capture-provider-generation", "--identity",
             identity, "--append", samples],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
        if result.returncode == 0:
            continue
    except (OSError, subprocess.TimeoutExpired):
        pass
    pathlib.Path(failed).touch()
    sys.exit(1)
' "$SIGNED_EVIDENCE" "$TMP_DIR/provider-identity.tsv" "$PROVIDER_GENERATION_SAMPLES" \
    "$PROVIDER_GENERATION_MONITOR_STOP" "$PROVIDER_GENERATION_MONITOR_FAILED" || return 1
  PROVIDER_GENERATION_MONITOR_PID="$OWNED_COMMAND_PID"
}

# shellcheck disable=SC2329  # invoked from the EXIT trap via finalize
stop_provider_generation_monitor() {
  local rc=0
  [[ "$PROVIDER_GENERATION_MONITOR_PID" =~ ^[1-9][0-9]*$ ]] || return 0
  : > "$PROVIDER_GENERATION_MONITOR_STOP"
  join_owned_command "$PROVIDER_GENERATION_MONITOR_PID" "$((SECONDS + 18))" || rc=$?
  (( OWNED_JOIN_REAPED == 0 )) || PROVIDER_GENERATION_MONITOR_PID=""
  if [[ "$rc" != 0 || -e "$PROVIDER_GENERATION_MONITOR_FAILED" ]]; then
    add_issue "canonical provider generation sampling failed or did not stop cleanly during the signed run"
    return 1
  fi
  /bin/rm -f "$PROVIDER_GENERATION_MONITOR_STOP" "$PROVIDER_GENERATION_MONITOR_FAILED"
}

capture_producer_sources() {
  local source target
  while IFS=$'\t' read -r source target; do
    if [[ ! -f "$source" || -L "$source" ]] \
      || ! /bin/cp -p "$source" "$TMP_DIR/$target"
    then
      add_issue "could not snapshot exact modern producer source $target"
      return 1
    fi
  done <<EOF
${BASH_SOURCE[0]}	source-test_modern_udp_flow.sh
$PROBE_SOURCE	source-modern_udp_e2e_probe.py
$INSTALLER_SOURCE	source-install_tproxy_app_bundle.sh
$MODERN_EVIDENCE_SOURCE	source-modern_udp_evidence.py
$SOAK_PRESSURE_SOURCE	source-soak_pressure_log.py
$SIGNED_EVIDENCE_SOURCE	source-signed_run_evidence.py
EOF
  PRODUCER_SOURCES_SHA256="$(/usr/bin/python3 - "$TMP_DIR" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
names = sorted((
    "source-test_modern_udp_flow.sh",
    "source-modern_udp_e2e_probe.py",
    "source-install_tproxy_app_bundle.sh",
    "source-modern_udp_evidence.py",
    "source-soak_pressure_log.py",
    "source-signed_run_evidence.py",
))
digest = hashlib.sha256()
for name in names:
    content = (root / name).read_bytes()
    digest.update(name.encode("utf-8") + b"\0")
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
print(digest.hexdigest())
PY
)" || PRODUCER_SOURCES_SHA256=none
  [[ "$PRODUCER_SOURCES_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    add_issue "could not fingerprint exact modern producer sources"
    return 1
  }
  PROBE="$TMP_DIR/source-modern_udp_e2e_probe.py"
  INSTALLER="$TMP_DIR/source-install_tproxy_app_bundle.sh"
  SIGNED_EVIDENCE="$TMP_DIR/source-signed_run_evidence.py"
  MODERN_EVIDENCE="$TMP_DIR/source-modern_udp_evidence.py"
}

wait_for_child_until() {
  local rc=0
  join_owned_command "$1" "$2" || rc=$?
  if (( rc == 124 )); then CONCURRENT_LOAD_TIMED_OUT=1; fi
  return "$rc"
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
stop_active_workloads() {
  local pid role rc
  # The registry contains only still-owned supervisor generations. Source PIDs
  # in evidence and already-reaped HTTP/3 rows are never cleanup inputs.
  for pid in "${!OWNED_COMMAND_ROLES[@]}"; do
    role="${OWNED_COMMAND_ROLES[pid]}"
    case "$role" in probe|echo|pressure|http3|http3-intercept) ;; *) continue ;; esac
    rc=0
    join_owned_command "$pid" "$SECONDS" stop 5 || rc=$?
    case "$rc" in
      0|130|143) ;;
      *) add_issue "active $role command did not stop cleanly (exit $rc)" ;;
    esac
  done
}

# shellcheck disable=SC2329  # invoked by the EXIT finalizer
stop_remaining_owned_commands() {
  local pid rc
  for pid in "${!OWNED_COMMAND_ROLES[@]}"; do
    add_issue "owned ${OWNED_COMMAND_ROLES[pid]} command remained after phase cleanup"
    rc=0
    join_owned_command "$pid" "$SECONDS" stop 1 || rc=$?
    (( rc != 125 )) || : > "$BOUNDED_CLEANUP_FAILED"
  done
}

capture_common_provider_identity() {
  local fields
  if ! run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" capture-provider \
    --built-provider "$BUILT_PROVIDER" --installed-provider "$INSTALLED_PROVIDER" \
    --pid "$PROVIDER_PID" --output "$TMP_DIR/provider-identity.tsv" \
    --source-root "$(cd "$ROOT_DIR/../../../.." && pwd)" \
    > "$TMP_DIR/provider-identity.out" 2> "$TMP_DIR/provider-identity.err"
  then
    add_issue "shared signed evidence could not capture exact provider identity"
    return 1
  fi
  fields="$(/usr/bin/python3 - "$TMP_DIR/provider-identity.tsv" <<'PY'
import sys
values = {}
for line in open(sys.argv[1], encoding="utf-8"):
    key, value = line.rstrip("\n").split("\t", 1)
    if key in values:
        raise SystemExit(2)
    values[key] = value
required = ("source_git_head", "source_git_dirty", "provider_build_identity", "provider_generation_identity")
if any(key not in values for key in required):
    raise SystemExit(2)
print(*(values[key] for key in required))
PY
)" || {
    add_issue "shared provider identity artifact is malformed"
    return 1
  }
  read -r SOURCE_GIT_HEAD SOURCE_GIT_DIRTY PROVIDER_BUILD_IDENTITY \
    PROVIDER_GENERATION_IDENTITY <<< "$fields"
  PROVIDER_IDENTITY="$PROVIDER_GENERATION_IDENTITY"
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
write_workload_claims() {
  local dial9_coverage=0 dial9_claim=incomplete
  if (( DIAL9_REQUIREMENT_COUNT > 0 \
    && DIAL9_MATCHED_REQUIREMENT_COUNT == DIAL9_REQUIREMENT_COUNT )); then
    dial9_coverage=1
    dial9_claim=exact-workload
  fi
  {
    printf 'evidence_kind\tmodern_udp\nrun_uuid\t%s\n' "$RUN_UUID"
    printf 'dial9_diagnostic_only\t0\ndial9_workload_coverage\t%s\n' "$dial9_coverage"
    printf 'dial9_claim\t%s\n' "$dial9_claim"
    printf 'quic_shaped_not_valid_quic\t1\n'
    printf 'echo_socket_count\t%s\necho_exact_echo_count\t%s\n' \
      "$ECHO_SOCKET_COUNT" "$ECHO_EXACT_ECHO_COUNT"
    printf 'http3_request_count\t%s\nhttp3_pass_count\t%s\n' \
      "$HTTP3_REQUEST_COUNT" "$HTTP3_PASS_COUNT"
    printf 'http3_intercept_passed\t%s\n' "$HTTP3_INTERCEPT_PASSED"
    printf 'dial9_requirement_count\t%s\ndial9_matched_requirement_count\t%s\n' \
      "$DIAL9_REQUIREMENT_COUNT" "$DIAL9_MATCHED_REQUIREMENT_COUNT"
    printf 'producer_sources_sha256\t%s\n' "$PRODUCER_SOURCES_SHA256"
    printf 'schema_complete\t1\n'
  } > "$WORKLOAD_CLAIMS"
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
write_common_evidence_status() {
  local complete="$1" passed="$2" exit_code="$3" claims_sha
  claims_sha="$(shasum -a 256 "$WORKLOAD_CLAIMS" | awk 'NR == 1 { print $1 }')"
  {
    printf 'complete\t%s\npassed\t%s\nexit_code\t%s\n' \
      "$complete" "$passed" "$exit_code"
    printf 'evidence_kind\tmodern_udp\nrun_uuid\t%s\n' "$RUN_UUID"
    printf 'run_start_epoch_ms\t%s\nrun_end_epoch_ms\t%s\n' \
      "$RUN_START_EPOCH_MS" "$RUN_END_EPOCH_MS"
    printf 'git_head\t%s\ngit_dirty\t%s\n' "$SOURCE_GIT_HEAD" "$SOURCE_GIT_DIRTY"
    printf 'provider_build_identity\t%s\nprovider_generation_identity\t%s\n' \
      "$PROVIDER_BUILD_IDENTITY" "$PROVIDER_GENERATION_IDENTITY"
    printf 'workload_claims_sha256\t%s\nschema_complete\t1\n' "$claims_sha"
  } > "$COMMON_EVIDENCE_STATUS"
}

# shellcheck disable=SC2329  # invoked by the EXIT finalizer's log verdict
write_provider_log_phases() {
  local provider_log_end
  provider_log_end="$(provider_log_line)"
  {
    printf 'schema_version\t2\n'
    printf 'unblocked_start_line\t%s\nudp_error_start_line\t%s\n' \
      "$UNBLOCKED_LOG_LINE" "$UDP_ERROR_PROVIDER_LOG_LINE"
    printf 'passthrough_start_line\t%s\npassthrough_end_line\t%s\n' \
      "$PASSTHROUGH_DNS_LOG_START" "$PASSTHROUGH_DNS_LOG_END"
    printf 'ntp_start_line\t%s\nntp_end_line\t%s\n' "$NTP_LOG_START" "$NTP_LOG_END"
    printf 'control_start_line\t%s\ncontrol_end_line\t%s\n' \
      "$CONTROL_DNS_LOG_START" "$CONTROL_DNS_LOG_END"
    printf 'http3_start_line\t%s\nhttp3_end_line\t%s\n' \
      "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_PROVIDER_LOG_END"
    printf 'blocked_profile_start_line\t%s\n' "$BLOCKED_LOG_LINE"
    printf 'blocked_start_line\t%s\nblocked_end_line\t%s\n' \
      "$BLOCKED_DNS_LOG_START" "$BLOCKED_DNS_LOG_END"
    printf 'pressure_start_line\t%s\npressure_end_line\t%s\n' \
      "$PRESSURE_LOG_START" "$PRESSURE_END_LOG_LINE"
    printf 'echo_start_line\t%s\necho_end_line\t%s\n' "$ECHO_LOG_START" "$ECHO_LOG_END"
    printf 'recovery_start_line\t%s\nrecovery_end_line\t%s\n' \
      "$RECOVERY_NTP_LOG_START" "$RECOVERY_NTP_LOG_END"
    printf 'http3_intercept_start_line\t%s\nhttp3_intercept_end_line\t%s\n' \
      "$HTTP3_INTERCEPT_LOG_START" "$HTTP3_INTERCEPT_LOG_END"
    printf 'provider_log_end_line\t%s\nschema_complete\t1\n' "$provider_log_end"
  } > "$PROVIDER_LOG_PHASES"
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
    printf 'run_start_epoch_ms\t%s\nrun_end_epoch_ms\t%s\n' \
      "$RUN_START_EPOCH_MS" "$RUN_END_EPOCH_MS"
    printf 'evidence_kind\tmodern_udp\n'
    printf 'provider_generation_identity\t%s\n' "$PROVIDER_GENERATION_IDENTITY"
    printf 'producer_sources_sha256\t%s\n' "$PRODUCER_SOURCES_SHA256"
    printf 'engine_generations_sha256\t%s\n' "$ENGINE_GENERATIONS_SHA256"
    printf 'provider_pid\t%s\nprovider_identity\t%s\nprovider_identity_stable\t%s\n' \
      "${PROVIDER_PID:-none}" "${PROVIDER_IDENTITY:-none}" "$PROVIDER_IDENTITY_STABLE"
    printf 'http3_source_pid\t%s\n' "$HTTP3_SOURCE_PID"
    printf 'http3_flow_id\t%s\nhttp3_remote_endpoint\t%s\n' \
      "$HTTP3_FLOW_ID" "$HTTP3_REMOTE_ENDPOINT"
    printf 'http3_request_count\t%s\nhttp3_pass_count\t%s\nhttp3_flow_count\t%s\n' \
      "$HTTP3_REQUEST_COUNT" "$HTTP3_PASS_COUNT" "$HTTP3_FLOW_COUNT"
    printf 'http3_duration_ms\t%s\nhttp3_min_concurrent\t%s\n' \
      "$HTTP3_DURATION_MS" "$HTTP3_MIN_CONCURRENT"
    printf 'http3_intercept_passed\t%s\nhttp3_intercept_source_pid\t%s\n' \
      "$HTTP3_INTERCEPT_PASSED" "$HTTP3_INTERCEPT_SOURCE_PID"
    printf 'http3_intercept_flow_id\t%s\nhttp3_intercept_provider_generation\t%s\n' \
      "$HTTP3_INTERCEPT_FLOW_ID" "$HTTP3_INTERCEPT_PROVIDER_GENERATION"
    printf 'http3_intercept_local_endpoint\t%s\nhttp3_intercept_remote_endpoint\t%s\n' \
      "$HTTP3_INTERCEPT_LOCAL_ENDPOINT" "$HTTP3_INTERCEPT_REMOTE_ENDPOINT"
    printf 'echo_socket_count\t%s\necho_datagrams_per_socket\t%s\n' \
      "$ECHO_SOCKET_COUNT" "$ECHO_DATAGRAMS_PER_SOCKET"
    printf 'echo_payload_bytes\t%s\necho_expected_count\t%s\n' \
      "$ECHO_PAYLOAD_BYTES" "$ECHO_EXPECTED_COUNT"
    printf 'echo_exact_echo_count\t%s\necho_flow_count\t%s\n' \
      "$ECHO_EXACT_ECHO_COUNT" "$ECHO_FLOW_COUNT"
    printf 'echo_payload_set_sha256\t%s\necho_endpoint\t%s\n' \
      "$ECHO_PAYLOAD_SET_SHA256" "$ECHO_ENDPOINT"
    printf 'echo_source_pid\t%s\n' "$ECHO_SOURCE_PID"
    printf 'pressure_datagram_count\t%s\npressure_payload_bytes\t%s\n' \
      "$PRESSURE_COUNT" "$PRESSURE_PAYLOAD_BYTES"
    printf 'pressure_expected_bytes\t%s\n' "$PRESSURE_EXPECTED_BYTES"
    printf 'concurrent_load_deadline_seconds\t%s\nconcurrent_load_timed_out\t%s\n' \
      "$CONCURRENT_LOAD_DEADLINE_SECONDS" "$CONCURRENT_LOAD_TIMED_OUT"
    printf 'active_workload_forced_termination_count\t%s\n' \
      "$ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT"
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
    printf 'recovery_ntp_source_pid\t%s\nrecovery_ntp_flow_id\t%s\n' \
      "$RECOVERY_NTP_SOURCE_PID" "$RECOVERY_NTP_FLOW_ID"
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
    printf 'dial9_requirements_sha256\t%s\n' "$DIAL9_REQUIREMENTS_SHA256"
    printf 'dial9_requirement_count\t%s\ndial9_matched_requirement_count\t%s\n' \
      "$DIAL9_REQUIREMENT_COUNT" "$DIAL9_MATCHED_REQUIREMENT_COUNT"
    printf 'schema_version\t6\n'
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
  PROVIDER_PROCESS_IDENTITY="$(provider_process_identity "$PROVIDER_PID" || true)"
  if [[ ! "$PROVIDER_PROCESS_IDENTITY" =~ ^[0-9a-f]{64}$ ]]; then
    add_issue "signed UDP E2E could not fingerprint the provider process"
    return 1
  fi
  PROVIDER_IDENTITY_STABLE=1
}

require_provider_identity() {
  local observed
  observed="$(provider_process_identity "$PROVIDER_PID" || true)"
  if [[ "$observed" != "$PROVIDER_PROCESS_IDENTITY" ]]; then
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
  local rc=0
  [[ "$LOG_PID" =~ ^[1-9][0-9]*$ ]] || return 0
  if owned_command_source_is_alive "$LOG_PID"; then
    LOG_STREAM_ALIVE_END=1
  else
    add_issue "provider log stream exited before the final capture boundary"
  fi
  join_owned_command "$LOG_PID" "$SECONDS" stop 5 || rc=$?
  if (( OWNED_JOIN_REAPED == 1 )) && [[ ! -e "$BOUNDED_CLEANUP_FAILED" ]]; then
    LOG_STREAM_JOINED=1
    LOG_PID=""
  fi
  case "$rc" in
    0|143) ;;
    *) add_issue "provider log stream did not stop cleanly (exit $rc)" ;;
  esac
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
stop_echo_server() {
  local rc=0
  [[ "$ECHO_SERVER_PID" =~ ^[1-9][0-9]*$ ]] || return 0
  # A normally completed server has already been reaped and unregistered.
  [[ -n "${OWNED_COMMAND_ROLES[ECHO_SERVER_PID]}" ]] || { ECHO_SERVER_PID=""; return 0; }
  join_owned_command "$ECHO_SERVER_PID" "$SECONDS" stop 5 || rc=$?
  (( OWNED_JOIN_REAPED == 0 )) || ECHO_SERVER_PID=""
  case "$rc" in
    0|130|143) ;;
    *) add_issue "controlled echo server did not stop cleanly (exit $rc)" ;;
  esac
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
restore_profile() {
  local starting_line ending_line line_count slice_sha256
  local restore_started_epoch_ms restore_completed_epoch_ms
  (( PROFILE_NEEDS_RESTORE == 1 )) || return 0
  PROFILE_RESTORED=0
  starting_line="$(container_log_line)"
  restore_started_epoch_ms="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  printf '%s\n' \
    'restore_invocation schema=1 mode=dev reset_profile=0 udp_passthrough_ports=empty udp_blocked_endpoints=empty evidence_identity=absent' \
    > "$TMP_DIR/restore.log"
  if ! run_bounded 90 "$INSTALLER" dev "$BUILT_APP" 0 \
    "--udp-passthrough-ports=" \
    "--udp-blocked-endpoints=" \
    >> "$TMP_DIR/restore.log" 2>&1
  then
    add_issue "automatic UDP policy restoration failed"
    return 1
  fi
  if ! wait_for_connected "$starting_line"; then
    add_issue "default UDP profile did not reconnect after restoration"
    return 1
  fi
  ending_line="$(container_log_line)"
  line_count=$((ending_line - starting_line))
  if (( line_count < 4 || line_count > 256 )); then
    add_issue "default UDP profile restoration log slice is outside its bounded cardinality"
    return 1
  fi
  sed -n "$((starting_line + 1)),${ending_line}p" "$CONTAINER_LOG" \
    > "$RESTORE_CONTAINER_LOG"
  slice_sha256="$(shasum -a 256 "$RESTORE_CONTAINER_LOG" | awk 'NR == 1 { print $1 }')"
  restore_completed_epoch_ms="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  if [[ ! "$slice_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    add_issue "default UDP profile restoration log slice could not be fingerprinted"
    return 1
  fi
  {
    printf 'schema_version\t1\nrun_uuid\t%s\n' "$RUN_UUID"
    printf 'provider_pid\t%s\nreplaced_provider_generation\t%s\n' \
      "$PROVIDER_PID" "$BLOCKED_PROVIDER_GENERATION"
    printf 'restore_started_epoch_ms\t%s\nrestore_completed_epoch_ms\t%s\n' \
      "$restore_started_epoch_ms" "$restore_completed_epoch_ms"
    printf 'container_start_line\t%s\ncontainer_end_line\t%s\n' \
      "$starting_line" "$ending_line"
    printf 'slice_line_count\t%s\nslice_sha256\t%s\n' "$line_count" "$slice_sha256"
    printf 'profile\tpersisted-default\nevidence_identity\tabsent\n'
    printf 'fresh_connected\t1\nschema_complete\t1\n'
  } > "$RESTORE_RECEIPT"
  PROFILE_NEEDS_RESTORE=0
  PROFILE_RESTORED=1
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
collect_dial9_evidence() {
  local metrics gate_end_monotonic_ms
  (( DIAL9_COLLECTION_ATTEMPTED == 0 )) || return 0
  DIAL9_COLLECTION_ATTEMPTED=1
  (( DIAL9_BASELINE_READY == 1 )) || return 0
  if [[ ! -s "$DIAL9_REQUIREMENTS" ]]; then
    add_issue "exact intercepted-flow Dial9 requirements are unavailable"
    return 1
  fi
  gate_end_monotonic_ms="$(monotonic_ms_now)"
  DIAL9_CLOSE_AGE_BOUND_MS=$((gate_end_monotonic_ms - GATE_START_MONOTONIC_MS))
  (( DIAL9_CLOSE_AGE_BOUND_MS > 0 )) || {
    add_issue "signed UDP gate produced an invalid monotonic evidence window"
    return 1
  }
  # The unprivileged shell intentionally owns the artifact redirections.
  # shellcheck disable=SC2024
  if ! run_bounded 30 sudo -n "$DIAL9_EVIDENCE_BIN" collect \
    "$DIAL9_DIR" "$DIAL9_BASELINE" "$TMP_DIR/dial9-traces" \
    --wait-seconds 15 --requirements "$DIAL9_REQUIREMENTS" \
    > "$DIAL9_SUMMARY" 2> "$TMP_DIR/dial9-collect.err"
  then
    add_issue "current-run dial9 UDP flow evidence is unavailable"
    return 1
  fi
  run_bounded 30 sudo -n chown -R "$(id -u):$(id -g)" \
    "$TMP_DIR/dial9-traces" "$DIAL9_SUMMARY" 2>/dev/null || {
      add_issue "could not transfer dial9 evidence artifact ownership"
      return 1
    }
  metrics="$(/usr/bin/python3 - "$DIAL9_SUMMARY" "$DIAL9_REQUIREMENTS" \
    "$DIAL9_CLOSE_AGE_BOUND_MS" <<'PY'
import csv, hashlib, io, json, sys
try:
    value = json.load(open(sys.argv[1]))
    if value.get("schema_version") != 1 or value.get("schema_complete") is not True:
        raise ValueError("incomplete schema")
    requirements = open(sys.argv[2], "rb").read()
    digest = hashlib.sha256(requirements).hexdigest()
    requirement_rows = list(csv.DictReader(
        io.StringIO(requirements.decode("utf-8")), delimiter="\t"
    ))
    count = len(requirement_rows)
    flows = value.get("required_flows")
    if value.get("requirements_sha256") != digest:
        raise ValueError("requirements identity mismatch")
    if value.get("requirement_count") != count or value.get("matched_requirement_count") != count:
        raise ValueError("not every exact intercepted flow was matched")
    if not isinstance(flows, list) or len(flows) != count:
        raise ValueError("required flow evidence cardinality mismatch")
    expected = {row["label"]: row for row in requirement_rows}
    observed = {flow.get("label"): flow for flow in flows}
    if len(expected) != count or len(observed) != count or expected.keys() != observed.keys():
        raise ValueError("required flow labels mismatch")
    for label, row in expected.items():
        flow = observed[label]
        for key in ("provider_pid", "provider_generation", "flow_id", "protocol", "source_pid", "close_reason"):
            if flow.get(key) != int(row[key]):
                raise ValueError(f"required flow identity mismatch: {label}")
        if not int(row["min_bytes_in"]) <= flow.get("bytes_in", -1) <= int(row["max_bytes_in"]):
            raise ValueError(f"required flow ingress mismatch: {label}")
        if not int(row["min_bytes_out"]) <= flow.get("bytes_out", -1) <= int(row["max_bytes_out"]):
            raise ValueError(f"required flow egress mismatch: {label}")
    if any(flow.get("close_reason") != 1 or flow.get("close_reason_name") != "shutdown" for flow in flows):
        raise ValueError("required flow had non-shutdown close")
    ages = [flow.get("close_age_ms") for flow in flows]
    if not all(isinstance(age, int) and 0 <= age <= int(sys.argv[3]) for age in ages):
        raise ValueError("invalid close age")
    print(value["current_segment_count"], count, count, digest, max(ages, default=0))
except Exception:
    raise SystemExit(2)
PY
)" || {
    add_issue "dial9 evidence summary is malformed or incomplete"
    return 1
  }
  read -r DIAL9_CURRENT_SEGMENT_COUNT DIAL9_REQUIREMENT_COUNT \
    DIAL9_MATCHED_REQUIREMENT_COUNT DIAL9_REQUIREMENTS_SHA256 \
    DIAL9_REQUIRED_CLOSE_AGE_MS <<< "$metrics"
  DIAL9_REQUIRED_PAIR_COUNT="$DIAL9_MATCHED_REQUIREMENT_COUNT"
  DIAL9_REQUIRED_CLOSE_REASON=1
  DIAL9_REQUIRED_CLOSE_REASON_NAME=shutdown
  DIAL9_REQUIRED_BYTES_IN=0
  DIAL9_REQUIRED_BYTES_OUT=0
}

# shellcheck disable=SC2329  # invoked by trap
finalize() {
  local raw_exit="$?" final_exit=2 complete=0 passed=0 value parsed_status crash_count
  (( FINALIZING == 0 )) || return
  FINALIZING=1
  trap - EXIT INT TERM
  if (( MAIN_FINISHED == 0 && raw_exit != 0 && ${#ISSUES[@]} == 0 )); then
    add_issue "unhandled command failure in phase $CURRENT_PHASE (exit $raw_exit)"
  fi
  stop_active_workloads
  stop_echo_server
  # Restoration seals the second E2E generation, including intercepted H3.
  # Collect once afterwards; exact generation requirements exclude new flows.
  restore_profile || true
  require_provider_identity || true
  collect_dial9_evidence || true
  capture_provider_generation_sample --append || \
    add_issue "could not capture the canonical provider generation before the run boundary"
  # Capture includes workload cleanup, sealed Dial9 collection, and the exact
  # default-profile restoration. Allow asynchronous bridge records to arrive
  # before freezing the boundary while the owned logger is still alive.
  if (( LOG_STREAM_STARTED == 1 )); then
    sleep 2
  fi
  RUN_END_EPOCH_MS="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  if [[ ! "$RUN_END_EPOCH_MS" =~ ^[1-9][0-9]*$ \
    || "$RUN_END_EPOCH_MS" -lt "$RUN_START_EPOCH_MS" ]]
  then
    add_issue "could not capture a valid signed UDP wall-clock end"
  fi
  stop_log_capture
  if (( LOG_STREAM_JOINED == 1 )); then
    check_final_provider_logs || true
  fi
  crash_count="$(run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" snapshot-crashes \
    --since-epoch-ms "$RUN_START_EPOCH_MS" --output-dir "$TMP_DIR/crashes" \
    --run-uuid "$RUN_UUID" \
    --provider-generation-identity "$PROVIDER_GENERATION_IDENTITY" \
    --process "$PROVIDER_BUNDLE" 2>/dev/null \
    | awk -F '\t' '$1 == "crash_count" { print $2 }')"
  if [[ ! "$crash_count" =~ ^[0-9]+$ ]]; then
    add_issue "shared signed evidence could not snapshot provider crashes"
  elif (( crash_count > 0 )); then
    add_failure "provider crash reports were created during the signed UDP run"
  fi
  capture_provider_generation_sample --append || \
    add_issue "could not re-observe the canonical provider generation after the crash snapshot"
  stop_provider_generation_monitor || true
  stop_remaining_owned_commands
  require_provider_identity || true
  if [[ -e "$BOUNDED_CLEANUP_FAILED" ]]; then
    add_issue "bounded command cleanup could not prove every artifact writer exited"
  fi
  if (( UDP_PROBE_ATTEMPT_COUNT != 9 )); then
    add_issue "signed UDP E2E attempted $UDP_PROBE_ATTEMPT_COUNT of 9 required probe groups"
  fi
  if (( UDP_PRESSURE_LOG_CHECKED != 1 )); then
    add_issue "signed UDP E2E did not validate UDP pressure telemetry"
  fi
  if (( PRESSURE_PROBE_ATTEMPTED != 1 || PRESSURE_PROBE_PASSED != 1 )); then
    add_issue "signed UDP E2E did not complete the deliberate pressure probe"
  fi
  if (( raw_exit == 130 || raw_exit == 143 )); then
    final_exit="$raw_exit"
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
  elif (( ${#ISSUES[@]} > 0 )); then
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
  elif (( ${#FAILURES[@]} > 0 )); then
    complete=1
    final_exit=1
  elif (( UDP_PROBE_PASS_COUNT != 9 )); then
    add_issue "signed UDP E2E passed $UDP_PROBE_PASS_COUNT of 9 required probe groups"
  else
    complete=1
    passed=1
    final_exit=0
  fi
  write_workload_claims
  write_evidence_status "$complete" "$passed" "$final_exit"
  parsed_status=$(/usr/bin/python3 "$MODERN_EVIDENCE" \
    "$EVIDENCE_STATUS" 2>/dev/null) || parsed_status=invalid
  if [[ "$parsed_status" != "$final_exit" ]]; then
    add_issue "terminal UDP evidence status failed strict self-validation"
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
    complete=0
    passed=0
    final_exit=2
    write_evidence_status 0 0 2
  fi
  write_common_evidence_status "$complete" "$passed" "$final_exit"
  if [[ -e "$BOUNDED_CLEANUP_FAILED" ]] \
    || ! run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" seal "$TMP_DIR" \
      --actual-exit-code "$final_exit" >/dev/null 2>/dev/null \
    || ! run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" verify "$TMP_DIR" \
      --actual-exit-code "$final_exit" >/dev/null 2>/dev/null
  then
    add_issue "shared signed evidence seal or verification failed"
    for value in "${FAILURES[@]}"; do OBSERVED_FAILURES+=("$value"); done
    FAILURES=()
    complete=0
    passed=0
    final_exit=2
    write_workload_claims
    write_evidence_status 0 0 2
    write_common_evidence_status 0 0 2
    if [[ ! -e "$BOUNDED_CLEANUP_FAILED" ]]; then
      run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" seal "$TMP_DIR" \
        --actual-exit-code 2 >/dev/null 2>/dev/null || true
      if [[ ! -e "$BOUNDED_CLEANUP_FAILED" ]]; then
        run_bounded 30 /usr/bin/python3 "$SIGNED_EVIDENCE" verify "$TMP_DIR" \
          --actual-exit-code 2 >/dev/null 2>/dev/null || true
      fi
    fi
  fi
  echo "modern UDP E2E artifacts: $TMP_DIR"
  exit "$final_exit"
}

trap finalize EXIT
trap 'add_issue "signed UDP E2E interrupted by SIGINT"; exit 130' INT
trap 'add_issue "signed UDP E2E interrupted by SIGTERM"; exit 143' TERM

fatal_issue() {
  add_issue "$1"
  echo "$1" >&2
  exit 2
}

run_probe() {
  local description="$1" expected_product_rc="$2" label="$3" protocol="$4" server="$5"
  shift 5
  local rc=0 port=53 receipt="$TMP_DIR/udp-probe-$label.json"
  [[ "$protocol" != ntp ]] || port=123
  UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
  LAST_PROBE_LOG_START="$(provider_log_line)"
  start_owned_command probe /usr/bin/python3 "$PROBE" "$protocol" --server "$server" \
    --run-uuid "$RUN_UUID" --probe-label "$label" --result-file "$receipt" "$@" || {
    add_issue "$description could not start its owned probe"
    return 1
  }
  LAST_PROBE_PID="$OWNED_COMMAND_SOURCE_PID"
  ACTIVE_PROBE_PID="$OWNED_COMMAND_PID"
  join_owned_command "$ACTIVE_PROBE_PID" "$((SECONDS + 30))" || rc=$?
  (( OWNED_JOIN_REAPED == 0 )) || ACTIVE_PROBE_PID=""
  close_probe_decision_window "$LAST_PROBE_LOG_START" "$LAST_PROBE_PID"
  # Preserve the observed child exit separately from its raw protocol receipt.
  # Neither a missing/partial publication nor a mismatched result earns a pass.
  if ! printf '%s\t%s\t%s\n' "$label" "$LAST_PROBE_PID" "$rc" >> "$PROBE_RESULTS" \
    || ! /usr/bin/python3 "$PROBE" verify-receipt "$receipt" \
      --run-uuid "$RUN_UUID" --probe-label "$label" --source-pid "$LAST_PROBE_PID" \
      --endpoint "$server:$port" --exit-code "$rc"
  then
    add_issue "$description lacks a complete matching raw protocol receipt"
    return 1
  fi
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
    's/.*udp_e2e_decision run_uuid=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) provider_pid=([0-9]+) provider_generation=([0-9]+) rama_decision=([^ ]+) flow_id=([0-9]+) remote_endpoint=([^ ]+) local_endpoint=([^ ]+) source_app=([^ ]+) source_pid=([0-9]+)$/\4\t\5\t\6\t\7\t\8\t\9\t\1\t\2\t\3/p'
}

decision_marker_count_for_pid() {
  local starting_line="$1" ending_line="$2" source_pid="$3"
  sed -n "$((starting_line + 1)),${ending_line}p" "$PROVIDER_LOG" 2>/dev/null \
    | /usr/bin/python3 -c 'import re, sys; pid = re.escape(sys.argv[1]); pattern = re.compile(r"udp_e2e_decision .*source_pid=" + pid + r"(?:[^0-9]|$)"); print(sum(pattern.search(line) is not None for line in sys.stdin))' \
      "$source_pid"
}

is_canonical_udp_endpoint() {
  /usr/bin/python3 -c 'import ipaddress, sys; value=sys.argv[1]; host, port=(value[1:].split("]:", 1) if value.startswith("[") else value.rsplit(":", 1)); raise SystemExit(0 if str(ipaddress.ip_address(host)) == host and 1 <= int(port) <= 65535 else 1)' "$1" 2>/dev/null
}

close_probe_decision_window() {
  local starting_line="$1" source_pid="$2" expected="${3:-1}"
  local ending_line snapshot="" previous="" count
  local stable_ticks=0
  # Require a decision-prefix quiescence interval after the first delivery.
  # This catches delayed duplicate rows without widening the PID window across
  # later probes, where process-id reuse could otherwise create ambiguity.
  for _ in $(seq 1 100); do
    ending_line="$(provider_log_line)"
    snapshot="$(decision_records "$starting_line" "$ending_line" \
      | awk -F '\t' -v pid="$source_pid" '$6 == pid')"
    count="$(printf '%s\n' "$snapshot" | awk 'NF { count += 1 } END { print count + 0 }')"
    if (( count >= expected )); then
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

close_http3_decision_window() {
  local starting_line="$1" expected="$2" ending_line snapshot previous="" count
  local stable_ticks=0
  for _ in $(seq 1 150); do
    ending_line="$(provider_log_line)"
    snapshot="$(awk -F '\t' \
      'NR == FNR { pids[$3] = 1; next } ($6 in pids) { print }' \
      "$HTTP3_PIDS" <(decision_records "$starting_line" "$ending_line"))"
    count="$(printf '%s\n' "$snapshot" | awk 'NF { count += 1 } END { print count + 0 }')"
    if (( count >= expected )); then
      if [[ "$snapshot" == "$previous" ]]; then
        stable_ticks=$((stable_ticks + 1))
      else
        stable_ticks=0
      fi
      if (( stable_ticks >= 10 )); then
        HTTP3_PROVIDER_LOG_END="$ending_line"
        return 0
      fi
    else
      stable_ticks=0
    fi
    previous="$snapshot"
    sleep 0.1
  done
  HTTP3_PROVIDER_LOG_END="$(provider_log_line)"
  add_issue "sustained HTTP/3 decisions did not reach exact cardinality"
  return 1
}

run_sustained_http3() {
  local start_ms end_ms round worker pid owner rc output marker digest round_pids deadline
  local barrier release_ms pre_release_alive
  local separator='?'
  [[ "$HTTP3_URL" == *\?* ]] && separator='&'
  : > "$HTTP3_PIDS"
  printf 'round\tworker\tsource_pid\texit_code\thttp3_marker\tsha256\n' > "$HTTP3_RESULTS"
  printf 'round\texpected_workers\tbarrier_release_epoch_ms\tpre_release_alive\n' \
    > "$HTTP3_ROUND_RESULTS"
  HTTP3_REQUEST_COUNT=$((HTTP3_ROUNDS * HTTP3_CONCURRENCY))
  HTTP3_MIN_CONCURRENT="$HTTP3_CONCURRENCY"
  HTTP3_PROVIDER_LOG_LINE="$(provider_log_line)"
  UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
  start_ms="$(monotonic_ms_now)"
  for round in $(seq 1 "$HTTP3_ROUNDS"); do
    round_pids="$TMP_DIR/http3-round-$round.pids"
    barrier="$TMP_DIR/http3-round-$round.release"
    : > "$round_pids"
    for worker in $(seq 1 "$HTTP3_CONCURRENCY"); do
      output="$TMP_DIR/http3-$round-$worker.log"
      # shellcheck disable=SC2016  # worker expands its own positional arguments
      start_owned_command http3 /bin/bash -c '
        barrier="$1"; shift
        while [[ ! -e "$barrier" ]]; do sleep 0.01; done
        exec "$@"
      ' http3-worker "$barrier" nscurl --http3-prior-knowledge -m 15 \
        "${HTTP3_URL}${separator}rama_udp_e2e_run=$RUN_UUID&round=$round&worker=$worker" \
        > "$output" 2>&1 || {
          add_issue "HTTP/3 round $round worker $worker could not start"
          return 1
        }
      pid="$OWNED_COMMAND_SOURCE_PID"
      owner="$OWNED_COMMAND_PID"
      printf '%s\t%s\t%s\n' "$round" "$worker" "$pid" >> "$HTTP3_PIDS"
      printf '%s\t%s\t%s\t%s\n' "$round" "$worker" "$pid" "$owner" >> "$round_pids"
    done
    pre_release_alive=0
    while IFS=$'\t' read -r _round _worker pid owner; do
      owned_command_source_is_alive "$owner" && pre_release_alive=$((pre_release_alive + 1))
    done < "$round_pids"
    (( pre_release_alive < HTTP3_MIN_CONCURRENT )) \
      && HTTP3_MIN_CONCURRENT="$pre_release_alive"
    if (( pre_release_alive != HTTP3_CONCURRENCY )); then
      add_issue "HTTP/3 barrier did not hold every concurrent worker in round $round"
    fi
    release_ms="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
    printf '%s\t%s\t%s\t%s\n' "$round" "$HTTP3_CONCURRENCY" \
      "$release_ms" "$pre_release_alive" >> "$HTTP3_ROUND_RESULTS"
    : > "$barrier"
    deadline=$((SECONDS + 20))
    while IFS=$'\t' read -r _round _worker pid owner; do
      rc=0
      join_owned_command "$owner" "$deadline" || rc=$?
      output="$TMP_DIR/http3-$_round-$_worker.log"
      marker=0
      grep -Fq 'http=http/3' "$output" && marker=1
      digest="$(shasum -a 256 "$output" | awk 'NR == 1 { print $1 }')"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$_round" "$_worker" "$pid" "$rc" "$marker" "$digest" >> "$HTTP3_RESULTS"
      if (( rc == 0 && marker == 1 )); then
        HTTP3_PASS_COUNT=$((HTTP3_PASS_COUNT + 1))
      fi
    done < "$round_pids"
    if (( round < HTTP3_ROUNDS )); then
      sleep "$HTTP3_ROUND_INTERVAL"
    fi
  done
  end_ms="$(monotonic_ms_now)"
  HTTP3_DURATION_MS=$((end_ms - start_ms))
  {
    printf 'schema_version\t1\nstart_monotonic_ms\t%s\nend_monotonic_ms\t%s\n' \
      "$start_ms" "$end_ms"
    printf 'duration_ms\t%s\nrounds\t%s\nconcurrency\t%s\n' \
      "$HTTP3_DURATION_MS" "$HTTP3_ROUNDS" "$HTTP3_CONCURRENCY"
    printf 'schema_complete\t1\n'
  } > "$HTTP3_TIMING"
  close_http3_decision_window "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_REQUEST_COUNT" || true
  if (( HTTP3_PASS_COUNT == HTTP3_REQUEST_COUNT && HTTP3_DURATION_MS > 0 )); then
    UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1))
  else
    add_issue "sustained concurrent UDP/443 probe did not complete every request over HTTP/3"
  fi
}

run_intercepted_http3() {
  local rc=0 endpoints
  HTTP3_INTERCEPT_LOG_START="$(provider_log_line)"
  UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
  start_owned_command http3-intercept /usr/bin/python3 "$PROBE" http3 \
    --libcurl "$HTTP3_LIBCURL" --url "$HTTP3_URL" --run-uuid "$RUN_UUID" \
    --result-file "$HTTP3_INTERCEPT_RESULT" --body-file "$HTTP3_INTERCEPT_BODY" \
    > "$TMP_DIR/http3-intercept.log" 2>&1 || {
      add_issue "intercepted HTTP/3 could not start its owned client"
      return 1
    }
  HTTP3_INTERCEPT_SOURCE_PID="$OWNED_COMMAND_SOURCE_PID"
  ACTIVE_PROBE_PID="$OWNED_COMMAND_PID"
  join_owned_command "$ACTIVE_PROBE_PID" "$((SECONDS + 25))" || rc=$?
  (( OWNED_JOIN_REAPED == 0 )) || ACTIVE_PROBE_PID=""
  close_probe_decision_window "$HTTP3_INTERCEPT_LOG_START" "$HTTP3_INTERCEPT_SOURCE_PID"
  HTTP3_INTERCEPT_LOG_END="$LAST_PROBE_LOG_END"
  printf 'source_pid\texit_code\n%s\t%s\n' "$HTTP3_INTERCEPT_SOURCE_PID" "$rc" \
    > "$TMP_DIR/http3-intercept-result.tsv" || return 1
  endpoints="$(/usr/bin/python3 "$PROBE" verify-http3-receipt "$HTTP3_INTERCEPT_RESULT" \
    --body-file "$HTTP3_INTERCEPT_BODY" --run-uuid "$RUN_UUID" \
    --source-pid "$HTTP3_INTERCEPT_SOURCE_PID" --url "$HTTP3_URL" \
    --exit-code "$rc" --print-endpoints)" || {
      add_issue "intercepted HTTP/3 lacks a complete matching raw response receipt"
      return 1
    }
  read -r HTTP3_INTERCEPT_LOCAL_ENDPOINT HTTP3_INTERCEPT_REMOTE_ENDPOINT <<< "$endpoints"
  HTTP3_INTERCEPT_PASSED=1
  UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1))
}

check_http3_intercept_decision() {
  local metrics
  metrics="$(/usr/bin/python3 -B - "$MODERN_EVIDENCE" "$PROBE" "$PROVIDER_LOG" \
    "$HTTP3_INTERCEPT_RESULT" "$HTTP3_INTERCEPT_BODY" "$RUN_UUID" \
    "$HTTP3_INTERCEPT_SOURCE_PID" "$HTTP3_URL" "$PROVIDER_PID" \
    "$BLOCKED_PROVIDER_GENERATION" "$HTTP3_INTERCEPT_LOG_START" \
    "$HTTP3_INTERCEPT_LOG_END" "$HTTP3_ENDPOINTS" <<'PY'
import runpy, sys
modern, probe = runpy.run_path(sys.argv[1]), runpy.run_path(sys.argv[2])
receipt = probe["read_http3_receipt"](sys.argv[4])
body = probe["read_http3_body"](sys.argv[5])
if probe["replay_http3_receipt"](receipt, body, sys.argv[6], int(sys.argv[7]), sys.argv[8]) != 0:
    raise SystemExit(2)
with open(sys.argv[3], encoding="utf-8") as stream:
    decisions = modern["_decision_records"](stream.read().splitlines())
phases = {"http3_intercept_start_line": int(sys.argv[11]),
          "http3_intercept_end_line": int(sys.argv[12])}
row = modern["validate_http3_intercept_decision"](
    decisions, phases, receipt, sys.argv[6], int(sys.argv[9]), int(sys.argv[10]),
)
with open(sys.argv[13], encoding="utf-8") as stream:
    endpoints = stream.read().splitlines()
if row["remote"] not in endpoints or sum(other["flow_id"] == row["flow_id"] for other in decisions) != 1:
    raise SystemExit(2)
print(row["flow_id"], row["generation"])
PY
)" || {
    add_issue "intercepted HTTP/3 lacked its exact socket tuple and provider generation"
    return 1
  }
  read -r HTTP3_INTERCEPT_FLOW_ID HTTP3_INTERCEPT_PROVIDER_GENERATION <<< "$metrics"
  # QUIC transport bytes include encrypted headers, handshake and acknowledgements.
  # Bound both directions independently of the HTTP response-body length.
  append_dial9_requirement http3-intercept "$HTTP3_INTERCEPT_FLOW_ID" \
    "$HTTP3_INTERCEPT_SOURCE_PID" "$HTTP3_INTERCEPT_PROVIDER_GENERATION" 1 16777216 1 16777216
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
    observation="$(/usr/bin/python3 -B - "$MODERN_EVIDENCE" "$PROVIDER_LOG" \
      "$starting_line" "$source_pid" "$endpoint" "$source_app" \
      "$RUN_UUID" "$PROVIDER_PID" "$TMP_DIR/source-soak_pressure_log.py" <<'PY'
import importlib.util, runpy, sys

# The modern helper imports this dependency by name inside the observation.
pressure_spec = importlib.util.spec_from_file_location("soak_pressure_log", sys.argv[9])
pressure_module = importlib.util.module_from_spec(pressure_spec)
sys.modules[pressure_spec.name] = pressure_module
pressure_spec.loader.exec_module(pressure_module)
pressure_window_observation = runpy.run_path(sys.argv[1])["pressure_window_observation"]

with open(sys.argv[2], encoding="utf-8") as provider_log:
    lines = provider_log.read().splitlines()
result = pressure_window_observation(
    lines, int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6],
    sys.argv[7], int(sys.argv[8]),
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
  local action flow_id remote local_endpoint source source_pid run_uuid provider_pid provider_generation
  local found=0 unexpected=0 matching_flow_id="" matching_generation="" raw_count
  local byte_counts bytes_in bytes_out
  while IFS=$'\t' read -r action flow_id remote local_endpoint source source_pid run_uuid provider_pid provider_generation; do
    [[ "$source_pid" == "$expected_pid" ]] || continue
    if ! is_canonical_udp_endpoint "$local_endpoint"; then
      unexpected=$((unexpected + 1))
      continue
    fi
    if [[ "$remote" != "$endpoint" || "$source" != "$source_app" \
      || "$run_uuid" != "$RUN_UUID" || "$provider_pid" != "$PROVIDER_PID" ]]
    then
      unexpected=$((unexpected + 1))
      continue
    fi
    found=$((found + 1))
    matching_flow_id="$flow_id"
    matching_generation="$provider_generation"
    if [[ "$action" != "$expected" ]]; then
      add_failure "$description recorded rama_decision=$action instead of $expected"
    fi
  done < <(decision_records "$starting_line" "$ending_line")
  raw_count="$(decision_marker_count_for_pid \
    "$starting_line" "$ending_line" "$expected_pid")"
  if [[ ! "$raw_count" =~ ^[0-9]+$ || "$raw_count" -ne $((found + unexpected)) ]]; then
    add_issue "$description contained a malformed or ambiguous diagnostic record"
  fi
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
  if [[ "$target" == pressure || "$target" == recovery ]] \
    && [[ "$matching_generation" != "$BLOCKED_PROVIDER_GENERATION" ]]
  then
    add_issue "$description used a different blocked provider generation"
    return 1
  fi
  if [[ "$target" == ntp || "$target" == recovery ]]; then
    # Bind Dial9's exact byte requirements to the once-only transaction the
    # child retained. NTP extensions can change response length, not ingress.
    byte_counts="$(/usr/bin/python3 "$PROBE" verify-receipt "$TMP_DIR/udp-probe-$target.json" \
      --run-uuid "$RUN_UUID" --probe-label "$target" --source-pid "$expected_pid" \
      --endpoint "$endpoint" --exit-code 0 --print-byte-counts)" || {
        add_issue "$description lacks successful raw byte evidence"
        return 1
      }
    if [[ ! "$byte_counts" =~ ^48\ [1-9][0-9]*$ ]]; then
      add_issue "$description returned malformed raw byte evidence"
      return 1
    fi
    read -r bytes_in bytes_out <<< "$byte_counts"
  fi
  case "$target" in
    passthrough) PASSTHROUGH_DNS_FLOW_ID="$matching_flow_id" ;;
    control) CONTROL_DNS_FLOW_ID="$matching_flow_id" ;;
    ntp)
      NTP_FLOW_ID="$matching_flow_id"
      UNBLOCKED_PROVIDER_GENERATION="$matching_generation"
      append_dial9_requirement ntp "$matching_flow_id" "$expected_pid" \
        "$matching_generation" "$bytes_in" "$bytes_in" "$bytes_out" "$bytes_out"
      ;;
    pressure)
      PRESSURE_FLOW_ID="$matching_flow_id"
      # Dial9 counts accepted ingress. This once-only burst must both deliver
      # at least one datagram and drop at least one on this exact pressure flow.
      append_dial9_requirement pressure "$matching_flow_id" "$expected_pid" \
        "$matching_generation" "$PRESSURE_PAYLOAD_BYTES" \
        "$((PRESSURE_EXPECTED_BYTES - PRESSURE_PAYLOAD_BYTES))" 0 0
      ;;
    blocked)
      BLOCKED_DNS_FLOW_ID="$matching_flow_id"
      BLOCKED_PROVIDER_GENERATION="$matching_generation"
      ;;
    recovery)
      RECOVERY_NTP_FLOW_ID="$matching_flow_id"
      append_dial9_requirement recovery-ntp "$matching_flow_id" "$expected_pid" \
        "$matching_generation" "$bytes_in" "$bytes_in" "$bytes_out" "$bytes_out"
      ;;
    http3) HTTP3_FLOW_ID="$matching_flow_id"; HTTP3_REMOTE_ENDPOINT="$endpoint" ;;
    *) add_issue "internal decision target is invalid: $target"; return 1 ;;
  esac
}

append_dial9_requirement() {
  local label="$1" flow_id="$2" source_pid="$3" generation="$4"
  local min_in="$5" max_in="$6" min_out="$7" max_out="$8"
  if [[ ! "$label" =~ ^[a-z0-9][a-z0-9_.-]*$ \
    || ! "$flow_id" =~ ^[1-9][0-9]*$ || ! "$source_pid" =~ ^[1-9][0-9]*$ \
    || ! "$generation" =~ ^[1-9][0-9]*$ ]]
  then
    add_issue "could not create a canonical Dial9 flow requirement for $label"
    return 1
  fi
  printf '%s\t%s\t%s\t%s\t2\t%s\t1\t%s\t%s\t%s\t%s\n' \
    "$label" "$PROVIDER_PID" "$generation" "$flow_id" "$source_pid" \
    "$min_in" "$max_in" "$min_out" "$max_out" >> "$DIAL9_REQUIREMENTS"
}

check_echo_decisions() {
  local records="$TMP_DIR/echo-decisions.tsv" identities="$TMP_DIR/echo-identities.tsv"
  local generation row_generation flow_id ordinal=0 bytes
  decision_records "$ECHO_LOG_START" "$ECHO_LOG_END" > "$records"
  /usr/bin/python3 - "$MODERN_EVIDENCE" "$records" "$identities" "$ECHO_CLIENT_RESULT" \
    "$ECHO_SOURCE_PID" "$RUN_UUID" "$PROVIDER_PID" "$ECHO_ENDPOINT" \
    "$ECHO_SOCKET_COUNT" <<'PY' || {
import json, runpy, sys
validate_echo_decision_bijection = runpy.run_path(sys.argv[1])["validate_echo_decision_bijection"]
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[2]) if line.strip()]
client_endpoints = json.load(open(sys.argv[4])).get("local_endpoints")
selected = validate_echo_decision_bijection(
    rows, client_endpoints, int(sys.argv[9]), int(sys.argv[5]), sys.argv[6],
    int(sys.argv[7]), sys.argv[8],
)
with open(sys.argv[3], "w", encoding="utf-8", newline="\n") as output:
    for generation, flow_id, local_endpoint in selected:
        output.write(f"{generation}\t{flow_id}\t{local_endpoint}\n")
PY
    add_issue "controlled echo load did not have one exact intercepted flow per socket"
    return 1
  }
  bytes=$((ECHO_DATAGRAMS_PER_SOCKET * ECHO_PAYLOAD_BYTES))
  while IFS=$'\t' read -r row_generation flow_id _local_endpoint; do
    generation="$row_generation"
    append_dial9_requirement "echo-$ordinal" "$flow_id" "$ECHO_SOURCE_PID" \
      "$generation" "$bytes" "$bytes" "$bytes" "$bytes" || true
    ordinal=$((ordinal + 1))
  done < "$identities"
  ECHO_FLOW_COUNT="$ordinal"
  if [[ "$(decision_marker_count_for_pid \
    "$ECHO_LOG_START" "$ECHO_LOG_END" "$ECHO_SOURCE_PID")" != "$ECHO_FLOW_COUNT" ]]; then
    add_issue "controlled echo load contained malformed or ambiguous diagnostics"
  fi
  for flow_id in "$PASSTHROUGH_DNS_FLOW_ID" "$CONTROL_DNS_FLOW_ID" "$NTP_FLOW_ID" \
    "$PRESSURE_FLOW_ID" "$RECOVERY_NTP_FLOW_ID" "$BLOCKED_DNS_FLOW_ID"; do
    if awk -F '\t' -v expected="$flow_id" \
      '$2 == expected { found = 1 } END { exit !found }' "$identities"; then
      add_issue "controlled echo flow identity collided with another probe flow"
    fi
  done
  [[ "$BLOCKED_PROVIDER_GENERATION" == "$generation" ]] \
    || add_issue "controlled echo flow used a different blocked provider generation"
}

check_http3_decisions() {
  local records="$TMP_DIR/http3-decisions.tsv" metrics pid raw_count raw_total=0
  decision_records "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_PROVIDER_LOG_END" > "$records"
  metrics="$(/usr/bin/python3 - "$records" "$HTTP3_PIDS" "$HTTP3_ENDPOINTS" \
    "$RUN_UUID" "$PROVIDER_PID" "$HTTP3_REQUEST_COUNT" "$TMP_DIR/echo-identities.tsv" \
    "$PASSTHROUGH_DNS_FLOW_ID,$CONTROL_DNS_FLOW_ID,$NTP_FLOW_ID,$PRESSURE_FLOW_ID,$RECOVERY_NTP_FLOW_ID,$BLOCKED_DNS_FLOW_ID" \
    "$MODERN_EVIDENCE" <<'PY'
import runpy, sys
is_http3_passthrough_local_endpoint = runpy.run_path(sys.argv[9])["is_http3_passthrough_local_endpoint"]
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1]) if line.strip()]
pids = {line.rstrip("\n").split("\t")[2] for line in open(sys.argv[2]) if line.strip()}
endpoints = {line.strip() for line in open(sys.argv[3]) if line.strip()}
run_uuid, provider_pid, expected = sys.argv[4], sys.argv[5], int(sys.argv[6])
echo_flows = {line.rstrip("\n").split("\t")[1] for line in open(sys.argv[7]) if line.strip()}
representative_flows = set(sys.argv[8].split(","))
if any(not flow.isdigit() or int(flow) <= 0 for flow in echo_flows | representative_flows):
    raise SystemExit(2)
selected = [row for row in rows if len(row) == 9 and row[5] in pids]
if len(pids) != expected or len(selected) != expected:
    raise SystemExit(2)
if {row[5] for row in selected} != pids or len({row[1] for row in selected}) != expected:
    raise SystemExit(2)
if any(row[2] not in endpoints
       or not is_http3_passthrough_local_endpoint(row[3], row[2], row[4], row[0])
       or row[6] != run_uuid
       or row[7] != provider_pid for row in selected):
    raise SystemExit(2)
if {row[1] for row in selected} & (echo_flows | representative_flows):
    raise SystemExit(2)
generations = {row[8] for row in selected}
if len(generations) != 1:
    raise SystemExit(2)
first = sorted(selected, key=lambda row: int(row[1]))[0]
print(len(selected), first[5], first[1], first[2], first[8])
PY
)" || {
    add_issue "sustained HTTP/3 traffic lacked exact PID/endpoint/flow diagnostics"
    return 1
  }
  read -r HTTP3_FLOW_COUNT HTTP3_SOURCE_PID HTTP3_FLOW_ID \
    HTTP3_REMOTE_ENDPOINT HTTP3_PROVIDER_GENERATION <<< "$metrics"
  while IFS=$'\t' read -r _round _worker pid; do
    raw_count="$(decision_marker_count_for_pid \
      "$HTTP3_PROVIDER_LOG_LINE" "$HTTP3_PROVIDER_LOG_END" "$pid")"
    [[ "$raw_count" =~ ^[0-9]+$ ]] || raw_count=0
    raw_total=$((raw_total + raw_count))
  done < "$HTTP3_PIDS"
  if (( raw_total != HTTP3_REQUEST_COUNT )); then
    add_issue "sustained HTTP/3 traffic contained malformed or ambiguous diagnostics"
  fi
  [[ "$HTTP3_PROVIDER_GENERATION" == "$UNBLOCKED_PROVIDER_GENERATION" ]] \
    || add_issue "HTTP/3 flow used a different unblocked provider generation"
}

# shellcheck disable=SC2329  # invoked after the logger is joined by finalize
check_final_provider_logs() {
  write_provider_log_phases
  # Unexpected callback markers and pressure transitions must be checked again
  # over the frozen full log, including Dial9 collection and restoration.
  if tail -n "+$((UDP_ERROR_PROVIDER_LOG_LINE + 1))" "$PROVIDER_LOG" | grep -E \
    'flow_callback_error operation=udp_flow\.(open|read|write)' >/dev/null
  then
    add_failure "provider emitted an unexpected UDP flow error during the live test"
  fi
  check_udp_pressure_logs
}

# shellcheck disable=SC2329  # invoked by the EXIT finalizer's log verdict
check_udp_pressure_logs() {
  local metrics status
  metrics="$(/usr/bin/python3 - "$TMP_DIR/source-soak_pressure_log.py" "$PROVIDER_LOG" \
    "$UNBLOCKED_LOG_LINE" "$PRESSURE_LOG_LINE" "$PRESSURE_END_LOG_LINE" \
    "$BLOCKED_LOG_LINE" "$PRESSURE_FLOW_ID" <<'PY'
import runpy, sys

summarize_udp_pressure_rows = runpy.run_path(sys.argv[1])["summarize_udp_pressure_rows"]

try:
    with open(sys.argv[2], encoding="utf-8") as provider_log:
        lines = provider_log.read().splitlines()
    unblocked_start = int(sys.argv[3])
    pressure_start = int(sys.argv[4])
    pressure_end = int(sys.argv[5])
    blocked_start = int(sys.argv[6])
    pressure_flow_id = int(sys.argv[7])
    if not 0 <= unblocked_start <= blocked_start <= pressure_start <= pressure_end <= len(lines):
        raise ValueError("invalid provider log phase boundaries")
    healthy_segments = (
        lines[unblocked_start:blocked_start],
        lines[blocked_start:pressure_start],
        lines[pressure_end:],
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

capture_producer_sources \
  || fatal_issue "could not capture exact modern evidence producer sources"

case "$(uname -m)" in
  arm64) DIAL9_EVIDENCE_BIN="$ROOT_DIR/tproxy_rs/target/aarch64-apple-darwin/debug/dial9_evidence" ;;
  x86_64) DIAL9_EVIDENCE_BIN="$ROOT_DIR/tproxy_rs/target/x86_64-apple-darwin/debug/dial9_evidence" ;;
  *) DIAL9_EVIDENCE_BIN="" ;;
esac

[[ "$(uname -s)" == Darwin ]] \
  || fatal_issue "modern UDP Network Extension E2E requires macOS"
[[ "$RUN_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || fatal_issue "could not create a canonical signed UDP run UUID"
[[ "$RUN_START_EPOCH_MS" =~ ^[1-9][0-9]*$ ]] \
  || fatal_issue "could not capture the signed UDP wall-clock start"
if [[ ! "$ECHO_SOCKET_COUNT" =~ ^[1-9][0-9]*$ ]] \
  || (( ECHO_SOCKET_COUNT < 128 || ECHO_SOCKET_COUNT > 450 )) \
  || [[ ! "$ECHO_DATAGRAMS_PER_SOCKET" =~ ^[1-9][0-9]*$ ]] \
  || (( ECHO_DATAGRAMS_PER_SOCKET != 64 )) \
  || [[ ! "$ECHO_INTERVAL_MS" =~ ^(0|[1-9][0-9]*)$ ]] \
  || (( ECHO_INTERVAL_MS != 2000 )) \
  || [[ ! "$ECHO_PAYLOAD_BYTES" =~ ^[1-9][0-9]*$ ]] \
  || (( ECHO_PAYLOAD_BYTES < 1200 || ECHO_PAYLOAD_BYTES > 60000 )) \
  || [[ ! "$ECHO_CONCURRENCY" =~ ^[1-9][0-9]*$ ]] \
  || (( ECHO_CONCURRENCY > ECHO_SOCKET_COUNT || ECHO_CONCURRENCY > 128 \
    || ECHO_SOCKET_COUNT > ECHO_CONCURRENCY * 16 \
    || ECHO_SOCKET_COUNT * ECHO_DATAGRAMS_PER_SOCKET * ECHO_PAYLOAD_BYTES > MAX_LOAD_BYTES ))
then
  fatal_issue "controlled echo load configuration is outside its bounded range"
fi
if [[ ! "$HTTP3_CONCURRENCY" =~ ^[1-9][0-9]*$ ]] \
  || (( HTTP3_CONCURRENCY > 16 )) \
  || [[ ! "$HTTP3_ROUNDS" =~ ^[1-9][0-9]*$ ]] \
  || (( HTTP3_ROUNDS < 2 || HTTP3_ROUNDS > 16 )) \
  || [[ ! "$HTTP3_ROUND_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || ! awk -v value="$HTTP3_ROUND_INTERVAL" 'BEGIN { exit !(value >= 0 && value <= 10) }'
then
  fatal_issue "sustained HTTP/3 configuration is outside its bounded range"
fi
if [[ ! "$PRESSURE_COUNT" =~ ^[1-9][0-9]*$ ]] \
  || (( PRESSURE_COUNT < 64 || PRESSURE_COUNT > 100000 )) \
  || [[ ! "$PRESSURE_PAYLOAD_BYTES" =~ ^[1-9][0-9]*$ ]] \
  || (( PRESSURE_PAYLOAD_BYTES < 64 || PRESSURE_PAYLOAD_BYTES > 60000 \
    || PRESSURE_COUNT * PRESSURE_PAYLOAD_BYTES > MAX_LOAD_BYTES )) \
  || [[ ! "$CONCURRENT_LOAD_DEADLINE_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || (( CONCURRENT_LOAD_DEADLINE_SECONDS != 180 ))
then
  fatal_issue "UDP pressure configuration is outside its bounded range"
fi
ECHO_EXPECTED_COUNT=$((ECHO_SOCKET_COUNT * ECHO_DATAGRAMS_PER_SOCKET))
PRESSURE_EXPECTED_BYTES=$((PRESSURE_COUNT * PRESSURE_PAYLOAD_BYTES))
GATE_START_MONOTONIC_MS="$(monotonic_ms_now)"
[[ "$GATE_START_MONOTONIC_MS" =~ ^[1-9][0-9]*$ ]] \
  || fatal_issue "could not capture the signed UDP monotonic gate start"
MACOS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
CALLBACK_GENERATION=modern
if (( MACOS_MAJOR < 15 )); then
  if [[ "${RAMA_TPROXY_ALLOW_LEGACY_UDP_E2E:-0}" != 1 ]]; then
    fatal_issue "modern UDP Network Extension E2E requires macOS 15 or newer"
  fi
  CALLBACK_GENERATION=legacy
  add_issue "legacy UDP callbacks are diagnostic-only and cannot satisfy modern release evidence"
fi
[[ -d "$BUILT_APP" ]] \
  || fatal_issue "signed app not found at $BUILT_APP; build it before running this test"
[[ -d "$BUILT_PROVIDER" ]] \
  || fatal_issue "signed provider not found at $BUILT_PROVIDER; build it before running this test"
command -v nscurl >/dev/null \
  || fatal_issue "nscurl is required for the public HTTP/3 UDP/443 probe"
if [[ -z "$HTTP3_LIBCURL" ]]; then
  for candidate in /opt/homebrew/opt/curl/lib/libcurl.4.dylib /usr/local/opt/curl/lib/libcurl.4.dylib; do
    [[ -f "$candidate" ]] || continue
    HTTP3_LIBCURL="$candidate"
    break
  done
fi
[[ "$HTTP3_LIBCURL" == /* && -f "$HTTP3_LIBCURL" ]] \
  || fatal_issue "intercepted HTTP/3 requires an installed HTTP/3-capable libcurl; set RAMA_TPROXY_E2E_HTTP3_LIBCURL"
printf '%s\n' "$HTTP3_URL" > "$TMP_DIR/http3-url.txt" \
  || fatal_issue "could not capture the configured HTTP/3 URL"
[[ -x "$DIAL9_EVIDENCE_BIN" ]] \
  || fatal_issue "dial9 evidence collector is missing; run just build-tproxy-rs"
sudo -n true 2>/dev/null \
  || fatal_issue "cached sudo credentials are required for root-owned dial9 evidence"

CURRENT_PHASE=echo-server-start
start_owned_command echo-server /usr/bin/python3 "$PROBE" echo-server --bind 127.0.0.1 --port 0 \
  --run-uuid "$RUN_UUID" --expected-count "$ECHO_EXPECTED_COUNT" \
  --max-seconds 600 --ready-file "$ECHO_READY" \
  --result-file "$ECHO_SERVER_RESULT" > "$TMP_DIR/controlled-echo-server.log" 2>&1 \
  || fatal_issue "could not start the owned controlled echo server"
ECHO_SERVER_PID="$OWNED_COMMAND_PID"
for _ in $(seq 1 100); do
  [[ -s "$ECHO_READY" ]] && break
  owned_command_source_is_alive "$ECHO_SERVER_PID" \
    || fatal_issue "controlled echo server exited before readiness"
  sleep 0.05
done
ECHO_ENDPOINT="$(/usr/bin/python3 - "$ECHO_READY" "$RUN_UUID" <<'PY'
import ipaddress, json, sys
value = json.load(open(sys.argv[1]))
if value.get("schema_version") != 2 or value.get("schema_complete") is not True:
    raise SystemExit(2)
if value.get("run_uuid") != sys.argv[2] or not isinstance(value.get("server_pid"), int):
    raise SystemExit(2)
endpoint = value.get("endpoint", "")
host, port = endpoint.rsplit(":", 1)
if host != "127.0.0.1" or not 1 <= int(port) <= 65535:
    raise SystemExit(2)
print(endpoint)
PY
)" || fatal_issue "controlled echo readiness artifact is malformed"

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
DIAGNOSTIC_ENDPOINTS="$(/usr/bin/python3 - "$HTTP3_ENDPOINTS" \
  "$PASSTHROUGH_DNS:53" "$INTERCEPT_NTP:123" "$BLOCKED_DNS:53" "$ECHO_ENDPOINT" <<'PY'
import sys
values = list(sys.argv[2:]) + [line.strip() for line in open(sys.argv[1]) if line.strip()]
if len(set(values)) != len(values) or not 1 <= len(values) <= 512:
    raise SystemExit(2)
print(",".join(values))
PY
)" || fatal_issue "UDP diagnostic endpoints are duplicated or malformed"
printf '%s\n' \
  'label	provider_pid	provider_generation	flow_id	protocol	source_pid	close_reason	min_bytes_in	max_bytes_in	min_bytes_out	max_bytes_out' \
  > "$DIAL9_REQUIREMENTS"

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
start_owned_command log /usr/bin/log stream --level debug --style compact \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"' \
  > "$PROVIDER_LOG" 2>&1 || fatal_issue "could not start the owned provider log stream"
LOG_PID="$OWNED_COMMAND_PID"
sleep 0.5
if owned_command_source_is_alive "$LOG_PID"; then
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
if ! run_bounded 90 "$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=443" \
  "--udp-blocked-endpoints=" \
  "--evidence-run-uuid=$RUN_UUID" \
  "--udp-e2e-diagnostic-endpoints=$DIAGNOSTIC_ENDPOINTS"
then
  fatal_issue "could not install the unblocked UDP E2E profile"
fi
wait_for_connected "$UNBLOCKED_CONTAINER_LINE" \
  || fatal_issue "unblocked UDP E2E profile did not connect"
capture_provider_identity \
  || fatal_issue "unblocked UDP E2E provider identity is unavailable"
capture_common_provider_identity \
  || fatal_issue "unblocked UDP E2E common provider identity is unavailable"
start_provider_generation_monitor \
  || fatal_issue "canonical provider generation monitoring could not start"
RUN_START_EPOCH_MS="$(/usr/bin/python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
[[ "$RUN_START_EPOCH_MS" =~ ^[1-9][0-9]*$ ]] \
  || fatal_issue "could not freeze the signed UDP workload start"

# Ignore teardown/startup errors from the provider instance being replaced.
sleep 1
UNBLOCKED_LOG_LINE="$(provider_log_line)"
UDP_ERROR_PROVIDER_LOG_LINE="$UNBLOCKED_LOG_LINE"

CURRENT_PHASE=unblocked-probes
run_probe "pass-through DNS control" none passthrough dns "$PASSTHROUGH_DNS"
PASSTHROUGH_DNS_SOURCE_PID="$LAST_PROBE_PID"
PASSTHROUGH_DNS_LOG_START="$LAST_PROBE_LOG_START"
PASSTHROUGH_DNS_LOG_END="$LAST_PROBE_LOG_END"
run_probe "intercept NTP control" none ntp ntp "$INTERCEPT_NTP"
NTP_SOURCE_PID="$LAST_PROBE_PID"
NTP_LOG_START="$LAST_PROBE_LOG_START"
NTP_LOG_END="$LAST_PROBE_LOG_END"
run_probe "future blocked DNS control" none control dns "$BLOCKED_DNS"
CONTROL_DNS_SOURCE_PID="$LAST_PROBE_PID"
CONTROL_DNS_LOG_START="$LAST_PROBE_LOG_START"
CONTROL_DNS_LOG_END="$LAST_PROBE_LOG_END"

CURRENT_PHASE=sustained-http3
run_sustained_http3

# Reinstall with one exact public DNS endpoint blocked. A new client socket is
# used below, so this must create a fresh NE flow and decision.
CURRENT_PHASE=blocked-install
BLOCKED_CONTAINER_LINE="$(container_log_line)"
if ! run_bounded 90 "$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=" \
  "--udp-blocked-endpoints=$BLOCKED_DNS:53" \
  "--evidence-run-uuid=$RUN_UUID" \
  "--udp-e2e-diagnostic-endpoints=$DIAGNOSTIC_ENDPOINTS"
then
  fatal_issue "could not install the blocked UDP E2E profile"
fi
wait_for_connected "$BLOCKED_CONTAINER_LINE" \
  || fatal_issue "blocked UDP E2E profile did not connect"
require_provider_identity || true
BLOCKED_LOG_LINE="$(provider_log_line)"

CURRENT_PHASE=blocked-probe
run_probe "blocked DNS probe" 10 blocked dns "$BLOCKED_DNS" \
  --timeout 4 --expect-no-response
BLOCKED_DNS_SOURCE_PID="$LAST_PROBE_PID"
BLOCKED_DNS_LOG_START="$LAST_PROBE_LOG_START"
BLOCKED_DNS_LOG_END="$LAST_PROBE_LOG_END"

# Keep the sustained echo population in the profile that intercepts UDP/443.
CURRENT_PHASE=concurrent-udp-load
PRESSURE_LOG_LINE="$(provider_log_line)"
PRESSURE_PROBE_ATTEMPTED=1
PRESSURE_LOG_START="$PRESSURE_LOG_LINE"
ECHO_LOG_START="$PRESSURE_LOG_LINE"
UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
CONCURRENT_LOAD_DEADLINE=$((SECONDS + CONCURRENT_LOAD_DEADLINE_SECONDS))
start_owned_command echo /usr/bin/python3 "$PROBE" echo-load \
  --server "${ECHO_ENDPOINT%:*}" --port "${ECHO_ENDPOINT##*:}" \
  --run-uuid "$RUN_UUID" --socket-count "$ECHO_SOCKET_COUNT" \
  --datagrams-per-socket "$ECHO_DATAGRAMS_PER_SOCKET" \
  --interval-ms "$ECHO_INTERVAL_MS" \
  --payload-bytes "$ECHO_PAYLOAD_BYTES" --concurrency "$ECHO_CONCURRENCY" \
  --result-file "$ECHO_CLIENT_RESULT" > "$TMP_DIR/controlled-echo-client.log" 2>&1 \
  || fatal_issue "could not start the owned controlled echo client"
ECHO_SOURCE_PID="$OWNED_COMMAND_SOURCE_PID"
ACTIVE_ECHO_PID="$OWNED_COMMAND_PID"
start_owned_command pressure /usr/bin/python3 "$PROBE" pressure --server "$INTERCEPT_NTP" \
  --count "$PRESSURE_COUNT" --payload-bytes "$PRESSURE_PAYLOAD_BYTES" --settle 4 \
  || fatal_issue "could not start the owned UDP pressure client"
PRESSURE_SOURCE_PID="$OWNED_COMMAND_SOURCE_PID"
ACTIVE_PRESSURE_PID="$OWNED_COMMAND_PID"
UDP_PROBE_ATTEMPT_COUNT=$((UDP_PROBE_ATTEMPT_COUNT + 1))
if wait_for_child_until "$ACTIVE_PRESSURE_PID" "$CONCURRENT_LOAD_DEADLINE"
then
  PRESSURE_PROBE_PASSED=1
  UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1))
else
  add_issue "deliberate UDP pressure burst did not complete"
fi
(( OWNED_JOIN_REAPED == 0 )) || ACTIVE_PRESSURE_PID=""
ECHO_CLIENT_RC=0
wait_for_child_until "$ACTIVE_ECHO_PID" "$CONCURRENT_LOAD_DEADLINE" || ECHO_CLIENT_RC=$?
(( OWNED_JOIN_REAPED == 0 )) || ACTIVE_ECHO_PID=""
ECHO_SERVER_RC=0
wait_for_child_until "$ECHO_SERVER_PID" "$CONCURRENT_LOAD_DEADLINE" || ECHO_SERVER_RC=$?
(( OWNED_JOIN_REAPED == 0 )) || ECHO_SERVER_PID=""
ECHO_METRICS="$(/usr/bin/python3 - "$ECHO_CLIENT_RESULT" "$ECHO_SERVER_RESULT" \
  "$RUN_UUID" "$ECHO_ENDPOINT" "$ECHO_EXPECTED_COUNT" \
  "$ECHO_SOCKET_COUNT" "$ECHO_DATAGRAMS_PER_SOCKET" "$ECHO_PAYLOAD_BYTES" \
  "$MODERN_EVIDENCE" "$RUN_START_EPOCH_MS" "$CONCURRENT_LOAD_DEADLINE_SECONDS" <<'PY'
import hashlib, ipaddress, json, re, runpy, sys, time
sys.dont_write_bytecode = True
validators = runpy.run_path(sys.argv[9])
client, server = (json.load(open(path)) for path in sys.argv[1:3])
run_uuid, endpoint, expected = sys.argv[3], sys.argv[4], int(sys.argv[5])
socket_count, per_socket, payload_bytes = map(int, sys.argv[6:9])
for value, kind in ((client, "controlled_echo_client"), (server, "controlled_echo_server")):
    if value.get("schema_version") != 2 or value.get("schema_complete") is not True:
        raise SystemExit(2)
    if value.get("kind") != kind or value.get("run_uuid") != run_uuid:
        raise SystemExit(2)
    if value.get("endpoint") != endpoint or value.get("passed") is not True:
        raise SystemExit(2)
if client.get("expected_count") != expected or server.get("expected_count") != expected:
    raise SystemExit(2)
if any(client.get(key) != expected for key in (
    "sent_count", "received_count", "exact_echo_count", "unique_echo_count",
)) or server.get("received_count") != expected or server.get("echo_count") != expected:
    raise SystemExit(2)
if (client.get("socket_count") != socket_count
        or client.get("independent_socket_count") != socket_count
        or client.get("datagrams_per_socket") != per_socket
        or client.get("payload_bytes") != payload_bytes):
    raise SystemExit(2)
if (server.get("duplicate_count") != 0 or server.get("malformed_count") != 0
        or client.get("error_count") != 0):
    raise SystemExit(2)
if re.fullmatch(r"[0-9a-f]{64}", client.get("local_endpoint_set_sha256", "")) is None:
    raise SystemExit(2)
local_endpoints = client.get("local_endpoints")
if not isinstance(local_endpoints, list) or len(set(local_endpoints)) != socket_count:
    raise SystemExit(2)
for endpoint_value in local_endpoints:
    host, port = (endpoint_value[1:].split("]:", 1)
                  if endpoint_value.startswith("[") else endpoint_value.rsplit(":", 1))
    if str(ipaddress.ip_address(host)) != host or not 1 <= int(port) <= 65535:
        raise SystemExit(2)
local_digest = hashlib.sha256("\n".join(sorted(local_endpoints)).encode()).hexdigest()
if local_digest != client["local_endpoint_set_sha256"]:
    raise SystemExit(2)
validators["validate_echo_socket_maps"](client, server, socket_count)
validators["_validate_echo_timing"](client, {
    "run_start_epoch_ms": sys.argv[10],
    "run_end_epoch_ms": str(time.time_ns() // 1_000_000),
    "concurrent_load_deadline_seconds": sys.argv[11],
}, socket_count, per_socket, require_active_population=True)
digest = client.get("payload_set_sha256")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit(2)
if client.get("echo_set_sha256") != digest or server.get("payload_set_sha256") != digest:
    raise SystemExit(2)
print(expected, digest)
PY
)" || ECHO_METRICS=""
if (( ECHO_CLIENT_RC == 0 && ECHO_SERVER_RC == 0 )) \
  && [[ "$ECHO_METRICS" =~ ^[0-9]+\ [0-9a-f]{64}$ ]]
then
  read -r ECHO_EXACT_ECHO_COUNT ECHO_PAYLOAD_SET_SHA256 <<< "$ECHO_METRICS"
  UDP_PROBE_PASS_COUNT=$((UDP_PROBE_PASS_COUNT + 1))
else
  add_issue "controlled QUIC-shaped UDP echo load lacked exact payload/cardinality evidence"
fi
close_pressure_probe_window "$PRESSURE_LOG_START" "$PRESSURE_SOURCE_PID" \
  "$INTERCEPT_NTP:123" com.apple.python3 || true
PRESSURE_END_LOG_LINE="$LAST_PROBE_LOG_END"
close_probe_decision_window "$ECHO_LOG_START" "$ECHO_SOURCE_PID" "$ECHO_SOCKET_COUNT"
ECHO_LOG_END="$LAST_PROBE_LOG_END"

CURRENT_PHASE=pressure-recovery-canary
run_probe "post-pressure NTP recovery canary" none recovery ntp "$INTERCEPT_NTP"
RECOVERY_NTP_SOURCE_PID="$LAST_PROBE_PID"
RECOVERY_NTP_LOG_START="$LAST_PROBE_LOG_START"
RECOVERY_NTP_LOG_END="$LAST_PROBE_LOG_END"

CURRENT_PHASE=intercepted-http3
run_intercepted_http3 || true

# Let os_log and the Rust tracing bridge flush the per-flow decision/service
# records before assertions.
sleep 2
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
check_exact_decision "$BLOCKED_DNS_LOG_START" "$BLOCKED_DNS_LOG_END" blocked \
  "$BLOCKED_DNS:53" com.apple.python3 "$BLOCKED_DNS_SOURCE_PID" \
  "Rust blocked decision for an exact public DNS endpoint" blocked
check_exact_decision "$PRESSURE_LOG_START" "$PRESSURE_END_LOG_LINE" intercept \
  "$INTERCEPT_NTP:123" com.apple.python3 "$PRESSURE_SOURCE_PID" \
  "Rust intercept decision for the deliberate pressure flow" pressure
check_exact_decision "$RECOVERY_NTP_LOG_START" "$RECOVERY_NTP_LOG_END" intercept \
  "$INTERCEPT_NTP:123" com.apple.python3 "$RECOVERY_NTP_SOURCE_PID" \
  "Rust post-pressure NTP recovery decision" recovery


check_echo_decisions || true
check_http3_decisions || true
check_http3_intercept_decision || true
if [[ "$UNBLOCKED_PROVIDER_GENERATION" =~ ^[1-9][0-9]*$ \
  && "$BLOCKED_PROVIDER_GENERATION" =~ ^[1-9][0-9]*$ \
  && "$UNBLOCKED_PROVIDER_GENERATION" != "$BLOCKED_PROVIDER_GENERATION" ]]
then
  ENGINE_GENERATIONS_SHA256="$(printf '%s' \
    "$PROVIDER_PID:$UNBLOCKED_PROVIDER_GENERATION:$BLOCKED_PROVIDER_GENERATION" \
    | shasum -a 256 | awk 'NR == 1 { print $1 }')"
else
  add_issue "signed UDP E2E did not observe two exact provider generations"
fi

require_provider_identity || true

MAIN_FINISHED=1
CURRENT_PHASE=finalize
echo "$CALLBACK_GENERATION UDP Network Extension E2E probes completed; finalizing evidence"
echo "pass-through DNS=$PASSTHROUGH_DNS:53 intercept NTP=$INTERCEPT_NTP:123 blocked DNS=$BLOCKED_DNS:53 UDP/443=$HTTP3_URL"
exit 0
