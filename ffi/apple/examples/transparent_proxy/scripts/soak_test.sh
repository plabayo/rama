#!/usr/bin/env bash
# soak_test.sh — one comprehensive live session for the rama Apple NE
# transparent proxy. Drives a battery of phases back-to-back and bundles
# everything that tells us whether the lifetime / leak / wake / flow-pressure
# fixes hold, into a single artifact dir (+ tarball) to hand back.
#
# It AUTO-DETECTS the running build's flow-pressure soft cap from the gauge
# log line ("… softCap=N") and adapts safely:
#   softCap > MAX_SAFE_FLOWS → CAP-TOO-HIGH-TO-CROSS: the cap cannot be reached
#       without nearing the (~600) kernel nexus ceiling, which would risk the
#       very machine freeze the cap prevents. The session runs at a SAFE
#       concurrency (under the cap) and validates leak/freeze/wake/keepalive
#       only; it tells you to use a LOW-CAP build to validate eviction.
#   0 < softCap ≤ MAX_SAFE_FLOWS → CAP-VALIDATE: safe to reach the (low) cap;
#       drive occupancy to/above it and prove the reaper invariants hold.
#   softCap == 0 → (only with FIND_CEILING=1) CEILING-FINDER: carefully ramp
#       until the nexus allocation is exhausted, report the gauge peak, back off.
#
# To VALIDATE the pressure reaper on-device, configure the Rust builder in
# tproxy_rs/src/lib.rs before installing the app:
#   .with_flow_pressure_soft_cap(80)
#   .with_flow_pressure_low_water(60)
#   .with_flow_pressure_idle_floor_ms(10_000)
# Keep the live-flow hard cap enabled. Ceiling-finder runs additionally require
# `.with_live_flow_hard_cap(0)` and are intentionally unsafe.
#
# Phases (default giant session):
#   0  baseline      detect softCap + baseline flow count + mem
#   1  stress        the mixed stress_traffic.sh burst (connect/relay churn)
#   2  fanout        sustained pool of ACTIVE (slow-drip) flows
#                    (→ peak, admit-and-ride, active-not-evicted)
#   3  idle-holders  sustained pool of SILENT (no-data) flows
#                    (→ idle-eviction reaper, on a short-floor build)
#   4  real-download steady transfer
#   5  sleep/wake    the original wake-bug scenario (TTY only)
#   6  idle-tail     quiesce so the gauge can settle back toward baseline
#   then: final mem snapshot, leaks pass, dial9 traces, signal extraction.
#
# What it captures (in OUT/):
#   system.ndjson        full debug-level os_log stream for the sysext
#   flow-counts.txt      the 60s "live-flow counts" gauge timeline
#   phases.tsv           wall-clock start/end of every phase (epoch + iso)
#   run-meta.tsv         softCap, mode, baseline flow count
#   timeline.txt         lifecycle / sleep / wake / reaper / relay / error lines
#   extract-summary.txt  peak vs cap, reaper tallies (keyed on the human log
#                        lines that actually reach os_log), body-relay errors,
#                        freeze verdict, per-phase gauge, baseline-relative leak
#   stress/              per-worker logs + preflight/postflight vmmap+heap
#   fanout.txt           per-worker outcomes of the active pool
#   holders.log          flow-pool live/gauge timeline
#   probe-timeline.txt    paired periodic liveness probes (start/end/rc/status)
#   pool-intervals.tsv    sustained explicitly-established flow-pool intervals
#   pool-brackets.tsv     provider-PID baseline/peak/post-kill gauge proof
#   holder-markers/       per-worker header/connected establishment proof
#   final-mem.txt        ps/vmmap/heap AFTER the idle tail
#   leaks.txt            `leaks` pass on the live sysext
#   dial9-traces/        per-flow egress dial traces
#
# Usage (run from anywhere):
#   bash scripts/soak_test.sh
#   FIND_CEILING=1 bash scripts/soak_test.sh      # only when both caps are 0!
#
# Requires: the dev proxy already enabled in the container app (or DO_INSTALL=1
# to build+install+open it first), and sudo.
#
# Env knobs (all optional):
#   REPO            repo root. Default: /Users/glendc/code/github.com/plabayo/rama
#   OUT             artifact dir. Default: ~/rama-tproxy-soak/<timestamp>
#   DO_INSTALL      1 = `just install-tproxy-dev` first. Default 0.
#   STRESS_SECONDS  phase-1 stress duration (0..86400; positive unless skipped). Default 180.
#   CONCURRENCY     phase-1 stress pool size (1..512). Default 24.
#   DL_HOST         download/holder host (rama http-test). Default http-test.ramaproxy.org.
#   FANOUT_TARGET   phase-2 concurrent active flows. Default auto
#                   (min(softCap+25%, MAX_SAFE_FLOWS), floored at 40, then
#                   bounded by enabled hard-cap headroom from the baseline).
#   FANOUT_HOLD     phase-2 sustain seconds. Default 90.
#   MAX_SAFE_FLOWS  max concurrency the AUTO target will request (1..1024), to stay well
#                   under the ~600 nexus ceiling. Default 300.
#   ALLOW_UNSAFE_LOAD 1 = let an explicit FANOUT_TARGET/IDLE_TARGET exceed
#                   MAX_SAFE_FLOWS (freeze risk!). Effective hard-cap headroom
#                   remains mandatory. Default 0.
#   IDLE_TARGET     phase-3 concurrent silent holders. Default = FANOUT_TARGET.
#   IDLE_HOLD       phase-3 sustain seconds. Default 150.
#   SKIP_STRESS / SKIP_FANOUT / SKIP_IDLE   1 = skip that phase. Default 0.
#   SKIP_SLEEP      1 = skip sleep/wake. Default 0.
#   IDLE_TAIL       trailing quiesce seconds (≥2 gauge ticks). Default 135.
#   FIND_CEILING    1 = ceiling-finder (DANGEROUS; softCap=0/hardCap=0 only). Default 0.
#   CEIL_STEP / CEIL_SETTLE   ceiling-finder ramp step / settle. Default 40 / 8.
#   ASSUME_YES      1 = skip the ceiling-finder confirmation. Default 0.

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────
REPO="${REPO:-/Users/glendc/code/github.com/plabayo/rama}"
EXAMPLE_DIR="$REPO/ffi/apple/examples/transparent_proxy"
STRESS_SH="$EXAMPLE_DIR/scripts/stress_traffic.sh"
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"
HTTPS_PROBE="https://http-test.ramaproxy.org/method"
DL_HOST="${DL_HOST:-http-test.ramaproxy.org}"
DL_MAX_BYTES=$(( 32 * 1024 * 1024 ))   # http-test /bytes server cap (MAX_BYTES)
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$HOME/rama-tproxy-soak/$STAMP}"
DO_INSTALL="${DO_INSTALL-0}"
STRESS_SECONDS="${STRESS_SECONDS-180}"
CONCURRENCY="${CONCURRENCY-24}"
FANOUT_TARGET="${FANOUT_TARGET-0}"      # 0 = auto from softCap
FANOUT_HOLD="${FANOUT_HOLD-90}"
MAX_SAFE_FLOWS="${MAX_SAFE_FLOWS-300}"
ALLOW_UNSAFE_LOAD="${ALLOW_UNSAFE_LOAD-0}"
IDLE_TARGET="${IDLE_TARGET-0}"          # 0 = auto (= FANOUT_TARGET)
IDLE_HOLD="${IDLE_HOLD-150}"
SKIP_STRESS="${SKIP_STRESS-0}"
SKIP_FANOUT="${SKIP_FANOUT-0}"
SKIP_IDLE="${SKIP_IDLE-0}"
SKIP_SLEEP="${SKIP_SLEEP-0}"
IDLE_TAIL="${IDLE_TAIL-135}"
FIND_CEILING="${FIND_CEILING-0}"
CEIL_STEP="${CEIL_STEP-40}"
CEIL_SETTLE="${CEIL_SETTLE-8}"
ASSUME_YES="${ASSUME_YES-0}"

LOGBUF=""; command -v stdbuf >/dev/null 2>&1 && LOGBUF="stdbuf -oL"
PYTHON_BIN="$(command -v python3 || true)"

# ── Pretty output ─────────────────────────────────────────────────────
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YEL=$'\e[33m'
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YEL=""
fi
say()  { printf '%s[soak]%s %s\n' "$DIM" "$RESET" "$*"; }
hdr()  { printf '\n%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$*" "$RESET"; }
warn() { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$YEL" "$*" "$RESET" >&2; }
die()  { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$RED" "$*" "$RESET" >&2; exit 2; }

write_incomplete_status() {
  local reason="$1" tmp="$OUT/.evidence-status.$$"
  {
    printf 'complete\t0\npassed\t0\nexit_code\t2\n'
    printf 'issue\t%s\n' "$reason"
    printf 'schema_complete\t1\n'
  } > "$tmp" && mv -f "$tmp" "$OUT/evidence-status.tsv"
}

# Reject ambiguous or oversized environment values before they enter Bash
# arithmetic. Leading-zero values are intentionally rejected because Bash
# interprets them as octal; oversized integers otherwise wrap silently.
require_bounded_uint() {
  local name="$1" value="$2" maximum="$3"
  local LC_ALL=C
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die "$name must be a canonical non-negative decimal integer (got '$value')"
  if [[ ${#value} -gt ${#maximum} ]] \
    || [[ ${#value} -eq ${#maximum} && "$value" > "$maximum" ]]
  then
    die "$name must be at most $maximum (got '$value')"
  fi
}

require_boolean() {
  local name="$1" value="$2"
  [[ "$value" == 0 || "$value" == 1 ]] \
    || die "$name must be 0 or 1 (got '$value')"
}

# Return success when the enabled hard cap cannot accommodate the registered
# growth needed to reach the soft trigger from this baseline. The hard cap
# counts allocated resources (including retiring ones); the soft trigger counts
# only registered TCP+UDP flows.
cap_validation_hard_limited() {
  local soft="$1" hard="$2" registered="$3" allocated="$4"
  local soft_headroom=0 hard_headroom=0
  (( hard > 0 )) || return 1
  (( hard < soft )) && return 0
  (( soft > registered )) && soft_headroom=$(( soft - registered ))
  (( hard > allocated )) && hard_headroom=$(( hard - allocated ))
  (( hard_headroom < soft_headroom ))
}

# Compute the provider rise/fall that can be attributed to one worker pool.
# The soft cap is registered-flow headroom; an enabled hard cap additionally
# bounds it by allocated headroom so retiring resources cannot be counted as
# workers or silently exceeded.
flow_pool_expected_contribution() {
  local target="$1" soft="$2" hard="$3" registered="$4" allocated="$5"
  local contribution="$target" hard_headroom=0
  if (( soft > 0 && hard > 0 && hard < soft )); then
    contribution=0
  elif (( soft > 0 )); then
    (( soft - registered < contribution )) \
      && contribution=$(( soft - registered ))
    if (( hard > 0 )); then
      (( hard > allocated )) && hard_headroom=$(( hard - allocated ))
      (( hard_headroom < contribution )) && contribution="$hard_headroom"
    fi
  elif (( hard > 0 )); then
    (( hard - allocated < contribution )) \
      && contribution=$(( hard - allocated ))
  fi
  (( contribution < 0 )) && contribution=0
  printf '%s\n' "$contribution"
}

require_bounded_uint STRESS_SECONDS "$STRESS_SECONDS" 86400
require_bounded_uint CONCURRENCY "$CONCURRENCY" 512
require_bounded_uint FANOUT_TARGET "$FANOUT_TARGET" 1024
require_bounded_uint FANOUT_HOLD "$FANOUT_HOLD" 86400
require_bounded_uint MAX_SAFE_FLOWS "$MAX_SAFE_FLOWS" 1024
require_bounded_uint IDLE_TARGET "$IDLE_TARGET" 1024
require_bounded_uint IDLE_HOLD "$IDLE_HOLD" 86400
require_bounded_uint IDLE_TAIL "$IDLE_TAIL" 86400
require_bounded_uint CEIL_STEP "$CEIL_STEP" 512
require_bounded_uint CEIL_SETTLE "$CEIL_SETTLE" 3600

for _n in DO_INSTALL ALLOW_UNSAFE_LOAD SKIP_STRESS SKIP_FANOUT SKIP_IDLE \
          SKIP_SLEEP FIND_CEILING ASSUME_YES; do
  require_boolean "$_n" "${!_n}"
done

[[ "$CEIL_STEP" != 0 ]] || die "CEIL_STEP must be greater than zero"
[[ "$CONCURRENCY" != 0 ]] || die "CONCURRENCY must be greater than zero"
[[ "$MAX_SAFE_FLOWS" != 0 ]] || die "MAX_SAFE_FLOWS must be greater than zero"
[[ "$SKIP_STRESS" == 1 || "$STRESS_SECONDS" != 0 ]] \
  || die "STRESS_SECONDS must be greater than zero when the stress phase is enabled"

sha256_path() {
  local path="$1" digest
  digest="$(shasum -a 256 -- "$path" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    digest="$(sudo -n shasum -a 256 -- "$path" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  fi
  printf '%s\n' "${digest:-unavailable}"
}

process_identity() {
  local pid="$1" snapshot digest
  snapshot="$(ps -ww -o pid= -o lstart= -o command= -p "$pid" 2>/dev/null)"
  [[ -n "$snapshot" ]] || return 1
  digest="$(printf '%s' "$snapshot" | shasum -a 256 | awk 'NR == 1 { print $1 }')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

# ── Teardown ──────────────────────────────────────────────────────────
LOG_STREAM_STARTED=0
LOG_STREAM_PID=""
SUDO_KEEPALIVE_PID=""
PROBE_MON_PID=""
HOLDER_PIDFILE=""
FLOW_POOL_ATTAINED=0
FLOW_POOL_MAX_LIVE=0
FLOW_POOL_MAX_ESTABLISHED=0
HOLDER_SEQUENCE=0
FLOW_POOL_LABEL=""
HOLDER_CLEANUP_OK=1
CURRENT_PHASE_START=""
WAKE_DL_PID=""
CLEANUP_STARTED=0
ACTIVE_CHILD_PID=""
kill_holders() {
  # PID ownership is the only cleanup authority: never pattern-kill unrelated
  # user traffic. Signal the complete batch first, then join it under one
  # shared deadline so cleanup remains bounded even with hundreds of holders.
  [[ -n "$HOLDER_PIDFILE" && -f "$HOLDER_PIDFILE" ]] || return 0
  local holder_pids=() _p _marker deadline force_deadline active
  local forced=0 reaped=0 unreaped=0
  while IFS=$'\t' read -r _p _marker; do
    [[ "$_p" =~ ^[1-9][0-9]*$ ]] && holder_pids+=("$_p")
  done < "$HOLDER_PIDFILE"
  (( ${#holder_pids[@]} > 0 )) || return 0
  for _p in "${holder_pids[@]}"; do
    child_job_is_active "$_p" && signal_child "$_p" TERM direct
  done
  deadline=$(( SECONDS + 5 ))
  while (( SECONDS < deadline )); do
    active=0
    for _p in "${holder_pids[@]}"; do
      child_job_is_active "$_p" && { active=1; break; }
    done
    (( active )) || break
    sleep 0.1
  done
  for _p in "${holder_pids[@]}"; do
    if child_job_is_active "$_p"; then
      forced=$((forced + 1))
      signal_child "$_p" KILL direct
    fi
  done
  force_deadline=$(( SECONDS + 2 ))
  while (( SECONDS < force_deadline )); do
    active=0
    for _p in "${holder_pids[@]}"; do
      child_job_is_active "$_p" && { active=1; break; }
    done
    (( active )) || break
    sleep 0.1
  done
  for _p in "${holder_pids[@]}"; do
    if child_job_is_active "$_p"; then
      unreaped=$((unreaped + 1))
      continue
    fi
    wait "$_p" 2>/dev/null || true
    reaped=$((reaped + 1))
  done
  : > "$HOLDER_PIDFILE"
  (( unreaped == 0 )) || HOLDER_CLEANUP_OK=0
  printf '%s\ttotal=%s\treaped=%s\tforced=%s\tunreaped=%s\n' \
    "${FLOW_POOL_LABEL:-unknown}" "${#holder_pids[@]}" "$reaped" \
    "$forced" "$unreaped" >> "$OUT/holder-cleanup.tsv"
}
# shellcheck disable=SC2329  # invoked by the EXIT/INT/TERM handlers
cleanup() {
  (( CLEANUP_STARTED == 0 )) || return 0
  CLEANUP_STARTED=1
  if [[ -n "$ACTIVE_CHILD_PID" ]]; then
    bounded_stop_and_join "$ACTIVE_CHILD_PID" 5 root-only
    ACTIVE_CHILD_PID=""
  fi
  if [[ -n "$PROBE_MON_PID" ]]; then
    bounded_stop_and_join "$PROBE_MON_PID" 5 direct
    PROBE_MON_PID=""
  fi
  if [[ -n "$WAKE_DL_PID" ]]; then
    bounded_stop_and_join "$WAKE_DL_PID" 5 direct
    WAKE_DL_PID=""
  fi
  kill_holders
  if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
    bounded_stop_and_join "$SUDO_KEEPALIVE_PID" 5 direct
    SUDO_KEEPALIVE_PID=""
  fi
  if (( LOG_STREAM_STARTED )) && [[ -n "$LOG_STREAM_PID" ]]; then
    bounded_stop_and_join "$LOG_STREAM_PID" 5 sudo
    LOG_STREAM_PID=""
    LOG_STREAM_STARTED=0
  fi
}

# Bash 3.2 on macOS has no timed `wait`. Poll the shell's job table, escalate
# TERM to KILL after a bounded interval, and call `wait` only after the job is no
# longer active. The caller treats anything except a clean exit or TERM as
# incomplete evidence.
child_job_is_active() {
  jobs -p | grep -Fqx -- "$1"
}

signal_child() {
  local pid="$1" signal="$2" privilege="$3"
  local child
  if [[ "$privilege" != root-only ]]; then
    while IFS= read -r child; do
      [[ "$child" =~ ^[1-9][0-9]*$ ]] || continue
      signal_child "$child" "$signal" "$privilege"
    done < <(pgrep -P "$pid" 2>/dev/null || true)
  fi
  if [[ "$privilege" == sudo ]]; then
    sudo -n kill "-$signal" "$pid" 2>/dev/null || true
  else
    kill "-$signal" "$pid" 2>/dev/null || true
  fi
}

# BOUNDED_CHILD_OK is also consumed by the function-level regression harness.
# shellcheck disable=SC2034
BOUNDED_CHILD_RC=missing
BOUNDED_CHILD_OK=0
BOUNDED_CHILD_REAPED=0
BOUNDED_CHILD_FORCED=0
bounded_stop_and_join() {
  local pid="$1" timeout="$2" privilege="$3"
  local deadline force_deadline child_rc
  BOUNDED_CHILD_RC=missing
  BOUNDED_CHILD_OK=0
  BOUNDED_CHILD_REAPED=0
  BOUNDED_CHILD_FORCED=0
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
  if child_job_is_active "$pid"; then
    signal_child "$pid" TERM "$privilege"
  fi
  deadline=$(( SECONDS + timeout ))
  while child_job_is_active "$pid" && (( SECONDS < deadline )); do
    sleep 0.1
  done
  if child_job_is_active "$pid"; then
    BOUNDED_CHILD_FORCED=1
    if [[ "$privilege" == root-only ]]; then
      signal_child "$pid" KILL direct
    else
      signal_child "$pid" KILL "$privilege"
    fi
    force_deadline=$(( SECONDS + 2 ))
    while child_job_is_active "$pid" && (( SECONDS < force_deadline )); do
      sleep 0.1
    done
  fi
  child_job_is_active "$pid" && return 0
  if wait "$pid" 2>/dev/null; then
    child_rc=0
  else
    child_rc=$?
  fi
  BOUNDED_CHILD_RC="$child_rc"
  BOUNDED_CHILD_REAPED=1
  if (( ! BOUNDED_CHILD_FORCED )) && [[ "$child_rc" == 0 || "$child_rc" == 143 ]]; then
    # shellcheck disable=SC2034  # asserted by the function-level regression harness
    BOUNDED_CHILD_OK=1
  fi
}

# shellcheck disable=SC2329  # invoked through trap
handle_signal() {
  local exit_code="$1"
  trap - EXIT INT TERM
  cleanup
  exit "$exit_code"
}

# shellcheck disable=SC2329  # invoked through trap
handle_exit() {
  local exit_code=$?
  trap - EXIT INT TERM
  cleanup
  exit "$exit_code"
}

# ── Helpers ───────────────────────────────────────────────────────────
trap handle_exit EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

# Output: start_epoch<TAB>completion_epoch<TAB>curl_rc<TAB>http_code.
probe_record() {
  local started completed code curl_rc=0
  started="$(epoch_now)"
  code="$(curl -sS -o /dev/null --max-time 12 -w '%{http_code}' "$HTTPS_PROBE" 2>/dev/null)" \
    || curl_rc=$?
  completed="$(epoch_now)"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  printf '%s\t%s\t%s\t%s\n' "$started" "$completed" "$curl_rc" "$code"
}
probe_once() {
  local record started completed curl_rc code
  record="$(probe_record)"
  IFS=$'\t' read -r started completed curl_rc code <<< "$record"
  if (( curl_rc == 0 )); then
    printf '%s\n' "$code"
  else
    printf 'curl-exit-%s-http-%s\n' "$curl_rc" "$code"
  fi
}

real_download_matches() {
  local curl_rc="$1" code="$2" downloaded="$3" expected="$4"
  local speed="$5" elapsed="$6"
  (( curl_rc == 0 )) \
    && [[ "$code" =~ ^2[0-9][0-9]$ ]] \
    && [[ "$downloaded" =~ ^(0|[1-9][0-9]*)$ ]] \
    && [[ "$downloaded" == "$expected" ]] \
    && [[ "$speed" =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] \
    && [[ ! "$speed" =~ ^0(\.0+)?$ ]] \
    && [[ "$elapsed" =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] \
    && [[ ! "$elapsed" =~ ^0(\.0+)?$ ]]
}

ceiling_transport_candidate() {
  local curl_rc="$1" code="$2"
  [[ "$code" == 000 ]] || return 1
  case "$curl_rc" in
    28|52|55|56) return 0 ;;
    *) return 1 ;;
  esac
}
probe_ok() { [[ "$(probe_once)" =~ ^2 ]]; }

epoch_now() {
  if [[ -n "$PYTHON_BIN" ]]; then
    "$PYTHON_BIN" -c 'import time; print(f"{time.time():.6f}")'
  else
    printf '%s.000000\n' "$(date +%s)"
  fi
}

# Render the exact whole second represented by an epoch captured above. Keeping
# the epoch and its display timestamp on one clock read prevents a second-boundary
# rollover from making an otherwise valid phase/probe row self-contradictory.
iso_for_epoch() {
  local epoch="$1" whole_seconds="${1%%.*}"
  if [[ -n "$PYTHON_BIN" ]]; then
    "$PYTHON_BIN" - "$epoch" <<'PY'
from datetime import datetime, timezone
from decimal import Decimal
import sys

seconds = int(Decimal(sys.argv[1]))
print(datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
  elif date -u -r "$whole_seconds" +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
    date -u -r "$whole_seconds" +%Y-%m-%dT%H:%M:%SZ
  else
    date -u -d "@$whole_seconds" +%Y-%m-%dT%H:%M:%SZ
  fi
}

gauge_is_fresh() {
  awk -v gauge="$1" -v probe="$2" -v phase_start="$3" \
    'BEGIN { exit !(gauge >= phase_start && gauge <= probe && probe - gauge <= 70) }'
}

# Build a rama /bytes URL that streams `size` bytes in `chunk` pieces with
# `delay_ms` between chunks (server-side drip). size clamped to the 32 MiB cap,
# delay to the 60s server cap.
dl_url() {
  local size="$1" chunk="${2:-16384}" delay="${3:-0}"
  (( size > DL_MAX_BYTES )) && size=$DL_MAX_BYTES
  (( delay > 60000 )) && delay=60000
  printf 'https://%s/bytes?size=%s&chunk=%s&delay_ms=%s' "$DL_HOST" "$size" "$chunk" "$delay"
}

phase_mark() {
  local epoch iso
  epoch="$(epoch_now)"
  iso="$(iso_for_epoch "$epoch")"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$epoch" "$iso" >> "$OUT/phases.tsv"
  [[ "$2" == "start" ]] && CURRENT_PHASE_START="$epoch"
}

# Latest target-provider gauge sample →
# "epoch softcap hardcap tcp udp registered allocated" (or empty). `registered`
# is the registry population used by the pressure soft cap; `allocated` also
# includes retiring kernel resources and is the live hard-cap population.
read_gauge() {
  if [[ -n "$PYTHON_BIN" ]]; then
    "$PYTHON_BIN" - "$OUT/system.ndjson" "$PID" "$PROVIDER_BUNDLE" \
      "$EXAMPLE_DIR/scripts" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[4])
from soak_pressure_log import flow_gauge, parse_oslog_timestamp
latest = None
try:
    with open(sys.argv[1], errors="replace") as source:
        for raw in source:
            try:
                row = json.loads(raw)
                if row.get("processID") != int(sys.argv[2]):
                    continue
                if row.get("subsystem") != sys.argv[3]:
                    continue
                gauge = flow_gauge(row.get("eventMessage", ""))
                epoch = parse_oslog_timestamp(row.get("timestamp"))
                if not gauge or epoch is None or gauge["hard_cap"] is None:
                    continue
                latest = (
                    f"{epoch:.6f} {gauge['soft_cap']} {gauge['hard_cap']} "
                    f"{gauge['tcp']} {gauge['udp']} "
                    f"{gauge['registered']} {gauge['allocated']}"
                )
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
except FileNotFoundError:
    pass
if latest:
    print(latest)
PY
  fi
}
wait_for_fresh_gauge() {
  local not_before="$1" timeout="$2" deadline g gauge_epoch observed_now
  deadline=$(( SECONDS + timeout ))
  while (( SECONDS < deadline )); do
    g="$(read_gauge)"
    if [[ -n "$g" ]]; then
      gauge_epoch="${g%% *}"
      observed_now="$(epoch_now)"
      if gauge_is_fresh "$gauge_epoch" "$observed_now" "$not_before"; then
        printf '%s\n' "$g"
        return 0
      fi
    fi
    sleep 2
  done
  echo ""
}

start_probe_monitor() {
  ( while true; do
      _provider_identity="$(process_identity "$PID" || true)"
      printf '%s\t%s\n' "$(epoch_now)" "${_provider_identity:-gone}" \
        >> "$OUT/provider-timeline.tsv"
      [[ "$_provider_identity" == "$PROVIDER_START_IDENTITY" ]] || exit 42
      _record="$(probe_record)"
      IFS=$'\t' read -r _started _completed _curl_rc _code <<< "$_record"
      printf '%s\t%s\t%s\t%s\t%s\n' "$_started" "$_completed" \
        "$(iso_for_epoch "$_completed")" "$_curl_rc" "$_code" >> "$OUT/probe-timeline.txt"
      _provider_identity="$(process_identity "$PID" || true)"
      printf '%s\t%s\n' "$(epoch_now)" "${_provider_identity:-gone}" \
        >> "$OUT/provider-timeline.tsv"
      [[ "$_provider_identity" == "$PROVIDER_START_IDENTITY" ]] || exit 42
      sleep 5
    done ) &
  PROBE_MON_PID=$!
}

# Count live and explicitly established workers, rewriting to survivors only.
recount_holders() {
  local live=0 established=0 tmp="$OUT/.pids.tmp" p marker; : > "$tmp"
  while IFS=$'\t' read -r p marker; do
    if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
      printf '%s\t%s\n' "$p" "$marker" >> "$tmp"
      live=$((live+1))
      holder_marker_established "$marker" && established=$((established+1))
    fi
  done < "$HOLDER_PIDFILE"
  mv "$tmp" "$HOLDER_PIDFILE"
  echo "$live $established"
}

# Active holders are established only after the origin has produced an HTTP 2xx
# response. A nonempty 4xx/5xx header file is not successful flow evidence.
holder_marker_established() {
  local marker="$1"
  if [[ "$marker" == *.active.headers ]]; then
    awk '
      /^HTTP\/[0-9.]+[[:space:]]+2[0-9][0-9]([[:space:]]|$)/ { found = 1 }
      END { exit found ? 0 : 1 }
    ' "$marker" 2>/dev/null
  else
    [[ -s "$marker" ]]
  fi
}

run_active_holder() {
  local phase_label="$1" marker="$2" target="$3"
  local metrics code downloaded elapsed curl_rc=0
  metrics="$(curl -sS -o /dev/null --dump-header "$marker" --max-time 70 \
    -w $'%{http_code}\t%{size_download}\t%{time_total}' "$target" \
    2>> "$OUT/fanout.curl.log")" || curl_rc=$?
  IFS=$'\t' read -r code downloaded elapsed <<< "$metrics"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  [[ "$downloaded" =~ ^(0|[1-9][0-9]*)$ ]] || downloaded=0
  [[ "$elapsed" =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] || elapsed=0
  printf '%s\t%s\t%s\t%s\tcurl_exit=%s\n' \
    "$phase_label" "$code" "$downloaded" "$elapsed" "$curl_rc" \
    >> "$OUT/fanout.txt"
  (( curl_rc == 0 )) && [[ "$code" =~ ^2[0-9][0-9]$ ]]
}

# spawn one ACTIVE flow: a slow server-side drip (~45s, refilled by top-up as
# the server's ~60s connection timeout cuts it). Holds an established flow.
spawn_active() {
  local delay=22 marker
  HOLDER_SEQUENCE=$((HOLDER_SEQUENCE + 1))
  marker="$OUT/holder-markers/${FLOW_POOL_LABEL}.${HOLDER_SEQUENCE}.active.headers"
  : > "$marker"
  run_active_holder "$FLOW_POOL_LABEL" "$marker" \
    "$(dl_url "$DL_MAX_BYTES" 16384 "$delay")" &
  printf '%s\t%s\n' "$!" "$marker" >> "$HOLDER_PIDFILE"
}

# spawn one SILENT flow: raw TCP connect that sends nothing, exits on EOF
# (server close) or after IDLE_HOLD. The proxy peeks for 8s, sees no
# ClientHello, then passes it through → an established silent flow that ages
# toward the idle floor. (On a long-floor build the server's ~60s timeout cuts
# it before the floor → admit-and-ride; on a short-floor build it gets evicted.)
# shellcheck disable=SC2329  # selected dynamically by run_flow_pool
spawn_silent() {
  local marker
  HOLDER_SEQUENCE=$((HOLDER_SEQUENCE + 1))
  marker="$OUT/holder-markers/${FLOW_POOL_LABEL}.${HOLDER_SEQUENCE}.silent.connected"
  ( exec 3<>/dev/tcp/"$DL_HOST"/443 2>/dev/null \
      && printf 'connected\n' > "$marker" \
      && IFS= read -r -t "$IDLE_HOLD" -u 3 _ ) \
    >/dev/null 2>&1 &
  printf '%s\t%s\n' "$!" "$marker" >> "$HOLDER_PIDFILE"
}

update_sustained_hold() {
  local target="$1" established="$2" now_seconds="$3" now_epoch="$4" hold="$5"
  if (( established >= target )); then
    if [[ -z "$sustained_since_seconds" ]]; then
      sustained_since_seconds="$now_seconds"
      sustained_since_epoch="$now_epoch"
    fi
    last_established_epoch="$now_epoch"
    if (( now_seconds - sustained_since_seconds >= hold )); then
      FLOW_POOL_ATTAINED=1
    fi
    return 0
  fi
  if [[ -n "$sustained_since_seconds" ]]; then
    printf '%s\t%s\t%s\n' "$FLOW_POOL_LABEL" "$sustained_since_epoch" \
      "$last_established_epoch" >> "$OUT/pool-intervals.tsv"
  fi
  sustained_since_seconds=""
  sustained_since_epoch=""
  last_established_epoch=""
}

# Sustain a pool of `target` flows for `hold` seconds via top-up, logging the
# gauge each tick.  run_flow_pool LABEL TARGET HOLD SPAWN_FN
run_flow_pool() {
  local label="$1" target="$2" hold="$3" spawn_fn="$4"
  : > "$HOLDER_PIDFILE"
  local live established need g counts
  local sustained_since_seconds="" sustained_since_epoch="" now_seconds now_epoch
  local last_established_epoch=""
  local baseline_gauge baseline_epoch="" baseline_registered="" baseline_allocated=""
  local peak_epoch="" peak_registered=-1 peak_allocated=-1 peak_basis=-1
  local gauge_epoch gauge_registered gauge_allocated gauge_basis
  local post_boundary post_gauge post_epoch="" post_registered="" post_allocated=""
  local contribution=0
  FLOW_POOL_LABEL="$label"
  FLOW_POOL_ATTAINED=0
  FLOW_POOL_MAX_LIVE=0
  FLOW_POOL_MAX_ESTABLISHED=0
  baseline_gauge="$(wait_for_fresh_gauge "$CURRENT_PHASE_START" 70)"
  if [[ -n "$baseline_gauge" ]]; then
    read -r baseline_epoch _ _ _ _ baseline_registered baseline_allocated \
      <<< "$baseline_gauge"
    peak_epoch="$baseline_epoch"
    peak_registered="$baseline_registered"
    peak_allocated="$baseline_allocated"
    if (( SOFTCAP > 0 || HARDCAP == 0 )); then
      peak_basis="$peak_registered"
    else
      peak_basis="$peak_allocated"
    fi
  else
    warn "$label has no fresh target-provider gauge before spawning"
  fi
  # Allow a bounded 70-second establishment window, then require one
  # uninterrupted interval at the full target for the entire requested hold.
  # A short early success followed by collapse is not a sustained pool.
  local deadline=$(( SECONDS + hold + 70 ))
  while (( SECONDS < deadline && ! FLOW_POOL_ATTAINED )); do
    counts="$(recount_holders)"; read -r live established <<< "$counts"
    now_seconds="$SECONDS"; now_epoch="$(epoch_now)"
    update_sustained_hold "$target" "$established" "$now_seconds" "$now_epoch" "$hold"
    need=$(( target - live ))
    (( need > 0 )) && { local k; for ((k=0; k<need; k++)); do "$spawn_fn"; done; }
    sleep 1
    counts="$(recount_holders)"; read -r live established <<< "$counts"
    (( live > FLOW_POOL_MAX_LIVE )) && FLOW_POOL_MAX_LIVE=$live
    (( established > FLOW_POOL_MAX_ESTABLISHED )) && FLOW_POOL_MAX_ESTABLISHED=$established
    now_seconds="$SECONDS"; now_epoch="$(epoch_now)"
    update_sustained_hold "$target" "$established" "$now_seconds" "$now_epoch" "$hold"
    gauge_registered=""
    gauge_allocated=""
    gauge_basis=""
    g="$(read_gauge)"
    if [[ -n "$g" ]]; then
      read -r gauge_epoch _ _ _ _ gauge_registered gauge_allocated <<< "$g"
      if (( SOFTCAP > 0 || HARDCAP == 0 )); then
        gauge_basis="$gauge_registered"
      else
        gauge_basis="$gauge_allocated"
      fi
      if [[ "$gauge_basis" =~ ^[0-9]+$ ]] && (( gauge_basis >= peak_basis )); then
        peak_epoch="$gauge_epoch"
        peak_registered="$gauge_registered"
        peak_allocated="$gauge_allocated"
        peak_basis="$gauge_basis"
      fi
    fi
    printf '%s\t%s\tlive=%s\testablished=%s\tregistered=%s\tallocated=%s\n' \
      "$(date -u +%FT%TZ)" "$label" "$live" "$established" \
      "${gauge_registered:-?}" "${gauge_allocated:-?}" >> "$OUT/holders.log"
    printf '\r[soak] %s live=%s established=%s registered=%s allocated=%s  %ds left   ' \
      "$label" "$live" "$established" "${gauge_registered:-?}" \
      "${gauge_allocated:-?}" "$(( deadline - SECONDS ))"
    probe_ok || warn "probe failed during $label (registered=${gauge_registered:-?} allocated=${gauge_allocated:-?}) — watch for freeze"
    (( FLOW_POOL_ATTAINED )) && break
    sleep 5
  done
  if [[ -n "$sustained_since_seconds" ]]; then
    printf '%s\t%s\t%s\n' "$label" "$sustained_since_epoch" \
      "$last_established_epoch" >> "$OUT/pool-intervals.tsv"
  fi
  printf '\r%-70s\r' ' '
  kill_holders
  post_boundary="$(epoch_now)"
  post_gauge="$(wait_for_fresh_gauge "$post_boundary" 70)"
  if [[ -n "$post_gauge" ]]; then
    read -r post_epoch _ _ _ _ post_registered post_allocated <<< "$post_gauge"
  else
    warn "$label has no fresh target-provider gauge after killing workers"
  fi
  if [[ "$baseline_registered" =~ ^[0-9]+$ && "$baseline_allocated" =~ ^[0-9]+$ ]]; then
    contribution="$(flow_pool_expected_contribution \
      "$target" "$SOFTCAP" "$HARDCAP" \
      "$baseline_registered" "$baseline_allocated")"
  fi
  if [[ -n "$baseline_epoch" && -n "$peak_epoch" && -n "$post_epoch" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" \
      "$baseline_epoch" "$baseline_registered" "$baseline_allocated" \
      "$peak_epoch" "$peak_registered" "$peak_allocated" \
      "$post_epoch" "$post_registered" "$post_allocated" "$contribution" \
      >> "$OUT/pool-brackets.tsv"
  fi
}

# ── Preconditions ─────────────────────────────────────────────────────
hdr "rama transparent proxy soak — comprehensive single session"
[[ -x "$(command -v curl)" ]] || die "curl not found"
[[ -f "$STRESS_SH" ]] || die "stress script not found at $STRESS_SH (is REPO correct?)"
REPO_HEAD="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || true)"
[[ "$REPO_HEAD" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] \
  || die "could not resolve the repository commit identity"
REPO_DIRTY=0
[[ -z "$(git -C "$REPO" status --porcelain --untracked-files=normal 2>/dev/null)" ]] \
  || REPO_DIRTY=1
SOAK_SCRIPT_SHA256="$(sha256_path "$0")"
STRESS_SCRIPT_SHA256="$(sha256_path "$STRESS_SH")"
PRESSURE_PARSER_SHA256="$(sha256_path "$EXAMPLE_DIR/scripts/soak_pressure_log.py")"
[[ "$SOAK_SCRIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "could not hash soak_test.sh"
[[ "$STRESS_SCRIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "could not hash stress_traffic.sh"
[[ "$PRESSURE_PARSER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not hash soak_pressure_log.py"
mkdir -p "$OUT" || die "cannot create OUT=$OUT"
if [[ -n "$(find "$OUT" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  die "OUT=$OUT is not empty; use a fresh artifact directory"
fi
: > "$OUT/phases.tsv"; : > "$OUT/run-meta.tsv"
: > "$OUT/probe-timeline.txt"; : > "$OUT/holders.log"
: > "$OUT/ceiling-probes.tsv"
: > "$OUT/pool-intervals.tsv"
: > "$OUT/pool-brackets.tsv"
: > "$OUT/holder-cleanup.tsv"
: > "$OUT/sleep-probes.tsv"
: > "$OUT/provider-timeline.tsv"
mkdir -p "$OUT/holder-markers"
{
  printf 'repo_head\t%s\nrepo_dirty\t%s\n' "$REPO_HEAD" "$REPO_DIRTY"
  printf 'soak_script_sha256\t%s\nstress_script_sha256\t%s\npressure_parser_sha256\t%s\n' \
    "$SOAK_SCRIPT_SHA256" "$STRESS_SCRIPT_SHA256" "$PRESSURE_PARSER_SHA256"
} >> "$OUT/run-meta.tsv"
write_incomplete_status "soak did not reach evidence extraction"
HOLDER_PIDFILE="$OUT/holders.pids"; : > "$HOLDER_PIDFILE"
ulimit -n 16384 2>/dev/null || true

say "artifacts:   $OUT"
say "stress:      ${STRESS_SECONDS}s @ concurrency $CONCURRENCY"
say "fanout:      target $([[ "$FANOUT_TARGET" == 0 ]] && echo auto || echo "$FANOUT_TARGET"), hold ${FANOUT_HOLD}s (active drip via $DL_HOST)"
say "idle hold:   target $([[ "$IDLE_TARGET" == 0 ]] && echo auto || echo "$IDLE_TARGET") silent flows, sustain ${IDLE_HOLD}s"
say "sleep/wake:  $([[ "$SKIP_SLEEP" == 1 ]] && echo skipped || echo enabled)"
say "idle tail:   ${IDLE_TAIL}s"
(( FIND_CEILING )) && warn "FIND_CEILING=1 — ceiling-finder ARMED (only valid when softCap=0 and hardCap=0)"

say "caching sudo (you may be prompted once)..."
sudo -v || die "sudo is required"
( while true; do sudo -n -v 2>/dev/null || exit 0; sleep 30; done ) &
SUDO_KEEPALIVE_PID=$!

# ── Optional install ──────────────────────────────────────────────────
if [[ "$DO_INSTALL" == 1 ]]; then
  hdr "building + installing the dev proxy"
  ( cd "$EXAMPLE_DIR" && just install-tproxy-dev ) || die "install failed"
  warn "enable the system extension + toggle the proxy ON in the app, then press Enter"
  if [[ -t 0 ]]; then read -r _; else sleep 10; fi
fi

# ── Liveness ──────────────────────────────────────────────────────────
hdr "liveness check"
PROBE_CODE="$(probe_once)"
[[ "$PROBE_CODE" =~ ^2 ]] || die "probe got '$PROBE_CODE' against $HTTPS_PROBE — endpoint unavailable, sysext down, or no network. Enable the proxy (or DO_INSTALL=1) and retry."
say "${GREEN}network preflight ok ($PROBE_CODE); provider correlation starts below${RESET}"
# Sanity-check the download host actually serves through the proxy (Cloudflare
# 403s under MITM; the rama host does not).
DL_CHECK_RC=0
DL_CHECK="$(curl -sS -o /dev/null --max-time 20 -w '%{http_code}' \
  "$(dl_url 65536 16384 0)" 2>/dev/null)" || DL_CHECK_RC=$?
[[ "$DL_CHECK" =~ ^[0-9]{3}$ ]] || DL_CHECK=000
if (( DL_CHECK_RC == 0 )) && [[ "$DL_CHECK" =~ ^2 ]]; then
  DOWNLOAD_HOST_PREFLIGHT_OK=1
  say "${GREEN}download host ok ($DL_CHECK via $DL_HOST/bytes)${RESET}"
else
  DOWNLOAD_HOST_PREFLIGHT_OK=0
  warn "download host probe got '$DL_CHECK' curl_exit=$DL_CHECK_RC against $DL_HOST/bytes — fanout/holders may be starved"
fi
printf 'download_host_preflight_ok\t%s\n' "$DOWNLOAD_HOST_PREFLIGHT_OK" >> "$OUT/run-meta.tsv"

PID="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
[[ -n "$PID" ]] || die "could not find the sysext process ($PROVIDER_BUNDLE). Is it enabled?"
PROVIDER_START_TIME="$(ps -o lstart= -p "$PID" 2>/dev/null | sed -E 's/^[[:space:]]+//')"
[[ -n "$PROVIDER_START_TIME" ]] || die "could not read sysext process identity for pid $PID"
PROVIDER_START_IDENTITY="$(process_identity "$PID" || true)"
[[ "$PROVIDER_START_IDENTITY" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not fingerprint sysext process identity for pid $PID"
PROVIDER_EXECUTABLE="$(
  sudo -n lsof -a -p "$PID" -d txt -Fn 2>/dev/null \
    | sed -n 's/^n//p' | head -1
)"
if [[ ! "$PROVIDER_EXECUTABLE" == /* ]]; then
  PROVIDER_EXECUTABLE="$(ps -ww -o comm= -p "$PID" 2>/dev/null | sed -E 's/^[[:space:]]+//')"
fi
[[ "$PROVIDER_EXECUTABLE" == /* ]] \
  || die "could not resolve the running sysext executable path"
PROVIDER_BINARY_SHA256="$(sha256_path "$PROVIDER_EXECUTABLE")"
[[ "$PROVIDER_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not hash the running sysext executable"
PROVIDER_CODESIGN_INFO="$(codesign -dvvv "$PROVIDER_EXECUTABLE" 2>&1 || true)"
PROVIDER_CODESIGN_IDENTIFIER="$(
  printf '%s\n' "$PROVIDER_CODESIGN_INFO" | sed -n 's/^Identifier=//p' | head -1
)"
PROVIDER_CODESIGN_CDHASH="$(
  printf '%s\n' "$PROVIDER_CODESIGN_INFO" | sed -n 's/^CDHash=//p' | head -1
)"
PROVIDER_CODESIGN_TEAM="$(
  printf '%s\n' "$PROVIDER_CODESIGN_INFO" | sed -n 's/^TeamIdentifier=//p' | head -1
)"
[[ "$PROVIDER_CODESIGN_IDENTIFIER" == "$PROVIDER_BUNDLE" ]] \
  || die "running sysext signing identifier does not match $PROVIDER_BUNDLE"
[[ -n "$PROVIDER_CODESIGN_CDHASH" && -n "$PROVIDER_CODESIGN_TEAM" ]] \
  || die "could not resolve running sysext CDHash/team identity"
say "sysext pid:  $PID"
{
  printf 'provider_start_pid\t%s\nprovider_start_time\t%s\nprovider_start_identity\t%s\n' \
    "$PID" "$PROVIDER_START_TIME" "$PROVIDER_START_IDENTITY"
  printf 'provider_bundle\t%s\nprovider_executable\t%s\nprovider_binary_sha256\t%s\n' \
    "$PROVIDER_BUNDLE" "$PROVIDER_EXECUTABLE" "$PROVIDER_BINARY_SHA256"
  printf 'provider_codesign_identifier\t%s\nprovider_codesign_cdhash\t%s\nprovider_codesign_team\t%s\n' \
    "$PROVIDER_CODESIGN_IDENTIFIER" "$PROVIDER_CODESIGN_CDHASH" \
    "$PROVIDER_CODESIGN_TEAM"
} >> "$OUT/run-meta.tsv"

# ── Start live log capture (debug — the gauge is debug) ────────────────
hdr "starting log capture"
LOG_STREAM_START_EPOCH="$(epoch_now)"
# Word splitting intentionally expands optional `stdbuf -oL`; the destination
# is user-owned even though the log reader itself runs through sudo.
# shellcheck disable=SC2086,SC2024
sudo $LOGBUF log stream --level debug --style ndjson \
  --predicate "processID == $PID AND subsystem == \"$PROVIDER_BUNDLE\"" \
  > "$OUT/system.ndjson" 2>/dev/null &
LOG_STREAM_PID=$!
LOG_STREAM_STARTED=1
sleep 2
if sudo -n kill -0 "$LOG_STREAM_PID" 2>/dev/null; then
  printf 'log_stream_started\t1\nlog_stream_pid\t%s\n' "$LOG_STREAM_PID" >> "$OUT/run-meta.tsv"
else
  printf 'log_stream_started\t0\nlog_stream_pid\t%s\n' "$LOG_STREAM_PID" >> "$OUT/run-meta.tsv"
  warn "log stream did not stay alive — evidence verdicts will be inconclusive"
fi
printf 'log_stream_start_epoch\t%s\n' "$LOG_STREAM_START_EPOCH" >> "$OUT/run-meta.tsv"
say "streaming → $OUT/system.ndjson"
start_probe_monitor
printf 'probe_monitor_pid\t%s\n' "$PROBE_MON_PID" >> "$OUT/run-meta.tsv"
say "probe monitor → $OUT/probe-timeline.txt (freeze detector)"

# ── Phase 0: baseline + softCap detection ─────────────────────────────
phase_mark baseline start
hdr "phase 0 — baseline (detecting softCap from the gauge; ≤65s)"
G0="$(wait_for_fresh_gauge "$CURRENT_PHASE_START" 65)"
if [[ -z "$G0" ]]; then
  die "no fresh target-provider gauge was seen in 65s; refusing to generate load with unknown live-flow headroom"
else
  SOFTCAP_KNOWN=1
  read -r BASELINE_GAUGE_EPOCH SOFTCAP HARDCAP _ _ \
    BASELINE_REGISTERED BASELINE_TOTAL <<< "$G0"
  BASELINE_GAUGE_PHASE_LOCAL=0
  if awk -v gauge="$BASELINE_GAUGE_EPOCH" -v phase="$CURRENT_PHASE_START" \
    -v capture="$LOG_STREAM_START_EPOCH" \
    'BEGIN { exit !(gauge >= phase && gauge >= capture) }'; then
    BASELINE_GAUGE_PHASE_LOCAL=1
  fi
  say "detected ${BOLD}softCap=$SOFTCAP hardCap=$HARDCAP${RESET}, baseline registered=$BASELINE_REGISTERED allocated=$BASELINE_TOTAL"
fi
printf 'softcap\t%s\nhardcap\t%s\nbaseline_gauge_epoch\t%s\nbaseline_registered\t%s\nbaseline_total\t%s\n' \
  "$SOFTCAP" "$HARDCAP" "${BASELINE_GAUGE_EPOCH:-missing}" \
  "$BASELINE_REGISTERED" "$BASELINE_TOTAL" \
  >> "$OUT/run-meta.tsv"
printf 'baseline_gauge_seen\t%s\nbaseline_gauge_phase_local\t%s\n' \
  "$SOFTCAP_KNOWN" "$BASELINE_GAUGE_PHASE_LOCAL" >> "$OUT/run-meta.tsv"

SOFT_TRIGGER_HEADROOM=0
(( SOFTCAP > BASELINE_REGISTERED )) \
  && SOFT_TRIGGER_HEADROOM=$(( SOFTCAP - BASELINE_REGISTERED ))
LIVE_HARD_HEADROOM=-1
if (( HARDCAP > 0 )); then
  LIVE_HARD_HEADROOM=0
  (( HARDCAP > BASELINE_TOTAL )) \
    && LIVE_HARD_HEADROOM=$(( HARDCAP - BASELINE_TOTAL ))
fi

# Resolve mode.
MODE="cap-validate"
if (( FIND_CEILING )); then
  (( SOFTCAP_KNOWN )) || die "FIND_CEILING=1 requires a current gauge proving both caps are disabled."
  (( SOFTCAP == 0 )) || die "FIND_CEILING=1 but softCap=$SOFTCAP — rebuild with both flow caps set to 0."
  (( HARDCAP == 0 )) || die "FIND_CEILING=1 but hardCap=$HARDCAP — rebuild with both flow caps set to 0."
  MODE="find-ceiling"
elif (( SOFTCAP_KNOWN )) && (( SOFTCAP == 0 )); then
  warn "softCap=0 (cap DISABLED) but FIND_CEILING!=1 — running stress only; pass FIND_CEILING=1 to ramp to the ceiling."
  MODE="stress-only"
elif (( SOFTCAP_KNOWN )) && cap_validation_hard_limited \
  "$SOFTCAP" "$HARDCAP" "$BASELINE_REGISTERED" "$BASELINE_TOTAL"
then
  warn "hardCap=$HARDCAP has effective headroom=$LIVE_HARD_HEADROOM, below the registered headroom=$SOFT_TRIGGER_HEADROOM needed to reach softCap=$SOFTCAP; pressure validation is configuration-limited"
  MODE="cap-hard-limited"
elif (( SOFTCAP_KNOWN )) && (( SOFTCAP > MAX_SAFE_FLOWS )); then
  MODE="cap-too-high"
fi
say "mode:        ${BOLD}$MODE${RESET}"
printf 'mode\t%s\n' "$MODE" >> "$OUT/run-meta.tsv"

# Derive an auto target that never exceeds MAX_SAFE_FLOWS or the enabled hard
# cap's currently allocated headroom. On a high-soft-cap build, reaching the
# trigger means nearing the ~600 nexus ceiling; use a LOW-CAP build instead.
auto_target() {
  local base=$MAX_SAFE_FLOWS hard_headroom=0
  (( SOFTCAP_KNOWN )) && (( SOFTCAP > 0 )) && base=$(( SOFTCAP + SOFTCAP / 4 ))
  (( base > MAX_SAFE_FLOWS )) && base=$MAX_SAFE_FLOWS
  (( base < 40 )) && base=40
  if (( HARDCAP > 0 )); then
    (( HARDCAP > BASELINE_TOTAL )) && hard_headroom=$(( HARDCAP - BASELINE_TOTAL ))
    (( base > hard_headroom )) && base="$hard_headroom"
  fi
  (( base > 0 )) || return 1
  printf '%s\n' "$base"
}
clamp_safe() {  # clamp explicit targets to the safety limit and effective hard-cap headroom
  local v="$1" name="$2"
  local hard_headroom=-1
  if (( v > MAX_SAFE_FLOWS )) && (( ALLOW_UNSAFE_LOAD != 1 )); then
    warn "$name=$v exceeds MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS — clamping to avoid"
    warn "  nearing the ~600 nexus ceiling (machine-freeze risk). Set ALLOW_UNSAFE_LOAD=1 to override,"
    warn "  only when the host is intentionally prepared for unsafe load."
    v=$MAX_SAFE_FLOWS
  fi
  if (( HARDCAP > 0 )); then
    hard_headroom=0
    (( HARDCAP > BASELINE_TOTAL )) \
      && hard_headroom=$(( HARDCAP - BASELINE_TOTAL ))
    if (( v > hard_headroom )); then
      warn "$name=$v exceeds effective hard-cap headroom=$hard_headroom — clamping to a reachable target"
      v=$hard_headroom
    fi
  fi
  (( v > 0 )) || return 1
  echo "$v"
}
if (( FANOUT_TARGET == 0 )); then
  FANOUT_TARGET="$(auto_target)" \
    || die "no effective live-flow hard-cap headroom remains for an automatic fanout target"
else
  FANOUT_TARGET="$(clamp_safe "$FANOUT_TARGET" FANOUT_TARGET)" \
    || die "no effective live-flow hard-cap headroom remains for FANOUT_TARGET"
fi
if (( IDLE_TARGET == 0 )); then
  IDLE_TARGET=$FANOUT_TARGET
else
  IDLE_TARGET="$(clamp_safe "$IDLE_TARGET" IDLE_TARGET)" \
    || die "no effective live-flow hard-cap headroom remains for IDLE_TARGET"
fi
say "resolved targets: fanout=$FANOUT_TARGET idle=$IDLE_TARGET (MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS)"
[[ "$MODE" == "cap-too-high" ]] && warn "softCap=$SOFTCAP > MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS: this run validates leak/freeze/wake only, NOT cap eviction. Use a low-cap build to exercise the reaper."

{
  printf '=== baseline @ %s ===\n' "$(date -u +%FT%TZ)"
  printf 'softCap=%s baseline_total=%s mode=%s fanout=%s idle=%s\n\n' "$SOFTCAP" "$BASELINE_TOTAL" "$MODE" "$FANOUT_TARGET" "$IDLE_TARGET"
  ps -o pid,rss,vsz,%cpu,state -p "$PID" 2>/dev/null || echo "pid gone"
  printf '\n--- vmmap --summary ---\n'
  sudo -n vmmap --summary "$PID" 2>/dev/null || echo "vmmap unavailable"
} > "$OUT/baseline-mem.txt" 2>&1
phase_mark baseline end

# ═════════════ CEILING-FINDER (opt-in, both caps disabled) ════════════
if [[ "$MODE" == "find-ceiling" ]]; then
  phase_mark ceiling start
  CEILING_START_EPOCH="$CURRENT_PHASE_START"
  hdr "CEILING-FINDER"
  warn "This deliberately exhausts the kernel nexus-flow allocation and can"
  warn "briefly FREEZE ALL networking on this Mac. It backs off + kills load the"
  warn "instant the probe fails. NOTE: against a 60s-timeout server it may"
  warn "plateau BELOW the true ceiling (flows die before enough accumulate)."
  if [[ "$ASSUME_YES" != 1 ]]; then
    if [[ ! -t 0 ]]; then
      die "non-interactive ceiling-finder requires ASSUME_YES=1"
    fi
    printf '%s[soak]%s type CEILING to proceed: ' "$DIM" "$RESET"; read -r _ans
    [[ "$_ans" == "CEILING" ]] || die "aborted"
  fi
  launched=0; last_good=0; ceiling=""; CEILING_FOUND=0
  FLOW_POOL_LABEL=ceiling
  CEILING_OUTAGE_START=""; CEILING_OUTAGE_END=""
  while (( launched < MAX_SAFE_FLOWS * 3 )); do
    for ((i=0; i<CEIL_STEP; i++)); do spawn_active; launched=$((launched+1)); done
    sleep "$CEIL_SETTLE"
    g="$(read_gauge)"; gauge_epoch="${g%% *}"; occ="${g##* }"; [[ -z "$occ" ]] && occ="?"
    probe_record_value="$(probe_record)"
    IFS=$'\t' read -r probe_started probe_completed probe_curl_rc code \
      <<< "$probe_record_value"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$probe_started" "$probe_completed" \
      "$probe_curl_rc" "$code" "$occ" "$gauge_epoch" >> "$OUT/ceiling-probes.tsv"
    if (( probe_curl_rc == 0 )) && [[ "$code" =~ ^2 ]]; then
      last_good="$occ"; say "ramp: launched=$launched gauge_total=$occ probe=OK"
    else
      warn "probe failed at gauge_total=$occ; confirming before attributing a ceiling"
      sleep 1
      g="$(read_gauge)"; confirm_gauge_epoch="${g%% *}"; confirm_occ="${g##* }"; [[ -z "$confirm_occ" ]] && confirm_occ="?"
      confirm_record="$(probe_record)"
      IFS=$'\t' read -r confirm_started confirm_completed confirm_curl_rc confirm_code \
        <<< "$confirm_record"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$confirm_started" "$confirm_completed" \
        "$confirm_curl_rc" "$confirm_code" "$confirm_occ" "$confirm_gauge_epoch" >> "$OUT/ceiling-probes.tsv"
      if ceiling_transport_candidate "$probe_curl_rc" "$code" \
        && ceiling_transport_candidate "$confirm_curl_rc" "$confirm_code" \
        && [[ "$occ" =~ ^[0-9]+$ && "$confirm_occ" =~ ^[0-9]+$ ]] \
        && (( occ > BASELINE_TOTAL && confirm_occ > BASELINE_TOTAL )) \
        && gauge_is_fresh "$gauge_epoch" "$probe_started" "$CEILING_START_EPOCH" \
        && gauge_is_fresh "$confirm_gauge_epoch" "$confirm_started" "$CEILING_START_EPOCH"; then
        ceiling="$confirm_occ"; CEILING_FOUND=1
        CEILING_OUTAGE_START="$probe_completed"
        warn "two elevated transport probes produced a ceiling candidate at gauge_total=$confirm_occ; final evidence still requires an explicit provider allocation-exhaustion signal. Backing off."
        break
      elif ! { (( confirm_curl_rc == 0 )) && [[ "$confirm_code" =~ ^2 ]]; }; then
        warn "repeated failure was not backed by elevated gauge evidence; aborting as unproven"
        break
      else
        warn "confirmation recovered; treating the first failure as transient and continuing"
      fi
    fi
  done
  (( CEILING_FOUND )) || warn "ceiling was not found before the configured ramp limit"
  say "killing load to recover the machine..."
  kill_holders
  CEILING_RECOVERED=0
  for i in $(seq 1 20); do
    g="$(read_gauge)"; recovery_gauge_epoch="${g%% *}"; recovery_occ="${g##* }"
    recovery_record="$(probe_record)"
    IFS=$'\t' read -r recovery_started recovery_completed recovery_curl_rc recovery_code \
      <<< "$recovery_record"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$recovery_started" "$recovery_completed" \
      "$recovery_curl_rc" "$recovery_code" "$recovery_occ" "$recovery_gauge_epoch" >> "$OUT/ceiling-probes.tsv"
    if (( recovery_curl_rc == 0 )) && [[ "$recovery_code" =~ ^2 ]]; then
      CEILING_RECOVERED=1
      CEILING_OUTAGE_END="$recovery_completed"
      say "${GREEN}recovered${RESET}"
      break
    fi
    sleep 3
  done
  (( CEILING_RECOVERED )) || warn "network did not recover within the ceiling-finder budget"
  {
    printf 'ceiling-finder result\n'
    printf 'last gauge_total with probe OK: %s\n' "$last_good"
    printf 'gauge_total at first repeated transport candidate: %s\n' "${ceiling:-none}"
    printf 'This tuple is heuristic until extract-summary.txt correlates exact provider gauges and an explicit allocation-exhaustion signal; do not tune caps from an inconclusive result.\n'
  } | tee "$OUT/ceiling.txt"
  printf 'ceiling_found\t%s\nceiling_recovered\t%s\nceiling_outage_start\t%s\nceiling_outage_end\t%s\n' \
    "$CEILING_FOUND" "$CEILING_RECOVERED" "$CEILING_OUTAGE_START" \
    "$CEILING_OUTAGE_END" >> "$OUT/run-meta.tsv"
  phase_mark ceiling end
else

# ════════════════ CAP-VALIDATE / STRESS battery ══════════════════════

if [[ "$SKIP_STRESS" != 1 ]]; then
  phase_mark stress start
  hdr "phase 1 — stress traffic (${STRESS_SECONDS}s @ $CONCURRENCY)"
  STRESS_DURATION="$STRESS_SECONDS" STRESS_CONCURRENCY="$CONCURRENCY" \
    STRESS_MONITOR_PID="$PID" STRESS_LOG_DIR="$OUT/stress" STRESS_SKIP_LIVENESS=1 \
      bash "$STRESS_SH" > "$OUT/stress-run.txt" 2>&1 &
  ACTIVE_CHILD_PID=$!
  if wait "$ACTIVE_CHILD_PID"; then
    STRESS_OK=1
  else
    STRESS_OK=0
    warn "stress run returned nonzero"
  fi
  ACTIVE_CHILD_PID=""
  cat "$OUT/stress-run.txt"
  STRESS_ATTRIBUTION=provider-monitored-traffic-only
  phase_mark stress end
else
  STRESS_OK=skipped
  STRESS_ATTRIBUTION=skipped
fi
printf 'stress_ok\t%s\nstress_attribution\t%s\n' \
  "$STRESS_OK" "$STRESS_ATTRIBUTION" >> "$OUT/run-meta.tsv"

if [[ "$SKIP_FANOUT" != 1 ]]; then
  phase_mark fanout start
  hdr "phase 2 — fanout: sustain $FANOUT_TARGET active flows for ${FANOUT_HOLD}s"
  say "active slow-drip flows via $DL_HOST/bytes → peak / admit-and-ride / active-not-evicted"
  : > "$OUT/fanout.txt"
  run_flow_pool fanout "$FANOUT_TARGET" "$FANOUT_HOLD" spawn_active
  FANOUT_ESTABLISHED_TARGET_SUSTAINED=$FLOW_POOL_ATTAINED
  printf 'fanout_max_live\t%s\nfanout_max_established\t%s\nfanout_target\t%s\n' \
    "$FLOW_POOL_MAX_LIVE" "$FLOW_POOL_MAX_ESTABLISHED" "$FANOUT_TARGET" \
    >> "$OUT/run-meta.tsv"
  phase_mark fanout end
else
  FANOUT_ESTABLISHED_TARGET_SUSTAINED=skipped
fi
printf 'fanout_established_target_sustained\t%s\n' "$FANOUT_ESTABLISHED_TARGET_SUSTAINED" >> "$OUT/run-meta.tsv"
printf 'fanout_hold_seconds\t%s\n' "$FANOUT_HOLD" >> "$OUT/run-meta.tsv"

if [[ "$SKIP_IDLE" != 1 ]]; then
  phase_mark idle-holders start
  hdr "phase 3 — idle holders: sustain $IDLE_TARGET silent flows for ${IDLE_HOLD}s"
  say "raw silent TCP flows (no data) → ages toward the idle floor → eviction reaper"
  warn "NOTE: the rama test host cuts idle conns at ~60s, and the prod idle floor"
  warn "is 120s, so on a PROD build expect admit-and-ride (no eviction). Build with"
  warn "a short Rust flow-pressure idle floor (≈10s) to see evictions."
  run_flow_pool idle-holders "$IDLE_TARGET" "$IDLE_HOLD" spawn_silent
  IDLE_HOLDERS_ESTABLISHED_TARGET_SUSTAINED=$FLOW_POOL_ATTAINED
  printf 'idle_holders_max_live\t%s\nidle_holders_max_established\t%s\nidle_holders_target\t%s\n' \
    "$FLOW_POOL_MAX_LIVE" "$FLOW_POOL_MAX_ESTABLISHED" "$IDLE_TARGET" \
    >> "$OUT/run-meta.tsv"
  phase_mark idle-holders end
else
  IDLE_HOLDERS_ESTABLISHED_TARGET_SUSTAINED=skipped
fi
printf 'idle_holders_established_target_sustained\t%s\n' "$IDLE_HOLDERS_ESTABLISHED_TARGET_SUSTAINED" >> "$OUT/run-meta.tsv"
printf 'idle_holders_hold_seconds\t%s\n' "$IDLE_HOLD" >> "$OUT/run-meta.tsv"

phase_mark real-download start
hdr "phase 4 — real-world download (32 MiB steady stream)"
REAL_DOWNLOAD_METRICS=""
REAL_DOWNLOAD_CURL_RC=0
: > "$OUT/real-download.metrics"
curl -L -f -sS -o /dev/null --max-time 120 \
  --header 'Accept-Encoding: identity' \
  -w $'%{http_code}\t%{size_download}\t%{speed_download}\t%{time_total}' \
  "$(dl_url "$DL_MAX_BYTES" 32768 5)" > "$OUT/real-download.metrics" \
  2>"$OUT/real-download.curl.log" &
ACTIVE_CHILD_PID=$!
wait "$ACTIVE_CHILD_PID" || REAL_DOWNLOAD_CURL_RC=$?
ACTIVE_CHILD_PID=""
REAL_DOWNLOAD_METRICS="$(<"$OUT/real-download.metrics")"
IFS=$'\t' read -r REAL_DOWNLOAD_CODE REAL_DOWNLOAD_BYTES \
  REAL_DOWNLOAD_SPEED REAL_DOWNLOAD_TIME <<< "$REAL_DOWNLOAD_METRICS"
{
  cat "$OUT/real-download.curl.log"
  printf 'real-download: code=%s curl_exit=%s size=%s expected=%s avg=%sB/s time=%ss\n' \
    "${REAL_DOWNLOAD_CODE:-000}" "$REAL_DOWNLOAD_CURL_RC" \
    "${REAL_DOWNLOAD_BYTES:-?}" "$DL_MAX_BYTES" \
    "${REAL_DOWNLOAD_SPEED:-?}" "${REAL_DOWNLOAD_TIME:-?}"
} | tee "$OUT/real-download.txt"
if real_download_matches "$REAL_DOWNLOAD_CURL_RC" "$REAL_DOWNLOAD_CODE" \
  "$REAL_DOWNLOAD_BYTES" "$DL_MAX_BYTES" "$REAL_DOWNLOAD_SPEED" \
  "$REAL_DOWNLOAD_TIME"; then
  REAL_DOWNLOAD_OK=1
else
  REAL_DOWNLOAD_OK=0
  warn "real download failed, transferred an unexpected byte count, or reported no throughput"
fi
printf 'real_download_ok\t%s\n' "$REAL_DOWNLOAD_OK" >> "$OUT/run-meta.tsv"
phase_mark real-download end

if [[ "$SKIP_SLEEP" == 1 || ! -t 0 ]]; then
  hdr "phase 5 — sleep/wake (SKIPPED)"
  [[ ! -t 0 && "$SKIP_SLEEP" != 1 ]] && warn "no TTY — skipping sleep/wake (needs a manual wake)"
  POST_WAKE_OK=skipped
  SLEEP_COMMAND_OK=skipped
  WAKE_WORKLOAD_STARTED=skipped
  WAKE_WORKLOAD_ESTABLISHED=skipped
  WAKE_WORKLOAD_ESTABLISHED_NONZERO_BYTES=skipped
  WAKE_WORKLOAD_ESTABLISHED_BYTES=skipped
  WAKE_WORKLOAD_HTTP_CODE=skipped
  WAKE_WORKLOAD_ALIVE_AT_SLEEP_COMMAND=skipped
  WAKE_WORKLOAD_CHILD_RC=skipped
  WAKE_WORKLOAD_JOINED=skipped
else
  phase_mark sleep-wake start
  hdr "phase 5 — sleep/wake"
  warn "This will put the Mac to SLEEP. A download will be in flight."
  warn "WAKE THE MAC MANUALLY (keypress / lid) ~45s after it sleeps."
  printf '%s[soak]%s press Enter to start (or Ctrl-C to abort)... ' "$DIM" "$RESET"
  read -r _
  say "starting a long server-drip download in the background (in flight across sleep)..."
  # Long drip so a transfer is genuinely mid-stream across sleep/wake (bounded
  # by --max-time; the server's ~60s timeout may cut the SAME flow — this proves
  # post-wake RECOVERY, not that one flow survives the gap).
  WAKE_WORKLOAD_STARTED="$(epoch_now)"
  WAKE_WORKLOAD_ESTABLISHED=missing
  WAKE_WORKLOAD_ESTABLISHED_NONZERO_BYTES=0
  WAKE_WORKLOAD_ESTABLISHED_BYTES=0
  WAKE_WORKLOAD_HTTP_CODE=000
  WAKE_WORKLOAD_ALIVE_AT_SLEEP_COMMAND=0
  WAKE_WORKLOAD_CHILD_RC=missing
  WAKE_WORKLOAD_JOINED=0
  : > "$OUT/wake-download-headers.txt"
  : > "$OUT/wake-download.body"
  curl -L -f -sS --no-buffer -o "$OUT/wake-download.body" \
      --dump-header "$OUT/wake-download-headers.txt" --max-time 600 \
      -w 'wake-download: code=%{http_code} size=%{size_download} time=%{time_total}s\n' \
      "$(dl_url "$DL_MAX_BYTES" 16384 250)" > "$OUT/wake-download.txt" 2>&1 &
  WAKE_DL_PID=$!
  WAKE_ESTABLISH_DEADLINE=$(( $(date +%s) + 20 ))
  while (( $(date +%s) < WAKE_ESTABLISH_DEADLINE )); do
    WAKE_WORKLOAD_HTTP_CODE="$(
      awk '/^HTTP\/[0-9.]+ [0-9][0-9][0-9]/ { code=$2 } END { print code }' \
        "$OUT/wake-download-headers.txt"
    )"
    [[ "$WAKE_WORKLOAD_HTTP_CODE" =~ ^[0-9]{3}$ ]] \
      || WAKE_WORKLOAD_HTTP_CODE=000
    WAKE_WORKLOAD_ESTABLISHED_BYTES="$(
      wc -c < "$OUT/wake-download.body" 2>/dev/null | tr -d ' ' || echo 0
    )"
    WAKE_WORKLOAD_ESTABLISHED_BYTES="${WAKE_WORKLOAD_ESTABLISHED_BYTES:-0}"
    if [[ "$WAKE_WORKLOAD_HTTP_CODE" =~ ^2 ]] \
      && [[ "$WAKE_WORKLOAD_ESTABLISHED_BYTES" =~ ^[0-9]+$ ]] \
      && (( WAKE_WORKLOAD_ESTABLISHED_BYTES > 0 )) \
      && kill -0 "$WAKE_DL_PID" 2>/dev/null
    then
      WAKE_WORKLOAD_ESTABLISHED="$(epoch_now)"
      WAKE_WORKLOAD_ESTABLISHED_NONZERO_BYTES=1
      break
    fi
    kill -0 "$WAKE_DL_PID" 2>/dev/null || break
    sleep 1
  done
  if [[ "$WAKE_WORKLOAD_ESTABLISHED_NONZERO_BYTES" != 1 ]]; then
    warn "sleep workload did not establish a live 2xx response with nonzero bytes"
  fi
  warn ">>> SLEEPING NOW — wake the Mac manually in ~45s <<<"
  SLEEP_COMMAND_START="$(epoch_now)"
  kill -0 "$WAKE_DL_PID" 2>/dev/null && WAKE_WORKLOAD_ALIVE_AT_SLEEP_COMMAND=1
  if sudo pmset sleepnow; then
    SLEEP_COMMAND_OK=1
  else
    SLEEP_COMMAND_OK=0
    warn "pmset sleepnow failed"
  fi
  SLEEP_COMMAND_END="$(epoch_now)"
  printf 'sleep_command_start\t%s\nsleep_command_end\t%s\n' \
    "$SLEEP_COMMAND_START" "$SLEEP_COMMAND_END" >> "$OUT/run-meta.tsv"
  sleep 5
  sudo -v 2>/dev/null || true
  say "awake — probing connectivity..."
  for i in 1 2 3; do
    WAKE_PROBE_RECORD="$(probe_record)"
    IFS=$'\t' read -r WAKE_PROBE_START WAKE_PROBE_END WAKE_PROBE_RC WCODE \
      <<< "$WAKE_PROBE_RECORD"
    printf '%s\t%s\t%s\t%s\t%s\n' "$WAKE_PROBE_START" "$WAKE_PROBE_END" \
      "$(iso_for_epoch "$WAKE_PROBE_END")" "$WAKE_PROBE_RC" "$WCODE" \
      >> "$OUT/sleep-probes.tsv"
    printf 'post-wake probe %d: http=%s curl_exit=%s\n' "$i" "$WCODE" \
      "$WAKE_PROBE_RC" | tee -a "$OUT/post-wake.txt"
    if (( WAKE_PROBE_RC == 0 )) && [[ "$WCODE" =~ ^2 ]]; then
      break
    fi
    sleep 3
  done
  if (( ${WAKE_PROBE_RC:-1} == 0 )) && [[ "${WCODE:-}" =~ ^2 ]]; then
    POST_WAKE_OK=1
    say "${GREEN}post-wake: traffic recovered ($WCODE)${RESET}"
  else
    POST_WAKE_OK=0
    warn "post-wake: traffic did NOT recover (last code '$WCODE') — this is the bug we're hunting"
  fi
  sleep 5
  bounded_stop_and_join "$WAKE_DL_PID" 5 direct
  WAKE_WORKLOAD_CHILD_RC="$BOUNDED_CHILD_RC"
  WAKE_WORKLOAD_JOINED="$BOUNDED_CHILD_REAPED"
  (( BOUNDED_CHILD_FORCED )) \
    && warn "sleep workload ignored TERM and required forced termination"
  (( BOUNDED_CHILD_REAPED )) && WAKE_DL_PID=""
  [[ -f "$OUT/wake-download.txt" ]] && cat "$OUT/wake-download.txt"
  phase_mark sleep-wake end
fi
{
  printf 'post_wake_ok\t%s\n' "$POST_WAKE_OK"
  printf 'sleep_command_ok\t%s\n' "$SLEEP_COMMAND_OK"
  printf 'wake_workload_started\t%s\nwake_workload_established\t%s\n' \
    "$WAKE_WORKLOAD_STARTED" "$WAKE_WORKLOAD_ESTABLISHED"
  printf 'wake_workload_established_nonzero_bytes\t%s\nwake_workload_established_bytes\t%s\n' \
    "$WAKE_WORKLOAD_ESTABLISHED_NONZERO_BYTES" "$WAKE_WORKLOAD_ESTABLISHED_BYTES"
  printf 'wake_workload_http_code\t%s\nwake_workload_alive_at_sleep_command\t%s\n' \
    "$WAKE_WORKLOAD_HTTP_CODE" "$WAKE_WORKLOAD_ALIVE_AT_SLEEP_COMMAND"
  printf 'wake_workload_child_rc\t%s\nwake_workload_joined\t%s\n' \
    "$WAKE_WORKLOAD_CHILD_RC" "$WAKE_WORKLOAD_JOINED"
} >> "$OUT/run-meta.tsv"

phase_mark idle-tail start
hdr "phase 6 — idle ${IDLE_TAIL}s (quiesce; keep the machine idle for a clean leak read)"
for ((t=IDLE_TAIL; t>0; t-=5)); do printf '\r[soak] idle %3ds remaining' "$t"; sleep 5; done
printf '\r%-40s\r' ' '
phase_mark idle-tail end

fi  # end cap-validate vs ceiling-finder

# ── Final memory snapshot (re-resolve pid; detect a restart) ──────────
hdr "final memory snapshot"
PID2=""
if kill -0 "$PID" 2>/dev/null; then
  PID2="$PID"
else
  PID2="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
fi
PROVIDER_END_TIME=""
[[ -n "$PID2" ]] && PROVIDER_END_TIME="$(ps -o lstart= -p "$PID2" 2>/dev/null | sed -E 's/^[[:space:]]+//')"
PROVIDER_END_IDENTITY=""
[[ -n "$PID2" ]] && PROVIDER_END_IDENTITY="$(process_identity "$PID2" || true)"
PROVIDER_CONTINUOUS=1
if [[ -z "$PID2" ]]; then
  warn "sysext process is GONE after the run (crashed or uninstalled)"
  PROVIDER_CONTINUOUS=0
elif [[ "$PID2" != "$PID" || "$PROVIDER_END_TIME" != "$PROVIDER_START_TIME" \
  || "$PROVIDER_END_IDENTITY" != "$PROVIDER_START_IDENTITY" ]]; then
  warn "sysext RESTARTED during the run: $PID → $PID2 (watchdog churn / crash — itself a signal)"
  PROVIDER_CONTINUOUS=0
fi
printf 'provider_end_pid\t%s\nprovider_end_time\t%s\nprovider_end_identity\t%s\nprovider_continuous\t%s\n' \
  "${PID2:-gone}" "${PROVIDER_END_TIME:-gone}" \
  "${PROVIDER_END_IDENTITY:-gone}" "$PROVIDER_CONTINUOUS" >> "$OUT/run-meta.tsv"
SNAP_PID="${PID2:-$PID}"
{
  printf '=== final snapshot @ %s ===\n' "$(date -u +%FT%TZ)"
  printf 'start pid=%s  final pid=%s  restarted=%s\n\n' \
    "$PID" "${PID2:-gone}" "$([[ "${PID2:-}" != "$PID" ]] && echo YES || echo no)"
  ps -o pid,rss,vsz,%cpu,state -p "$SNAP_PID" 2>/dev/null || echo "pid $SNAP_PID gone"
  printf '\n--- vmmap --summary ---\n'
  sudo -n vmmap --summary "$SNAP_PID" 2>/dev/null || echo "vmmap unavailable"
  printf '\n--- heap totals ---\n'
  sudo -n heap "$SNAP_PID" 2>/dev/null | grep -E 'All zones:|Total|Process [0-9]+:' || echo "heap unavailable"
} > "$OUT/final-mem.txt" 2>&1
say "→ $OUT/final-mem.txt"

# ── leaks pass ────────────────────────────────────────────────────────
hdr "leaks pass"
LEAKS_COMMAND_RC=0
# The privileged command writes through the invoking shell into user-owned OUT.
# shellcheck disable=SC2024
if sudo leaks "$SNAP_PID" > "$OUT/leaks.txt" 2>&1; then
  :
else
  LEAKS_COMMAND_RC=$?
fi
printf 'leaks_command_rc\t%s\n' "$LEAKS_COMMAND_RC" >> "$OUT/run-meta.tsv"
LEAK_LINE="$(grep -E 'leaks for|total leaked|Process .* leaks' "$OUT/leaks.txt" 2>/dev/null | head -1)"
say "${LEAK_LINE:-(leaks output unavailable or unparseable; see leaks.txt)}"
printf 'holder_cleanup_ok\t%s\n' "$HOLDER_CLEANUP_OK" >> "$OUT/run-meta.tsv"

# ── Stop log capture ──────────────────────────────────────────────────
hdr "stopping log capture"
PROBE_MONITOR_ALIVE=0
[[ -n "$PROBE_MON_PID" ]] && kill -0 "$PROBE_MON_PID" 2>/dev/null && PROBE_MONITOR_ALIVE=1
printf 'probe_monitor_alive_end\t%s\n' "$PROBE_MONITOR_ALIVE" >> "$OUT/run-meta.tsv"
PROBE_MONITOR_CHILD_RC=missing
PROBE_MONITOR_JOINED=0
if [[ -n "$PROBE_MON_PID" ]]; then
  bounded_stop_and_join "$PROBE_MON_PID" 5 direct
  PROBE_MONITOR_CHILD_RC="$BOUNDED_CHILD_RC"
  PROBE_MONITOR_JOINED="$BOUNDED_CHILD_REAPED"
  (( BOUNDED_CHILD_FORCED )) \
    && warn "probe monitor ignored TERM and required forced termination"
  (( BOUNDED_CHILD_REAPED )) && PROBE_MON_PID=""
fi
printf 'probe_monitor_child_rc\t%s\nprobe_monitor_joined\t%s\n' \
  "$PROBE_MONITOR_CHILD_RC" "$PROBE_MONITOR_JOINED" >> "$OUT/run-meta.tsv"
LOG_STREAM_ALIVE=0
[[ -n "$LOG_STREAM_PID" ]] && sudo -n kill -0 "$LOG_STREAM_PID" 2>/dev/null && LOG_STREAM_ALIVE=1
printf 'log_stream_alive_end\t%s\n' "$LOG_STREAM_ALIVE" >> "$OUT/run-meta.tsv"
LOG_STREAM_CHILD_RC=missing
LOG_STREAM_JOINED=0
if [[ -n "$LOG_STREAM_PID" ]]; then
  bounded_stop_and_join "$LOG_STREAM_PID" 5 sudo
  LOG_STREAM_CHILD_RC="$BOUNDED_CHILD_RC"
  LOG_STREAM_JOINED="$BOUNDED_CHILD_REAPED"
  (( BOUNDED_CHILD_FORCED )) \
    && warn "log stream ignored TERM and required forced termination"
  if (( BOUNDED_CHILD_REAPED )); then
    LOG_STREAM_PID=""
    LOG_STREAM_STARTED=0
  fi
fi
printf 'log_stream_child_rc\t%s\nlog_stream_joined\t%s\n' \
  "$LOG_STREAM_CHILD_RC" "$LOG_STREAM_JOINED" >> "$OUT/run-meta.tsv"
NDJSON_LINES="$(wc -l < "$OUT/system.ndjson" 2>/dev/null | tr -d ' ' || echo 0)"
say "captured $NDJSON_LINES ndjson lines"

# ── dial9 traces ──────────────────────────────────────────────────────
hdr "collecting dial9 traces"
if sudo -n test -d "$DIAL9_DIR" 2>/dev/null; then
  if sudo cp -R "$DIAL9_DIR" "$OUT/dial9-traces" 2>/dev/null \
    && sudo chown -R "$(whoami)" "$OUT/dial9-traces" 2>/dev/null
  then
    say "→ $OUT/dial9-traces ($(find "$OUT/dial9-traces" -type f | wc -l | tr -d ' ') files)"
  else
    warn "could not copy dial9 traces"
  fi
else
  say "(no dial9 traces present)"
fi

# ── Extract the signals that matter from the ndjson ───────────────────
hdr "extracting signals"
PYX="$(command -v python3 || true)"
if [[ -n "$PYX" ]]; then
  if "$PYX" - "$OUT" "$EXAMPLE_DIR/scripts" <<'PYEOF'
import os, re, sys
from decimal import Decimal

sys.path.insert(0, sys.argv[2])
from soak_pressure_log import (
    artifact_identity_issues,
    cap_validation_hard_limited,
    ceiling_configuration_issues,
    ceiling_outage_window,
    ceiling_probe_evidence_issues,
    classify_soak_result,
    engine_lifecycle_event,
    filter_provider_ndjson_records,
    flow_pool_evidence_issues,
    flow_pool_status,
    flow_gauge,
    leak_evidence,
    lifecycle_category_issue,
    no_headroom_event,
    parse_artifact_epoch,
    parse_artifact_uint,
    parse_epoch,
    parse_ndjson_lines,
    parse_ceiling_probe_lines,
    parse_oslog_timestamp,
    parse_phase_marker_lines,
    parse_provider_identity_lines,
    parse_probe_lines,
    phase_for_epoch,
    pressure_episode,
    pressure_telemetry_issue,
    pressure_reaper_status,
    provider_allocation_failure,
    probe_succeeded,
    selection_event,
    sleep_wake_evidence,
    settled_final_flow_gauge,
    soak_evidence_issues,
    summarize_pressure_rows,
    unexpected_probe_failure_count_across_outages,
)

out = sys.argv[1]
nd = os.path.join(out, "system.ndjson")

meta = {}
meta_issues = []
mf = os.path.join(out, "run-meta.tsv")
if os.path.exists(mf):
    for line_number, ln in enumerate(open(mf), 1):
        p = ln.rstrip("\n").split("\t")
        if len(p) == 2:
            if p[0] in meta:
                meta_issues.append(f"duplicate run metadata key {p[0]!r}")
            meta[p[0]] = p[1]
        elif ln.strip():
            meta_issues.append(f"malformed run metadata at line {line_number}")

for key in ("softcap", "hardcap", "baseline_registered", "baseline_total"):
    value = meta.get(key)
    if parse_artifact_uint(value) is None:
        meta_issues.append(f"run metadata {key!r} is missing or invalid")
for key in (
    "provider_start_pid", "provider_start_time", "provider_end_pid",
    "provider_end_time", "provider_start_identity", "provider_end_identity",
    "provider_bundle", "log_stream_pid", "probe_monitor_pid",
):
    if not meta.get(key):
        meta_issues.append(f"run metadata {key!r} is missing")
for key in ("provider_start_pid", "provider_end_pid", "log_stream_pid", "probe_monitor_pid"):
    parsed_pid = parse_artifact_uint(meta.get(key), maximum=2_147_483_647)
    if parsed_pid is None or parsed_pid == 0:
        meta_issues.append(f"run metadata {key!r} is not a positive integer")
if (
    meta.get("provider_start_pid") != meta.get("provider_end_pid")
    or meta.get("provider_start_time") != meta.get("provider_end_time")
    or meta.get("provider_start_identity") != meta.get("provider_end_identity")
):
    meta_issues.append("provider start/end process identity does not match")
meta_issues.extend(artifact_identity_issues(meta))

provider_identity_issues = []
provider_identity_path = os.path.join(out, "provider-timeline.tsv")
if os.path.exists(provider_identity_path):
    with open(provider_identity_path) as provider_identity_input:
        _, provider_identity_issues = parse_provider_identity_lines(
            provider_identity_input, meta.get("provider_start_identity"))
else:
    provider_identity_issues.append("provider identity timeline is missing")

pf = os.path.join(out, "phases.tsv")
expected_phase_order = (
    ["baseline", "ceiling"]
    if meta.get("mode") == "find-ceiling"
    else [
        "baseline", "stress", "fanout", "idle-holders", "real-download",
        "sleep-wake", "idle-tail",
    ]
)
if os.path.exists(pf):
    with open(pf) as phase_input:
        phases, incomplete_phases, phase_starts_us, phase_ends_us, phase_issues = (
            parse_phase_marker_lines(phase_input, expected_phase_order)
        )
else:
    phases, incomplete_phases, phase_starts_us, phase_ends_us = [], set(), {}, {}
    phase_issues = ["phase marker artifact is missing"]

def phase_of(ep):
    return phase_for_epoch(ep, phases)

baseline_end_epoch = next(
    (end for name, _, end in phases if name == "baseline"), None)
baseline_end_epoch_us = phase_ends_us.get("baseline")

def is_in_run(ep):
    return baseline_end_epoch is None or (
        ep is not None and ep > baseline_end_epoch)

rows = []
ndjson_issues = []
provider_source_issues = []
timestamp_issues = []
try:
    with open(nd, "r", errors="replace") as f:
        decoded, ndjson_issues = parse_ndjson_lines(f)
        decoded, provider_source_issues = filter_provider_ndjson_records(
            decoded, meta.get("provider_start_pid"), meta.get("provider_bundle")
        )
        rows = [
            (
                o.get("timestamp", ""), o.get("eventMessage", ""),
                o.get("messageType", ""), o.get("category", ""),
            )
            for o in decoded
        ]
        invalid_timestamps = sum(
            1 for ts, _, _, _ in rows if parse_oslog_timestamp(ts) is None
        )
        if invalid_timestamps:
            timestamp_issues.append(
                f"{invalid_timestamps} NDJSON record(s) have invalid timestamps")
except FileNotFoundError:
    pass

# Reaper signals are summarized separately below. Periodic deltas and episode
# totals overlap, so they are evidence channels rather than additive counters.
wd_idle_re = re.compile(r"watchdog: force-tearing down (\d+) idle promoted flow")
wd_wedged_re = re.compile(r"watchdog: force-tearing down (\d+) wedged closing flow")
wd_prerdy_re = re.compile(r"watchdog: force-tearing down (\d+) stale pre-ready flow")
drain_re = re.compile(r"drain backstop fired")
# Body-relay / egress-health signals — the Firefox "authenticity could not be
# verified" maps to these (decode-aborted/truncated client streams).
body_err_re = re.compile(r"brotli error|gzip error|zstd error|deflate error|send body user stream error|User\(Body\)")
egress_fail_re = re.compile(r"egress NWConnection failed after flow opened.*rawValue: (\d+)")
relay_drop_re = re.compile(r"drop MITM relay")
sleep_event_re = re.compile(r"^system sleep\b", re.I)
wake_event_re = re.compile(r"^system wake\b", re.I)
life_re = re.compile(r"(startProxy|stopProxy|system sleep|system wake|engine created|engine detached|"
                     r"watchdog:|drain backstop|force-drop|force-tear|flow pressure|not satisfied|"
                     r"Network is down|reset by peer|brotli error|drop MITM relay)", re.I)

peak_tcp = peak_udp = peak_total = 0
softcap_seen = set()
hardcap_seen = set()
missing_hardcap_gauges = 0
n_gauge = 0
c = dict(admit_and_ride=0, wd_idle=0,
         wd_wedged=0, wd_prerdy=0, drain_backstop=0, body_err=0,
         relay_drop=0, sleep=0, wake=0, err=0, fault=0, unknown_error=0)
egress_fail = {}   # posix code -> count
per_phase = {}
gauge_epochs_per_phase = {}
occupancy_samples_per_phase = {}
gauge_samples_per_phase = {}
lifecycle_category_issues = []
pressure_telemetry_issues = []
numeric_log_issues = []
pressure_rows = []
trusted_rows = []
for ts, msg, mtype, category in rows:
    epoch = parse_oslog_timestamp(ts)
    category_issue = lifecycle_category_issue(msg, category)
    if category_issue:
        lifecycle_category_issues.append(category_issue)
        continue
    telemetry_issue = pressure_telemetry_issue(msg)
    if telemetry_issue:
        pressure_telemetry_issues.append(telemetry_issue)
        continue
    trusted_rows.append((ts, msg, mtype, category))
    pressure_rows.append((epoch, msg))

pressure = summarize_pressure_rows(
    pressure_rows,
    baseline_end_epoch=baseline_end_epoch,
    baseline_end_epoch_us=baseline_end_epoch_us)

idle_tail = next(
    ((start, end) for name, start, end in phases if name == "idle-tail"),
    (None, None))
final_gauge = settled_final_flow_gauge(
    ((parse_oslog_timestamp(ts), msg) for ts, msg, _, _ in trusted_rows),
    settle_start_epoch=idle_tail[0],
    settle_end_epoch=idle_tail[1])

def ph(n):
    return per_phase.setdefault(
        n, dict(peak_total=0, ride=0, body_err=0, gauge=0, sleep=0, wake=0))

generation_events = []
sleep_epochs = []
wake_epochs = []
allocation_failure_epochs = []

with open(os.path.join(out, "flow-counts.txt"), "w") as g, \
     open(os.path.join(out, "timeline.txt"), "w") as t:
    for ts, msg, mtype, category in trusted_rows:
        ep = parse_oslog_timestamp(ts); pname = phase_of(ep)
        gauge = flow_gauge(msg)
        if gauge:
            tcp = gauge["tcp"]; udp = gauge["udp"]
            registered = gauge["registered"]; allocated = gauge["allocated"]
            total = allocated
            pk = gauge["peak"]; sc = gauge["soft_cap"]; hc = gauge["hard_cap"]
            g.write(
                f"{ts}  [{pname}]  tcp={tcp} udp={udp} "
                f"registered={registered} allocated={allocated} "
                f"peak={pk} softCap={sc} hardCap={hc if hc is not None else 'missing'}\n"
            )
            if ep is not None:
                peak_tcp = max(peak_tcp, tcp); peak_udp = max(peak_udp, udp); peak_total = max(peak_total, total)
                softcap_seen.add(sc); n_gauge += 1
                if hc is not None:
                    hardcap_seen.add(hc)
                else:
                    missing_hardcap_gauges += 1
                p = ph(pname); p["peak_total"] = max(p["peak_total"], total); p["gauge"] += 1
                gauge_epochs_per_phase.setdefault(pname, []).append(ep)
                occupancy_samples_per_phase.setdefault(pname, []).append(
                    (ep, registered))
                gauge_samples_per_phase.setdefault(pname, []).append(
                    (ep, registered, allocated))
        selection = selection_event(msg)
        if selection is not None and is_in_run(ep):
            ph(pname)["peak_total"] = max(
                ph(pname)["peak_total"], selection["occupancy"])
            occupancy_samples_per_phase.setdefault(pname, []).append(
                (ep, selection["occupancy"]))
        no_headroom = no_headroom_event(msg)
        if no_headroom is not None and is_in_run(ep):
            c["admit_and_ride"] += 1; ph(pname)["ride"] += 1
            ph(pname)["peak_total"] = max(
                ph(pname)["peak_total"], no_headroom["occupancy"])
            occupancy_samples_per_phase.setdefault(pname, []).append(
                (ep, no_headroom["occupancy"]))
        for rx, key in ((wd_idle_re, "wd_idle"), (wd_wedged_re, "wd_wedged"), (wd_prerdy_re, "wd_prerdy")):
            mm = rx.search(msg)
            if mm:
                count = parse_artifact_uint(mm.group(1))
                if count is None:
                    numeric_log_issues.append(
                        f"{key} event has an invalid numeric count")
                else:
                    c[key] += count
        if drain_re.search(msg):
            c["drain_backstop"] += 1
        if body_err_re.search(msg):
            c["body_err"] += 1; ph(pname)["body_err"] += 1
        if relay_drop_re.search(msg):
            c["relay_drop"] += 1
        if ep is not None and provider_allocation_failure(msg):
            allocation_failure_epochs.append(ep)
        ef = egress_fail_re.search(msg)
        if ef:
            code = parse_artifact_uint(ef.group(1))
            if code is None:
                numeric_log_issues.append(
                    "egress failure event has an invalid numeric code")
            else:
                code_text = str(code)
                egress_fail[code_text] = egress_fail.get(code_text, 0) + 1
        if mtype in ("Error", "Fault") or life_re.search(msg):
            t.write(f"{ts}  [{pname}] [{mtype or 'Default'}]  {msg}\n")
            if mtype in ("Error", "Fault"):
                c["err"] += 1
            if mtype == "Fault":
                c["fault"] += 1
            elif mtype == "Error" and not (
                body_err_re.search(msg)
                or relay_drop_re.search(msg)
                or (
                    meta.get("mode") == "find-ceiling"
                    and pname == "ceiling"
                    and provider_allocation_failure(msg)
                )
            ):
                c["unknown_error"] += 1
            if sleep_event_re.search(msg) and category == "lifecycle":
                c["sleep"] += 1; ph(pname)["sleep"] += 1
                if ep is not None:
                    sleep_epochs.append(ep)
            if wake_event_re.search(msg) and category == "lifecycle":
                c["wake"] += 1; ph(pname)["wake"] += 1
                if ep is not None:
                    wake_epochs.append(ep)
        lifecycle = engine_lifecycle_event(msg)
        if lifecycle and category == "lifecycle":
            generation_events.append((ts, lifecycle))

# Freeze detector (start \t completion \t iso \t curl_rc \t http_code).
probe_fail = probe_total = max_fail_run = probe_skipped = 0
probe_per_phase = {}
probe_failure_records = []
probe_issues = []
probe_records = []
ptl = os.path.join(out, "probe-timeline.txt")
if os.path.exists(ptl):
    with open(ptl) as probe_input:
        probe_records, probe_issues = parse_probe_lines(probe_input)
    run = 0
    for started, completed, curl_rc, code in probe_records:
        probe_phase = phase_of(completed)
        probe_total += 1
        if probe_phase not in ("?", "-"):
            probe_per_phase.setdefault(probe_phase, []).append(
                (started, completed))
        else:
            probe_phase = "outside-phase"
        if not probe_succeeded((started, completed, curl_rc, code)):
            probe_fail += 1; run += 1; max_fail_run = max(max_fail_run, run)
            probe_failure_records.append((started, completed, curl_rc, code))
        else:
            run = 0

# Completed active-flow outcomes. Intentional phase-end kills do not emit a row;
# every recorded non-2xx, truncated body, or nonzero curl outcome is a failure.
fo_ok = fo_bad = ceiling_fo_ok = ceiling_fo_bad = 0
fof = os.path.join(out, "fanout.txt")
if os.path.exists(fof):
    for line_number, ln in enumerate(open(fof, errors="replace"), 1):
        mm = re.fullmatch(
            r"(fanout|ceiling)\t(\d{3})\t(\d+)\t"
            r"(?:0|[1-9]\d*)(?:\.\d+)?\tcurl_exit=(\d+)\n?",
            ln,
        )
        if mm is None:
            numeric_log_issues.append(
                f"malformed active fanout outcome at line {line_number}")
            continue
        phase_label, code, downloaded, curl_rc = mm.groups()
        transfer_ok = (
            code.startswith("2")
            and parse_artifact_uint(downloaded) == 32 * 1024 * 1024
            and parse_artifact_uint(curl_rc) == 0
        )
        if phase_label == "fanout" and transfer_ok:
            fo_ok += 1
        elif phase_label == "fanout":
            fo_bad += 1
        elif transfer_ok:
            ceiling_fo_ok += 1
        else:
            # Ceiling-finder transfer failures are expected candidate signals;
            # they are reported separately and never weaken the independent,
            # phase-local allocation-exhaustion proof.
            ceiling_fo_bad += 1

def meta_true(key):
    return meta.get(key) == "1"

def meta_uint(key):
    return parse_artifact_uint(meta.get(key))

pool_intervals = {"fanout": [], "idle-holders": []}
pool_interval_issues = []
pool_interval_file = os.path.join(out, "pool-intervals.tsv")
if os.path.exists(pool_interval_file):
    for line_number, line in enumerate(open(pool_interval_file), 1):
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 3 or fields[0] not in pool_intervals:
            pool_interval_issues.append(
                f"malformed established-pool interval at line {line_number}")
            continue
        start = parse_artifact_epoch(fields[1])
        end = parse_artifact_epoch(fields[2])
        if start is None or end is None or end - start < Decimal("5"):
            pool_interval_issues.append(
                f"invalid established-pool interval at line {line_number}")
            continue
        pool_intervals[fields[0]].append((start, end))

pool_brackets = {}
pool_bracket_issues = []
pool_bracket_file = os.path.join(out, "pool-brackets.tsv")
if os.path.exists(pool_bracket_file):
    for line_number, line in enumerate(open(pool_bracket_file), 1):
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 11 or fields[0] not in pool_intervals:
            pool_bracket_issues.append(
                f"malformed provider flow-pool bracket at line {line_number}")
            continue
        if fields[0] in pool_brackets:
            pool_bracket_issues.append(
                f"duplicate provider flow-pool bracket for {fields[0]!r}")
            continue
        epochs = [parse_artifact_epoch(fields[index]) for index in (1, 4, 7)]
        counts = [
            parse_artifact_uint(fields[index])
            for index in (2, 3, 5, 6, 8, 9, 10)
        ]
        if any(epoch is None for epoch in epochs) or any(
            value is None for value in counts
        ):
            pool_bracket_issues.append(
                f"invalid provider flow-pool bracket at line {line_number}")
            continue
        pool_brackets[fields[0]] = (
            epochs[0], counts[0], counts[1],
            epochs[1], counts[2], counts[3],
            epochs[2], counts[4], counts[5], counts[6],
        )

# Event-local cap values participate in configuration consistency too; checking
# only periodic gauges could bless an episode from another generation/config.
softcap_seen.update(pressure["soft_caps"])
baseline_total = meta_uint("baseline_total")
baseline_registered = meta_uint("baseline_registered")
configured_softcap = meta_uint("softcap")
configured_hardcap = meta_uint("hardcap")
hard_limited_configuration = cap_validation_hard_limited(
    configured_softcap, configured_hardcap,
    baseline_registered, baseline_total)
mode_configuration_issues = []
if hard_limited_configuration is None:
    mode_configuration_issues.append(
        "baseline flow counts conflict with live-flow cap invariants")
elif meta.get("mode") == "cap-validate" and hard_limited_configuration is True:
    mode_configuration_issues.append(
        "cap-validation mode conflicts with effective live-flow hard-cap headroom")
elif (
    meta.get("mode") == "cap-hard-limited"
    and hard_limited_configuration is False
):
    mode_configuration_issues.append(
        "hard-limited mode conflicts with effective live-flow hard-cap headroom")
fanout_status = flow_pool_status(
    meta.get("fanout_established_target_sustained"),
    meta.get("fanout_target"),
    occupancy_samples_per_phase.get("fanout", []),
    gauge_samples_per_phase.get("fanout", []),
    configured_softcap,
    configured_hardcap,
    pool_intervals["fanout"],
    next((p for p in phases if p[0] == "fanout"), None),
    pool_brackets.get("fanout"),
    meta.get("fanout_hold_seconds"),
)
idle_status = flow_pool_status(
    meta.get("idle_holders_established_target_sustained"),
    meta.get("idle_holders_target"),
    occupancy_samples_per_phase.get("idle-holders", []),
    gauge_samples_per_phase.get("idle-holders", []),
    configured_softcap,
    configured_hardcap,
    pool_intervals["idle-holders"],
    next((p for p in phases if p[0] == "idle-holders"), None),
    pool_brackets.get("idle-holders"),
    meta.get("idle_holders_hold_seconds"),
)
meta["fanout_ok"] = fanout_status
meta["idle_holders_ok"] = idle_status

ceiling_records = []
ceiling_parse_issues = []
ceiling_file = os.path.join(out, "ceiling-probes.tsv")
if os.path.exists(ceiling_file):
    with open(ceiling_file) as ceiling_input:
        ceiling_records, ceiling_parse_issues = parse_ceiling_probe_lines(ceiling_input)
ceiling_phase = next((p for p in phases if p[0] == "ceiling"), None)
ceiling_gauges = [
    (epoch, allocated)
    for epoch, _, allocated in gauge_samples_per_phase.get("ceiling", [])
]
ceiling_proof_issues = []
if meta.get("mode") == "find-ceiling":
    ceiling_proof_issues.extend(ceiling_configuration_issues(
        configured_softcap, configured_hardcap))
    ceiling_proof_issues.extend(ceiling_parse_issues)
    ceiling_proof_issues.extend(ceiling_probe_evidence_issues(
        ceiling_records, meta.get("ceiling_found"), baseline_total, ceiling_phase,
        meta.get("ceiling_recovered"), ceiling_gauges,
        allocation_failure_epochs))
ceiling_window = (
    ceiling_outage_window(
        ceiling_records, baseline_total, ceiling_phase, ceiling_gauges,
        allocation_failure_epochs)
    if meta.get("mode") == "find-ceiling" and meta.get("ceiling_found") == "1"
    else None
)
if ceiling_window is not None:
    recorded_window = (
        parse_artifact_epoch(meta.get("ceiling_outage_start")),
        parse_artifact_epoch(meta.get("ceiling_outage_end")),
    )
    if recorded_window != ceiling_window:
        ceiling_proof_issues.append("recorded ceiling outage window does not match direct probes")

sleep_probe_records = []
sleep_probe_issues = []
sleep_result = {"issues": [], "outage_window": None}
if meta.get("mode") != "find-ceiling" and meta.get("post_wake_ok") != "skipped":
    sleep_probe_file = os.path.join(out, "sleep-probes.tsv")
    if os.path.exists(sleep_probe_file):
        with open(sleep_probe_file) as sleep_probe_input:
            sleep_probe_records, sleep_probe_issues = parse_probe_lines(
                sleep_probe_input, "post-wake probe"
            )
    else:
        sleep_probe_issues.append("post-wake probe artifact is missing")
    sleep_phase = next((phase for phase in phases if phase[0] == "sleep-wake"), None)
    sleep_result = sleep_wake_evidence(
        meta.get("sleep_command_ok"),
        meta.get("post_wake_ok"),
        meta.get("sleep_command_start"),
        meta.get("sleep_command_end"),
        [epoch for epoch in sleep_epochs if phase_of(epoch) == "sleep-wake"],
        [epoch for epoch in wake_epochs if phase_of(epoch) == "sleep-wake"],
        sleep_probe_records,
        sleep_phase,
        workload_evidence={
            "started": meta.get("wake_workload_started"),
            "established": meta.get("wake_workload_established"),
            "established_nonzero_bytes": meta.get(
                "wake_workload_established_nonzero_bytes"),
            "established_bytes": meta.get("wake_workload_established_bytes"),
            "http_code": meta.get("wake_workload_http_code"),
            "alive_at_command": meta.get(
                "wake_workload_alive_at_sleep_command"),
            "child_rc": meta.get("wake_workload_child_rc"),
            "joined": meta.get("wake_workload_joined"),
        },
    )

leaks_path = os.path.join(out, "leaks.txt")
try:
    with open(leaks_path, errors="replace") as leak_input:
        leaks_text = leak_input.read()
except FileNotFoundError:
    leaks_text = None
leak_result = leak_evidence(meta.get("leaks_command_rc"), leaks_text)
leak_issues = leak_result["issues"]
leak_count = leak_result["leaks"]

capture_issues = (
    list(ndjson_issues) + provider_source_issues + meta_issues + phase_issues
    + provider_identity_issues + timestamp_issues + probe_issues
    + pool_interval_issues + pool_bracket_issues
    + lifecycle_category_issues + pressure_telemetry_issues + pressure["issues"]
    + numeric_log_issues
    + mode_configuration_issues + ceiling_proof_issues + sleep_probe_issues
    + sleep_result["issues"] + leak_issues
)
for label, status, raw_status in (
    ("fanout", fanout_status, meta.get("fanout_established_target_sustained")),
    ("idle-holders", idle_status, meta.get("idle_holders_established_target_sustained")),
):
    capture_issues.extend(flow_pool_evidence_issues(
        label, raw_status, status, label in pool_brackets))
if generation_events:
    capture_issues.append(
        f"provider engine generation changed ({len(generation_events)} lifecycle event(s))")
if missing_hardcap_gauges:
    capture_issues.append(
        f"{missing_hardcap_gauges} flow-gauge sample(s) omitted hardCap")
if len(softcap_seen) > 1:
    capture_issues.append("flow-pressure soft cap changed during the run")
if len(hardcap_seen) > 1:
    capture_issues.append("live-flow hard cap changed during the run")
if softcap_seen and meta.get("softcap") not in {str(value) for value in softcap_seen}:
    capture_issues.append("baseline soft cap does not match captured gauges")
if hardcap_seen and meta.get("hardcap") not in {str(value) for value in hardcap_seen}:
    capture_issues.append("baseline hard cap does not match captured gauges")
if meta.get("mode") == "find-ceiling":
    required_phases = {"baseline", "ceiling"}
else:
    required_phases = {"baseline", "real-download", "idle-tail"}
    for outcome, phase in (
        ("stress_ok", "stress"),
        ("fanout_established_target_sustained", "fanout"),
        ("idle_holders_established_target_sustained", "idle-holders"),
        ("post_wake_ok", "sleep-wake"),
    ):
        if meta.get(outcome) != "skipped":
            required_phases.add(phase)

evidence_issues = soak_evidence_issues(
    meta,
    rows_count=len(rows),
    gauge_count=n_gauge,
    probe_count=probe_total,
    incomplete_phases=incomplete_phases,
    phase_coverage=(
        (
            name, start, end,
            probe_per_phase.get(name, []),
            gauge_epochs_per_phase.get(name, []),
        )
        for name, start, end in phases
    ),
    required_phases=required_phases,
    capture_issues=capture_issues,
    final_gauge_required=meta.get("mode") != "find-ceiling",
    final_gauge_present=final_gauge is not None,
)
final_total = final_gauge["total"] if final_gauge else None
settlement_tolerance = 5
sc = configured_softcap if configured_softcap is not None else 0
observed_peak = pressure["observed_peak"]
periodic = pressure["periodic"]
episode = pressure["episode"]
reaper_status = pressure_reaper_status(pressure, sc, not evidence_issues)
proved_outage_windows = []
if ceiling_window is not None and ceiling_window[1] is not None and not ceiling_proof_issues:
    proved_outage_windows.append(ceiling_window)
sleep_window = sleep_result["outage_window"]
if sleep_window is not None:
    proved_outage_windows.append(sleep_window)
unexpected_monitor_failures = unexpected_probe_failure_count_across_outages(
    probe_failure_records, proved_outage_windows)
probe_skipped = probe_fail - unexpected_monitor_failures
unexpected_probe_failures = unexpected_monitor_failures + sum(
    1 for probe in sleep_probe_records if not probe_succeeded(probe))
run_result = classify_soak_result(
    meta,
    evidence_issues,
    probe_failures=unexpected_probe_failures,
    body_errors=c["body_err"] + c["relay_drop"],
    reaper_status=reaper_status,
    fanout_failures=fo_bad,
    leak_count=leak_count,
    baseline_total=baseline_total,
    final_total=final_total,
    settlement_tolerance=settlement_tolerance,
    provider_faults=c["fault"],
    unknown_provider_errors=c["unknown_error"],
)
evidence_issues = run_result["evidence_issues"]
evidence_complete = run_result["complete"]
run_passed = run_result["passed"]
run_failures = run_result["failures"]

with open(os.path.join(out, "extract-summary.txt"), "w") as s:
    def w(line=""):
        print(line); s.write(line + "\n")
    w("=== soak extract summary ===")
    w(f"mode:                     {meta.get('mode','?')}")
    w("workload attribution:     aggregate provider correlation for holder pools; "
      "HTTP stress/download traffic is not individually attributed to proxy flows")
    w(f"repository identity:      {meta.get('repo_head','?')} "
      f"({'dirty' if meta.get('repo_dirty') == '1' else 'clean'})")
    w(f"evidence script hashes:   soak={meta.get('soak_script_sha256','?')} "
      f"stress={meta.get('stress_script_sha256','?')} "
      f"parser={meta.get('pressure_parser_sha256','?')}")
    w(f"provider binary SHA-256:  {meta.get('provider_binary_sha256','?')}")
    w(f"provider signing:         {meta.get('provider_codesign_identifier','?')} "
      f"team={meta.get('provider_codesign_team','?')} "
      f"CDHash={meta.get('provider_codesign_cdhash','?')}")
    w(f"ndjson rows parsed:       {len(rows)}")
    w(f"phases:                   {', '.join(p[0] for p in phases) or '(none)'}")
    w(f"softCap (gauge):          {sorted(softcap_seen) or sc}")
    w(f"hardCap (gauge):          {sorted(hardcap_seen) or meta.get('hardcap', '?')}")
    w(f"gauge ticks:              {n_gauge}")
    w(f"sampled peak flows:       tcp={peak_tcp} udp={peak_udp} total={peak_total}")
    w(f"observed event peak:      total={observed_peak}")
    w(f"provider continuity:      {'GOOD' if meta_true('provider_continuous') else 'FAIL'}")
    w(f"evidence completeness:    {'GOOD' if evidence_complete else 'INCONCLUSIVE'}")
    for issue in evidence_issues:
        w(f"  missing: {issue}")
    w(f"run verdict:              {'GOOD' if run_passed else 'FAIL'}")
    for failure in run_failures:
        w(f"  failure: {failure}")
    w("")
    w("--- leak evidence ---")
    if leak_issues:
        w("leaks tool verdict:       INCONCLUSIVE — command/output evidence is incomplete")
    elif leak_count > 0:
        w(f"leaks tool verdict:       FAIL — {leak_count} leaked allocation(s) reported")
    else:
        w("leaks tool verdict:       GOOD — parsed report contains zero leaks")
    w("flow-count settling (baseline-relative; assumes a quiet idle tail):")
    w(f"baseline allocated flows: {baseline_total}")
    w(f"final allocated flows:    {final_total if final_total is not None else 'n/a'}")
    if not evidence_complete:
        w("flow-settlement verdict: INCONCLUSIVE — evidence or provider continuity is incomplete")
    elif final_total is None:
        w("flow-settlement verdict: NOT EVALUATED — ceiling mode has no required idle tail")
    elif final_total <= baseline_total + settlement_tolerance:
        w("flow-settlement verdict: GOOD — allocated flows settled to the "
          f"baseline tolerance ({final_total} ≤ {baseline_total}+{settlement_tolerance})")
    else:
        w("flow-settlement verdict: FAIL — final allocated flows exceeded the "
          f"baseline tolerance ({final_total} > {baseline_total}+{settlement_tolerance})")
    w("")
    w("--- flow-pressure reaper (keyed on emitted log lines) ---")
    w(f"pressure selections:      {pressure['selection_events']}  "
      f"(flows selected: {pressure['selected']})")
    w(f"periodic outcome deltas:  evicted={periodic['evicted']} spared={periodic['spared']} "
      f"canceled={periodic['canceled']} expired={periodic['expired']} "
      f"(intervals: {pressure['periodic_intervals']})")
    w(f"finalized episode totals: evicted={episode['evicted']} spared={episode['spared']} "
      f"canceled={episode['canceled']} expired={episode['expired']} "
      f"(episodes: {pressure['episodes']})")
    w("                          channels overlap and are NOT summed")
    w(f"admit-and-ride (no idle): {c['admit_and_ride']}")
    if sc > 0:
        head = sc - observed_peak
        w(f"peak vs softCap:          observed_peak={observed_peak} softCap={sc} "
          f"({'UNDER by %d' % head if head >= 0 else 'OVER by %d (rode)' % (-head)})")
        if not evidence_complete:
            w("reaper verdict:           INCONCLUSIVE — evidence or provider continuity is incomplete")
        elif reaper_status == "good":
            w("reaper verdict:           GOOD — cap reached and reaper evicted idle flows.")
        elif reaper_status == "crossed-without-attributable-eviction":
            w("reaper verdict:           cap reached with no post-boundary finalized eviction episode;")
            w("                          periodic deltas alone are not attributable to this run.")
        else:
            w("reaper verdict:           cap reach NOT OBSERVED. A between-tick burst can evade sampled")
            w("                          gauges; use a LOW-CAP build and require event/episode evidence.")
    w("")
    w("--- watchdog / drain teardowns ---")
    w(f"drain-backstop fires:     {c['drain_backstop']}")
    w(f"watchdog idle teardowns:  {c['wd_idle']}")
    w(f"watchdog wedged-close:    {c['wd_wedged']}")
    w(f"watchdog stale pre-ready: {c['wd_prerdy']}")
    w("")
    w("--- body-relay / egress health (Firefox 'authenticity' bug detector) ---")
    w(f"body decode/relay errors: {c['body_err']}")
    w(f"MITM relay drops:         {c['relay_drop']}")
    if egress_fail:
        codes = {"50": "Network down", "54": "reset by peer", "60": "timed out", "61": "conn refused"}
        w("egress NWConnection fails: " + ", ".join(
            f"{n}x POSIX {k}({codes.get(k,'?')})" for k, n in sorted(egress_fail.items())))
    if c["body_err"] > 0:
        w("body verdict:             !! response-body decode/relay errors — clients can see truncated/")
        w("                          aborted streams ('authenticity could not be verified'). See timeline.txt.")
    elif not evidence_complete:
        w("body verdict:             INCONCLUSIVE — log coverage or provider continuity is incomplete")
    else:
        w("body verdict:             GOOD — no body decode/relay errors")
    w("")
    w("--- freeze detector (liveness probe; sleep-wake excluded) ---")
    w(f"monitor probes:           {probe_total} (failures {probe_fail}, longest run {max_fail_run}, proved-outage waived {probe_skipped})")
    w(f"post-wake direct probes:  {len(sleep_probe_records)} (failures {sum(1 for probe in sleep_probe_records if not probe_succeeded(probe))})")
    if unexpected_probe_failures > 0:
        w(f"freeze verdict:           !! {unexpected_probe_failures} unexpected probe failures — investigate nexus exhaustion / network blip")
    elif probe_fail > 0:
        w("freeze verdict:           GOOD — failures overlap proved outage window(s)")
    elif not evidence_complete:
        w("freeze verdict:           INCONCLUSIVE — probe coverage or provider continuity is incomplete")
    else:
        w("freeze verdict:           GOOD — proxy stayed live (no freeze)")
    w("")
    w(f"sleep markers: {c['sleep']}   wake markers: {c['wake']}   "
      f"error/fault lines: {c['err']} (unknown Error={c['unknown_error']} Fault={c['fault']})")
    w(f"fanout active outcomes:   ok={fo_ok} failed/non-2xx/truncated={fo_bad}")
    w(f"ceiling active outcomes:  ok={ceiling_fo_ok} candidate-failures={ceiling_fo_bad}")
    w("")
    if phases:
        w("--- per-phase ---")
        w(f"{'phase':<14} {'peak_total':>10} {'ride':>5} {'bodyErr':>8} {'ticks':>6}")
        for name, sp, epe in phases:
            p = ph(name)
            w(f"{name:<14} {p['peak_total']:>10} {p['ride']:>5} "
              f"{p['body_err']:>8} {p['gauge']:>6}")
        w("(eviction deltas are intentionally not phase-attributed: reporting ticks can cross phases)")
    w("")
    w("see flow-counts.txt, timeline.txt, probe-timeline.txt, holders.log, leaks.txt")

status_path = os.path.join(out, "evidence-status.tsv")
status_tmp = status_path + f".tmp.{os.getpid()}"
with open(status_tmp, "w") as status:
    status.write(f"complete\t{1 if evidence_complete else 0}\n")
    status.write(f"passed\t{1 if run_passed else 0}\n")
    status.write(f"exit_code\t{run_result['exit_code']}\n")
    for issue in evidence_issues:
        status.write(f"issue\t{issue}\n")
    for failure in run_failures:
        status.write(f"failure\t{failure}\n")
    status.write("schema_complete\t1\n")
    status.flush()
    os.fsync(status.fileno())
os.replace(status_tmp, status_path)
PYEOF
  then
    :
  else
    warn "evidence extractor failed — preserving artifacts with an incomplete verdict"
    write_incomplete_status "evidence extractor failed"
  fi
else
  warn "python3 not found — falling back to grep"
  grep -oE 'live-flow counts[^"]*' "$OUT/system.ndjson" > "$OUT/flow-counts.txt" 2>/dev/null || true
  grep -iE 'flow pressure|drain backstop|force-tear|brotli error|drop MITM relay|system sleep|system wake' \
    "$OUT/system.ndjson" > "$OUT/timeline.txt" 2>/dev/null || true
  write_incomplete_status "python3 unavailable"
fi

# ── Bundle ────────────────────────────────────────────────────────────
hdr "done"
TARBALL="$OUT.tgz"
if tar -czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null; then
  say "tarball:   $TARBALL"
else
  warn "could not create tarball"
fi
say "dir:       $OUT"
echo
[[ -f "$OUT/extract-summary.txt" ]] && cat "$OUT/extract-summary.txt"
echo
hdr "hand me: $OUT  (or the tarball)"
STATUS_LAST="$(awk 'NF { line=$0 } END { print line }' "$OUT/evidence-status.tsv" 2>/dev/null)"
STATUS_ORDER="$(awk -F '\t' 'NF { print $1; seen++; if (seen == 3) exit }' "$OUT/evidence-status.tsv" 2>/dev/null | paste -sd ' ' -)"
STATUS_KEYS="$(awk -F '\t' '$1 == "complete" || $1 == "passed" || $1 == "exit_code" || $1 == "schema_complete" { count[$1]++ } END { print count["complete"]+0, count["passed"]+0, count["exit_code"]+0, count["schema_complete"]+0 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
STATUS_DIAGNOSTICS="$(awk -F '\t' '$1 == "issue" { issues++ } $1 == "failure" { failures++ } END { print issues+0, failures+0 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
STATUS_BAD_LINES="$(awk -F '\t' 'NF && (NF != 2 || ($1 != "complete" && $1 != "passed" && $1 != "exit_code" && $1 != "issue" && $1 != "failure" && $1 != "schema_complete")) { bad++ } END { print bad+0 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
EVIDENCE_COMPLETE="$(awk -F '\t' '$1 == "complete" { print $2 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
RUN_PASSED="$(awk -F '\t' '$1 == "passed" { print $2 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
DECLARED_EXIT="$(awk -F '\t' '$1 == "exit_code" { print $2 }' "$OUT/evidence-status.tsv" 2>/dev/null)"
read -r STATUS_ISSUES STATUS_FAILURES <<< "$STATUS_DIAGNOSTICS"
if [[ "$STATUS_LAST" != $'schema_complete\t1' \
  || "$STATUS_ORDER" != "complete passed exit_code" \
  || "$STATUS_KEYS" != "1 1 1 1" || "$STATUS_BAD_LINES" != 0 ]]; then
  warn "evidence status is truncated or schema-incomplete"
  exit 2
fi
case "$EVIDENCE_COMPLETE:$RUN_PASSED:$DECLARED_EXIT" in
  1:1:0)
    (( STATUS_ISSUES == 0 && STATUS_FAILURES == 0 )) || {
      warn "successful evidence verdict contains issue/failure diagnostics"
      exit 2
    }
    exit 0
    ;;
  1:0:1)
    (( STATUS_ISSUES == 0 && STATUS_FAILURES > 0 )) || {
      warn "failed evidence verdict lacks a consistent failure diagnostic"
      exit 2
    }
    warn "soak evidence is complete, but one or more validation checks failed; see evidence-status.tsv"
    exit 1
    ;;
  0:0:2)
    (( STATUS_ISSUES > 0 )) \
      || warn "incomplete evidence verdict lacks an issue diagnostic"
    warn "soak completed, but evidence is incomplete; see evidence-status.tsv"
    exit 2
    ;;
  *)
    warn "evidence status contains an inconsistent verdict tuple"
    exit 2
    ;;
esac
