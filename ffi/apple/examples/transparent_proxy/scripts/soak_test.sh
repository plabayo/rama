#!/usr/bin/env bash
# soak_test.sh — one comprehensive live session for the rama Apple NE
# transparent proxy. Drives a battery of phases back-to-back and bundles
# everything that tells us whether the lifetime / leak / wake / flow-pressure
# fixes hold, into a single artifact dir (+ tarball) to hand back.
#
# It AUTO-DETECTS the running build's flow-pressure soft cap from the gauge
# log line ("… softCap=N") and adapts:
#   softCap > 0  → CAP-VALIDATE: push live-flow count toward / past the cap and
#                  prove the invariants hold — peak stays bounded, the reaper
#                  evicts idle flows (or rides when none are idle), NO machine
#                  freeze, and active downloads complete intact (no dropped
#                  user connection).
#   softCap == 0 → (only with FIND_CEILING=1) CEILING-FINDER: carefully ramp
#                  concurrency until the kernel nexus allocation is exhausted,
#                  report the gauge peak at that point = the real ceiling, then
#                  back off to recover the machine.
#
# Phases (default giant session, cap ON):
#   0  baseline      detect softCap, baseline mem + gauge
#   1  stress        the mixed stress_traffic.sh burst (connect/relay churn)
#   2  fanout        high-concurrency slow downloads toward the cap
#                    (active flows → exercises admit-and-ride + no active drop)
#   3  idle-holders  sustain a pool of established-but-idle flows + keep
#                    admitting (→ exercises the idle-eviction reaper)
#   4  real-download steady large download
#   5  sleep/wake    the original wake-bug scenario (TTY only)
#   6  idle-tail     drain to 0 so the 60s gauge ticks empty (leak signal)
#   then: final mem snapshot, leaks pass, dial9 traces, signal extraction.
#
# What it captures (in OUT/):
#   system.ndjson        full debug-level os_log stream for the sysext
#   flow-counts.txt      the 60s "live-flow counts" gauge timeline (PRIMARY
#                        leak + pressure signal)
#   phases.tsv           wall-clock start/end of every phase (epoch + iso)
#   timeline.txt         lifecycle / sleep / wake / reaper / error lines
#   extract-summary.txt  peak vs cap, reaper/evict/ride/idle-timeout tallies,
#                        per-phase gauge, close verdicts, drain verdict
#   stress/              per-worker logs + preflight/postflight vmmap+heap
#   fanout.txt           per-worker integrity of the high-concurrency burst
#   holders.log          idle-holder pool timeline
#   probe-timeline.txt    periodic liveness probe (freeze detector)
#   final-mem.txt        ps/vmmap/heap AFTER the idle tail
#   leaks.txt            `leaks` pass on the live sysext
#   dial9-traces/        per-flow egress dial traces
#
# Usage (run from anywhere):
#   bash scripts/soak_test.sh
#   FIND_CEILING=1 bash scripts/soak_test.sh      # only on a softCap=0 build!
#
# Requires: the dev proxy already enabled in the container app (or DO_INSTALL=1
# to build+install+open it first), and sudo.
#
# Env knobs (all optional):
#   REPO            repo root. Default: /Users/glendc/code/github.com/plabayo/rama
#   OUT             artifact dir. Default: ~/rama-tproxy-soak/<timestamp>
#   DO_INSTALL      1 = `just install-tproxy-dev` first. Default 0.
#   STRESS_SECONDS  phase-1 stress duration. Default 180.
#   CONCURRENCY     phase-1 stress pool size. Default 24.
#   FANOUT_TARGET   phase-2 concurrent slow downloads. Default auto
#                   (softCap + 25%, clamped to [40, MAX_FANOUT]).
#   FANOUT_HOLD     phase-2 hold seconds. Default 100.
#   FANOUT_RATE     phase-2 per-curl rate cap (keeps flows alive+slow). Default 48k.
#   MAX_FANOUT      hard ceiling on phase-2 concurrency. Default 700.
#   IDLE_TARGET     phase-3 concurrent idle holders. Default auto (= FANOUT_TARGET).
#   IDLE_HOLD       phase-3 sustain seconds. Default 200.
#   HOLD_HOST       idle-holder target host. Default the probe host.
#   MAX_HOLDERS     hard ceiling on phase-3 holders. Default 700.
#   SKIP_STRESS / SKIP_FANOUT / SKIP_IDLE   1 = skip that phase. Default 0.
#   SKIP_SLEEP      1 = skip sleep/wake. Default 0.
#   IDLE_TAIL       trailing idle seconds (≥1 gauge tick at 0 flows). Default 95.
#   WAKE_DL_BYTES   sleep/wake mid-flight download bytes. Default 1 GiB.
#   REAL_DL_BYTES   phase-4 download bytes. Default 256 MiB.
#   FIND_CEILING    1 = ceiling-finder (DANGEROUS; softCap=0 build only). Default 0.
#   CEIL_STEP       ceiling-finder ramp step (flows added per round). Default 40.
#   CEIL_SETTLE     ceiling-finder seconds between ramp rounds. Default 8.
#   ASSUME_YES      1 = skip the interactive ceiling-finder confirmation. Default 0.

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────
REPO="${REPO:-/Users/glendc/code/github.com/plabayo/rama}"
EXAMPLE_DIR="$REPO/ffi/apple/examples/transparent_proxy"
STRESS_SH="$EXAMPLE_DIR/scripts/stress_traffic.sh"
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"
SUBSYSTEM_PREFIX="org.ramaproxy.example.tproxy"
HTTPS_PROBE="https://http-test.ramaproxy.org/method"
DL_URL_BASE="https://speed.cloudflare.com/__down?bytes="
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$HOME/rama-tproxy-soak/$STAMP}"
DO_INSTALL="${DO_INSTALL:-0}"
STRESS_SECONDS="${STRESS_SECONDS:-180}"
CONCURRENCY="${CONCURRENCY:-24}"
FANOUT_TARGET="${FANOUT_TARGET:-0}"     # 0 = auto from softCap
FANOUT_HOLD="${FANOUT_HOLD:-100}"
FANOUT_RATE="${FANOUT_RATE:-48k}"
MAX_FANOUT="${MAX_FANOUT:-700}"
IDLE_TARGET="${IDLE_TARGET:-0}"          # 0 = auto (= FANOUT_TARGET)
IDLE_HOLD="${IDLE_HOLD:-200}"
HOLD_HOST="${HOLD_HOST:-http-test.ramaproxy.org}"
MAX_HOLDERS="${MAX_HOLDERS:-700}"
SKIP_STRESS="${SKIP_STRESS:-0}"
SKIP_FANOUT="${SKIP_FANOUT:-0}"
SKIP_IDLE="${SKIP_IDLE:-0}"
SKIP_SLEEP="${SKIP_SLEEP:-0}"
IDLE_TAIL="${IDLE_TAIL:-95}"
WAKE_DL_BYTES="${WAKE_DL_BYTES:-1073741824}"   # 1 GiB
REAL_DL_BYTES="${REAL_DL_BYTES:-268435456}"    # 256 MiB
FIND_CEILING="${FIND_CEILING:-0}"
CEIL_STEP="${CEIL_STEP:-40}"
CEIL_SETTLE="${CEIL_SETTLE:-8}"
ASSUME_YES="${ASSUME_YES:-0}"

LOG_MATCH='log stream --level debug.*ramaproxy'
LOGBUF=""; command -v stdbuf >/dev/null 2>&1 && LOGBUF="stdbuf -oL"

# ── Pretty output ─────────────────────────────────────────────────────
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YEL=$'\e[33m'
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YEL=""
fi
say()  { printf '%s[soak]%s %s\n' "$DIM" "$RESET" "$*"; }
hdr()  { printf '\n%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$*" "$RESET"; }
warn() { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$YEL" "$*" "$RESET"; }
die()  { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$RED" "$*" "$RESET" >&2; exit 1; }

# Fail loud on a non-numeric knob rather than a confusing partial run.
for _n in STRESS_SECONDS CONCURRENCY FANOUT_TARGET FANOUT_HOLD MAX_FANOUT \
          IDLE_TARGET IDLE_HOLD MAX_HOLDERS IDLE_TAIL WAKE_DL_BYTES \
          REAL_DL_BYTES CEIL_STEP CEIL_SETTLE; do
  _v="${!_n}"
  [[ "$_v" =~ ^[0-9]+$ ]] || die "$_n must be a non-negative integer (got '$_v')"
done
[[ "$FANOUT_RATE" =~ ^[0-9]+k?$ ]] || die "FANOUT_RATE must be an integer, optionally k-suffixed (got '$FANOUT_RATE')"

# ── Teardown ──────────────────────────────────────────────────────────
LOG_STREAM_STARTED=0
SUDO_KEEPALIVE_PID=""
PROBE_MON_PID=""
HOLDER_PIDFILE=""
kill_holders() {
  # Kill every idle holder we launched (pidfile is the source of truth; the
  # pattern kill is a scoped backup in case a pid was reused).
  if [[ -n "$HOLDER_PIDFILE" && -f "$HOLDER_PIDFILE" ]]; then
    while read -r _p; do [[ -n "$_p" ]] && kill "$_p" 2>/dev/null || true; done < "$HOLDER_PIDFILE"
    : > "$HOLDER_PIDFILE"
  fi
  pkill -f "s_client -connect $HOLD_HOST" 2>/dev/null || true
}
cleanup() {
  [[ -n "$PROBE_MON_PID" ]] && kill "$PROBE_MON_PID" 2>/dev/null || true
  kill_holders
  [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  if (( LOG_STREAM_STARTED )); then
    sudo pkill -f "$LOG_MATCH" 2>/dev/null || true
  fi
  local _j; _j="$(jobs -p 2>/dev/null)"
  [[ -n "$_j" ]] && kill $_j 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Helpers ───────────────────────────────────────────────────────────
# Probe the proxy once; echo the HTTP code (empty/000 on failure).
probe_once() {
  curl -s -o /dev/null --max-time 12 -w '%{http_code}' "$HTTPS_PROBE" 2>/dev/null || true
}
probe_ok() { [[ "$(probe_once)" =~ ^2 ]]; }

# Record a phase boundary: phase_mark NAME start|end
phase_mark() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(date +%s)" "$(date -u +%FT%TZ)" >> "$OUT/phases.tsv"
}

# Read the most recent softCap / tcp / udp / total from the live gauge in the
# ndjson capture. Echoes "softcap tcp udp total" or "" if no tick yet.
read_gauge() {
  grep -oE 'live-flow counts tcp=[0-9]+ udp=[0-9]+ total=[0-9]+ peak=[0-9]+ softCap=[0-9]+' \
    "$OUT/system.ndjson" 2>/dev/null | tail -1 \
    | sed -E 's/.*tcp=([0-9]+) udp=([0-9]+) total=([0-9]+) peak=[0-9]+ softCap=([0-9]+)/\4 \1 \2 \3/'
}

# Wait up to $1 seconds for the first gauge tick; echo softCap (or "").
wait_for_gauge() {
  local deadline=$(( $(date +%s) + $1 )) g
  while (( $(date +%s) < deadline )); do
    g="$(read_gauge)"
    if [[ -n "$g" ]]; then echo "${g%% *}"; return 0; fi
    sleep 3
  done
  echo ""
}

# Background liveness sampler: one probe every 5s → probe-timeline.txt. This is
# the freeze detector — a run of failures means new flows can't open (likely
# nexus exhaustion / machine freeze).
start_probe_monitor() {
  ( while true; do
      printf '%s\t%s\t%s\n' "$(date +%s)" "$(date -u +%FT%TZ)" "$(probe_once)" >> "$OUT/probe-timeline.txt"
      sleep 5
    done ) &
  PROBE_MON_PID=$!
}

# ── Preconditions ─────────────────────────────────────────────────────
hdr "rama transparent proxy soak — comprehensive single session"
[[ -x "$(command -v curl)" ]] || die "curl not found"
[[ -x "$(command -v openssl)" ]] || warn "openssl not found — idle-holder phase will be skipped"
[[ -f "$STRESS_SH" ]] || die "stress script not found at $STRESS_SH (is REPO correct?)"
mkdir -p "$OUT" || die "cannot create OUT=$OUT"
: > "$OUT/phases.tsv"
HOLDER_PIDFILE="$OUT/holders.pids"; : > "$HOLDER_PIDFILE"

# Raise our own fd limit so a big fanout/holder pool can't hit EMFILE.
ulimit -n 16384 2>/dev/null || true

say "artifacts:   $OUT"
say "stress:      ${STRESS_SECONDS}s @ concurrency $CONCURRENCY"
say "fanout:      target $([[ "$FANOUT_TARGET" == 0 ]] && echo auto || echo "$FANOUT_TARGET"), hold ${FANOUT_HOLD}s, rate $FANOUT_RATE"
say "idle hold:   target $([[ "$IDLE_TARGET" == 0 ]] && echo auto || echo "$IDLE_TARGET") → $HOLD_HOST, sustain ${IDLE_HOLD}s"
say "sleep/wake:  $([[ "$SKIP_SLEEP" == 1 ]] && echo skipped || echo enabled)"
say "idle tail:   ${IDLE_TAIL}s"
(( FIND_CEILING )) && warn "FIND_CEILING=1 — ceiling-finder ARMED (only valid on a softCap=0 build)"

# Cache sudo + keep it warm.
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
[[ "$PROBE_CODE" =~ ^2 ]] || die "probe got '$PROBE_CODE' against $HTTPS_PROBE — proxy not intercepting, sysext down, or no network. Enable the proxy (or DO_INSTALL=1) and retry."
say "${GREEN}probe ok ($PROBE_CODE) — traffic is flowing through the proxy${RESET}"

PID="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
[[ -n "$PID" ]] || die "could not find the sysext process ($PROVIDER_BUNDLE). Is it enabled?"
say "sysext pid:  $PID"

# ── Start live log capture (debug — the gauge is debug) ────────────────
hdr "starting log capture"
sudo $LOGBUF log stream --level debug --style ndjson \
  --predicate "subsystem BEGINSWITH \"$SUBSYSTEM_PREFIX\"" \
  > "$OUT/system.ndjson" 2>/dev/null &
LOG_STREAM_STARTED=1
sleep 2
pgrep -f "$LOG_MATCH" >/dev/null || warn "log stream may not have started — system.ndjson could be empty"
say "streaming → $OUT/system.ndjson"
start_probe_monitor
say "probe monitor → $OUT/probe-timeline.txt (freeze detector)"

# ── Phase 0: baseline + softCap detection ─────────────────────────────
phase_mark baseline start
hdr "phase 0 — baseline (detecting softCap from the gauge; ≤65s)"
SOFTCAP="$(wait_for_gauge 65)"
if [[ -z "$SOFTCAP" ]]; then
  warn "no gauge tick seen in 65s — proceeding without auto-detect (cap verdicts limited)"
  SOFTCAP_KNOWN=0; SOFTCAP=0
else
  SOFTCAP_KNOWN=1
  say "detected ${BOLD}softCap=$SOFTCAP${RESET} (live-flow gauge)"
fi

# Resolve mode.
MODE="cap-validate"
if (( FIND_CEILING )); then
  if (( SOFTCAP_KNOWN )) && (( SOFTCAP != 0 )); then
    die "FIND_CEILING=1 but softCap=$SOFTCAP — the cap would reap before the ceiling. Rebuild with defaultFlowPressureSoftCap=0 to find the raw ceiling."
  fi
  MODE="find-ceiling"
elif (( SOFTCAP_KNOWN )) && (( SOFTCAP == 0 )); then
  warn "softCap=0 (cap DISABLED) but FIND_CEILING!=1 — running stress only; pass FIND_CEILING=1 to ramp to the ceiling."
  MODE="stress-only"
fi
say "mode:        ${BOLD}$MODE${RESET}"

# Derive auto target from softCap (+25% to cross the cap), floored at 40.
auto_target() {
  local base=200
  (( SOFTCAP_KNOWN )) && (( SOFTCAP > 0 )) && base=$(( SOFTCAP + SOFTCAP / 4 ))
  (( base < 40 )) && base=40
  echo "$base"
}
(( FANOUT_TARGET == 0 )) && FANOUT_TARGET="$(auto_target)"
(( FANOUT_TARGET > MAX_FANOUT )) && { warn "FANOUT_TARGET clamped to MAX_FANOUT=$MAX_FANOUT"; FANOUT_TARGET=$MAX_FANOUT; }
(( IDLE_TARGET == 0 )) && IDLE_TARGET=$FANOUT_TARGET
(( IDLE_TARGET > MAX_HOLDERS )) && { warn "IDLE_TARGET clamped to MAX_HOLDERS=$MAX_HOLDERS"; IDLE_TARGET=$MAX_HOLDERS; }

# Run metadata the summary parser keys its verdicts off.
{
  printf 'softcap\t%s\n' "$SOFTCAP"
  printf 'softcap_known\t%s\n' "$SOFTCAP_KNOWN"
  printf 'mode\t%s\n' "$MODE"
  printf 'fanout_target\t%s\n' "$FANOUT_TARGET"
  printf 'idle_target\t%s\n' "$IDLE_TARGET"
} > "$OUT/run-meta.tsv"

{
  printf '=== baseline @ %s ===\n' "$(date -u +%FT%TZ)"
  printf 'softCap=%s mode=%s fanout_target=%s idle_target=%s\n\n' "$SOFTCAP" "$MODE" "$FANOUT_TARGET" "$IDLE_TARGET"
  ps -o pid,rss,vsz,%cpu,state -p "$PID" 2>/dev/null || echo "pid gone"
  printf '\n--- vmmap --summary ---\n'
  sudo -n vmmap --summary "$PID" 2>/dev/null || echo "vmmap unavailable"
} > "$OUT/baseline-mem.txt" 2>&1
phase_mark baseline end

# ════════════════ CEILING-FINDER (opt-in, softCap=0 only) ═════════════
if [[ "$MODE" == "find-ceiling" ]]; then
  phase_mark ceiling start
  hdr "CEILING-FINDER"
  warn "This deliberately exhausts the kernel nexus-flow allocation."
  warn "It can briefly FREEZE ALL networking on this Mac. The script backs"
  warn "off + kills load the instant the liveness probe fails, but expect a"
  warn "stall. Do not run on a machine doing anything important."
  if [[ -t 0 && "$ASSUME_YES" != 1 ]]; then
    printf '%s[soak]%s type CEILING to proceed: ' "$DIM" "$RESET"; read -r _ans
    [[ "$_ans" == "CEILING" ]] || die "aborted"
  fi
  command -v openssl >/dev/null 2>&1 || die "ceiling-finder needs openssl"

  launched=0; last_good=0; ceiling=0
  while (( launched < MAX_HOLDERS )); do
    for ((i=0; i<CEIL_STEP && launched<MAX_HOLDERS; i++)); do
      openssl s_client -connect "$HOLD_HOST:443" -servername "$HOLD_HOST" -quiet \
        </dev/null >/dev/null 2>&1 &
      echo $! >> "$HOLDER_PIDFILE"
      launched=$((launched+1))
    done
    sleep "$CEIL_SETTLE"
    g="$(read_gauge)"; occ="${g##* }"; [[ -z "$occ" ]] && occ="?"
    if probe_ok; then
      last_good="$occ"
      say "ramp: launched=$launched gauge_total=$occ probe=OK"
    else
      ceiling="$occ"
      warn "probe FAILED at launched=$launched gauge_total=$occ — likely the ceiling. Backing off."
      break
    fi
  done
  (( launched >= MAX_HOLDERS )) && warn "hit MAX_HOLDERS=$MAX_HOLDERS without a probe failure — ceiling is higher; raise MAX_HOLDERS."
  say "killing holders to recover the machine..."
  kill_holders
  # Wait for recovery.
  for i in $(seq 1 20); do probe_ok && { say "${GREEN}recovered (probe ok)${RESET}"; break; }; sleep 3; done
  {
    printf 'ceiling-finder result\n'
    printf 'last gauge_total with probe OK: %s\n' "$last_good"
    printf 'gauge_total at first probe FAIL: %s\n' "${ceiling:-none}"
    printf 'launched holders: %s (max %s)\n' "$launched" "$MAX_HOLDERS"
    printf '\nset defaultFlowPressureSoftCap to ~70%% and lowWater ~55%% of the ceiling.\n'
  } | tee "$OUT/ceiling.txt"
  phase_mark ceiling end
else

# ════════════════ CAP-VALIDATE / STRESS battery ══════════════════════

# ── Phase 1: stress traffic ───────────────────────────────────────────
if [[ "$SKIP_STRESS" != 1 ]]; then
  phase_mark stress start
  hdr "phase 1 — stress traffic (${STRESS_SECONDS}s @ $CONCURRENCY)"
  STRESS_DURATION="$STRESS_SECONDS" \
  STRESS_CONCURRENCY="$CONCURRENCY" \
  STRESS_MONITOR_PID="$PID" \
  STRESS_LOG_DIR="$OUT/stress" \
  STRESS_SKIP_LIVENESS=1 \
    bash "$STRESS_SH" | tee "$OUT/stress-run.txt" || warn "stress run returned nonzero"
  phase_mark stress end
fi

# ── Phase 2: fanout burst (active flows toward the cap) ───────────────
if [[ "$SKIP_FANOUT" != 1 ]]; then
  phase_mark fanout start
  hdr "phase 2 — fanout: $FANOUT_TARGET slow downloads (hold ${FANOUT_HOLD}s, rate $FANOUT_RATE)"
  say "active flows toward softCap=$SOFTCAP → exercises admit-and-ride + active-drop check"
  # Big enough that --limit-rate keeps each flow alive for the whole hold.
  # Size each download so --limit-rate keeps the flow alive for the whole hold.
  rate_bps="${FANOUT_RATE%k}"; [[ "$FANOUT_RATE" == *k ]] && rate_bps=$(( rate_bps * 1024 ))
  fbytes=$(( rate_bps * (FANOUT_HOLD + 60) ))
  fanout_pids=()
  for ((i=1; i<=FANOUT_TARGET; i++)); do
    curl -s -o /dev/null --limit-rate "$FANOUT_RATE" --max-time "$((FANOUT_HOLD + 30))" \
      -w '%{http_code} %{size_download} %{time_total}\n' "$DL_URL_BASE$fbytes" \
      >> "$OUT/fanout.txt" 2>&1 &
    fanout_pids+=("$!")
  done
  say "launched $FANOUT_TARGET concurrent downloads; holding ${FANOUT_HOLD}s..."
  for ((t=FANOUT_HOLD; t>0; t-=5)); do
    g="$(read_gauge)"; printf '\r[soak] fanout %3ds left  gauge_total=%s   ' "$t" "${g##* }"
    probe_ok || warn "probe failed during fanout (occupancy=${g##* }) — watch for freeze"
    sleep 5
  done
  printf '\r%-60s\r' ' '
  say "draining fanout downloads..."
  # Kill ONLY the fanout curls (never the log-capture / probe-monitor / sudo
  # jobs), then reap just those pids (a bare `wait` would block on the
  # infinite-loop infra jobs forever). Record how many were still running when
  # we cut them: those are OUR teardown, not proxy-dropped connections — the
  # parser must not score them as failures (or successes).
  if (( ${#fanout_pids[@]} > 0 )); then
    fterm=0
    for p in "${fanout_pids[@]}"; do
      if kill -0 "$p" 2>/dev/null; then fterm=$((fterm+1)); kill "$p" 2>/dev/null || true; fi
    done
    printf 'terminated-by-script %d\n' "$fterm" >> "$OUT/fanout.txt"
    wait "${fanout_pids[@]}" 2>/dev/null || true
    say "fanout: terminated $fterm still-running downloads at hold-end (expected)"
  fi
  phase_mark fanout end
fi

# ── Phase 3: idle-holder pool (idle flows → eviction reaper) ──────────
if [[ "$SKIP_IDLE" != 1 ]] && command -v openssl >/dev/null 2>&1; then
  phase_mark idle-holders start
  hdr "phase 3 — idle holders: sustain $IDLE_TARGET established-idle flows for ${IDLE_HOLD}s"
  say "each holder TLS-handshakes $HOLD_HOST then goes silent → ages toward the idle floor"
  warn "NOTE: real servers close idle conns in ~30-75s. Observing the EVICTION reaper"
  warn "reliably needs holders to outlive the build's idle floor — best on a short-floor"
  warn "build (defaultFlowPressureIdleFloorMs small). On the prod 120s floor expect"
  warn "mostly admit-and-ride. This phase reports honestly either way."
  : > "$OUT/holders.log"
  spawn_holder() {
    openssl s_client -connect "$HOLD_HOST:443" -servername "$HOLD_HOST" -quiet \
      </dev/null >/dev/null 2>&1 &
    echo $! >> "$HOLDER_PIDFILE"
  }
  end=$(( $(date +%s) + IDLE_HOLD ))
  while (( $(date +%s) < end )); do
    # Prune dead pids, count live ones, top back up to target (each spawn is a
    # fresh admission → triggers the reaper when occupancy >= softCap).
    live=0; tmp="$OUT/.pids.tmp"; : > "$tmp"
    while read -r p; do
      [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null && { echo "$p" >> "$tmp"; live=$((live+1)); }
    done < "$HOLDER_PIDFILE"
    mv "$tmp" "$HOLDER_PIDFILE"
    while (( live < IDLE_TARGET )); do spawn_holder; live=$((live+1)); done
    g="$(read_gauge)"
    printf '%s\tlive_holders=%s\tgauge_total=%s\n' "$(date -u +%FT%TZ)" "$live" "${g##* }" >> "$OUT/holders.log"
    printf '\r[soak] idle holders live=%s gauge_total=%s  %ds left   ' "$live" "${g##* }" "$(( end - $(date +%s) ))"
    probe_ok || warn "probe failed during idle-hold (occupancy=${g##* })"
    sleep 6
  done
  printf '\r%-60s\r' ' '
  say "tearing down idle holders..."
  kill_holders
  sleep 3
  phase_mark idle-holders end
fi

# ── Phase 4: steady real-world download ───────────────────────────────
phase_mark real-download start
hdr "phase 4 — real-world download (${REAL_DL_BYTES} bytes)"
curl -L -s -o /dev/null --max-time 240 \
  -w 'real-download: code=%{http_code} size=%{size_download} avg=%{speed_download}B/s time=%{time_total}s\n' \
  "$DL_URL_BASE$REAL_DL_BYTES" 2>&1 \
  | tee "$OUT/real-download.txt" || warn "real download failed (non-fatal)"
phase_mark real-download end

# ── Phase 5: sleep / wake ─────────────────────────────────────────────
if [[ "$SKIP_SLEEP" == 1 || ! -t 0 ]]; then
  hdr "phase 5 — sleep/wake (SKIPPED)"
  [[ ! -t 0 && "$SKIP_SLEEP" != 1 ]] && warn "no TTY — skipping sleep/wake (needs a manual wake)"
else
  phase_mark sleep-wake start
  hdr "phase 5 — sleep/wake"
  warn "This will put the Mac to SLEEP. A download will be in flight."
  warn "WAKE THE MAC MANUALLY (keypress / lid) ~45s after it sleeps."
  printf '%s[soak]%s press Enter to start (or Ctrl-C to abort)... ' "$DIM" "$RESET"
  read -r _
  say "starting 1 GiB download in the background..."
  ( curl -L -s -o /dev/null --max-time 600 \
      -w 'wake-download: code=%{http_code} size=%{size_download} time=%{time_total}s\n' \
      "$DL_URL_BASE$WAKE_DL_BYTES" > "$OUT/wake-download.txt" 2>&1 ) &
  WAKE_DL_PID=$!
  sleep 8
  warn ">>> SLEEPING NOW — wake the Mac manually in ~45s <<<"
  sudo pmset sleepnow || warn "pmset sleepnow failed"
  sleep 5
  sudo -v 2>/dev/null || true
  say "awake — probing connectivity..."
  for i in 1 2 3; do
    WCODE="$(probe_once)"
    printf 'post-wake probe %d: %s\n' "$i" "$WCODE" | tee -a "$OUT/post-wake.txt"
    [[ "$WCODE" =~ ^2 ]] && break
    sleep 3
  done
  if [[ "${WCODE:-}" =~ ^2 ]]; then
    say "${GREEN}post-wake: traffic recovered ($WCODE)${RESET}"
  else
    warn "post-wake: traffic did NOT recover (last code '$WCODE') — this is the bug we're hunting"
  fi
  sleep 5
  kill "$WAKE_DL_PID" 2>/dev/null || true
  [[ -f "$OUT/wake-download.txt" ]] && cat "$OUT/wake-download.txt"
  phase_mark sleep-wake end
fi

# ── Phase 6: idle tail ────────────────────────────────────────────────
phase_mark idle-tail start
hdr "phase 6 — idle ${IDLE_TAIL}s (waiting for flows to drain to 0)"
for ((t=IDLE_TAIL; t>0; t-=5)); do printf '\r[soak] idle %3ds remaining' "$t"; sleep 5; done
printf '\r%-40s\r' ' '
phase_mark idle-tail end

fi  # end cap-validate vs ceiling-finder

# ── Final memory snapshot (re-resolve pid; detect a restart) ──────────
hdr "final memory snapshot"
PID2="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
if [[ -z "$PID2" ]]; then
  warn "sysext process is GONE after the run (crashed or uninstalled)"
elif [[ "$PID2" != "$PID" ]]; then
  warn "sysext RESTARTED during the run: $PID → $PID2 (watchdog churn / crash — itself a signal)"
fi
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
sudo leaks "$SNAP_PID" > "$OUT/leaks.txt" 2>&1 || true
LEAK_LINE="$(grep -E 'leaks for|total leaked|Process .* leaks' "$OUT/leaks.txt" 2>/dev/null | head -1)"
say "${LEAK_LINE:-(see leaks.txt)}"

# ── Stop log capture ──────────────────────────────────────────────────
hdr "stopping log capture"
[[ -n "$PROBE_MON_PID" ]] && kill "$PROBE_MON_PID" 2>/dev/null || true; PROBE_MON_PID=""
sudo pkill -f "$LOG_MATCH" 2>/dev/null || true
LOG_STREAM_STARTED=0
sleep 1
NDJSON_LINES="$(wc -l < "$OUT/system.ndjson" 2>/dev/null | tr -d ' ' || echo 0)"
say "captured $NDJSON_LINES ndjson lines"

# ── dial9 traces ──────────────────────────────────────────────────────
hdr "collecting dial9 traces"
if sudo -n test -d "$DIAL9_DIR" 2>/dev/null; then
  sudo cp -R "$DIAL9_DIR" "$OUT/dial9-traces" 2>/dev/null \
    && sudo chown -R "$(whoami)" "$OUT/dial9-traces" 2>/dev/null \
    && say "→ $OUT/dial9-traces ($(find "$OUT/dial9-traces" -type f | wc -l | tr -d ' ') files)" \
    || warn "could not copy dial9 traces"
else
  say "(no dial9 traces present)"
fi

# ── Extract the signals that matter from the ndjson ───────────────────
hdr "extracting signals"
PYX="$(command -v python3 || true)"
if [[ -n "$PYX" ]]; then
  "$PYX" - "$OUT" <<'PYEOF'
import json, os, re, sys
from datetime import datetime, timezone

out = sys.argv[1]
nd = os.path.join(out, "system.ndjson")

# Phase windows: name -> [start_epoch, end_epoch]
phases = []
pf = os.path.join(out, "phases.tsv")
if os.path.exists(pf):
    starts = {}
    with open(pf) as f:
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            name, kind, epoch = parts[0], parts[1], parts[2]
            try:
                e = int(epoch)
            except ValueError:
                continue
            if kind == "start":
                starts[name] = e
            elif kind == "end" and name in starts:
                phases.append([name, starts[name], e])

def phase_of(ep):
    if ep is None:
        return "?"
    for name, s, e in phases:
        if s <= ep <= e:
            return name
    return "-"

def to_epoch(ts):
    # os_log ndjson: "2026-06-12 19:47:53.179000-0700"
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
    except Exception:
        try:
            return datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:
            return None

rows = []
try:
    with open(nd, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            rows.append((o.get("timestamp", ""), o.get("eventMessage", ""),
                         o.get("messageType", "")))
except FileNotFoundError:
    print("no system.ndjson")
    sys.exit(0)

gauge_re = re.compile(
    r"live-flow counts tcp=(\d+) udp=(\d+) total=(\d+) peak=(\d+) softCap=(\d+)")
reap_re = re.compile(
    r"flow pressure: occupancy (\d+) over soft cap (\d+); reaping (\d+) idle")
ride_re = re.compile(
    r"flow pressure: over soft cap \((\d+)\) at occupancy (\d+) but no flow idle")
life_re = re.compile(
    r"(startProxy|stopProxy|system sleep|system wake|engine created|engine detached|"
    r"watchdog:|stuck|drain backstop|force-dropped|force-tearing|timed out|"
    r"not viable|not satisfied|reset)", re.I)

# Reaper/teardown domains -> friendly key
domains = {
    "rama.tproxy.pressure-evicted": "pressure_evicted",
    "rama.tproxy.idle-timeout": "idle_timeout",
    "rama.tproxy.drain-backstop": "drain_backstop",
    "rama.tproxy.wake-dead-path": "wake_dead_path",
}

peak_tcp = peak_udp = peak_total = 0
softcap_seen = set()
last_tcp = last_udp = None
n_gauge = 0
counts = {"reap_events": 0, "flows_reaped": 0, "admit_and_ride": 0,
          "pressure_evicted": 0, "idle_timeout": 0, "drain_backstop": 0,
          "wake_dead_path": 0, "err": 0, "sleep": 0, "wake": 0}
per_phase = {}   # phase -> {peak_total, evicted, reaped, ride}

def ph(name):
    return per_phase.setdefault(name, {"peak_total": 0, "evicted": 0,
                                       "reaped": 0, "ride": 0, "gauge": 0})

with open(os.path.join(out, "flow-counts.txt"), "w") as g, \
     open(os.path.join(out, "timeline.txt"), "w") as t:
    for ts, msg, mtype in rows:
        ep = to_epoch(ts)
        pname = phase_of(ep)
        m = gauge_re.search(msg)
        if m:
            tcp, udp, total, pk, sc = map(int, m.groups())
            g.write(f"{ts}  [{pname}]  tcp={tcp} udp={udp} total={total} peak={pk} softCap={sc}\n")
            peak_tcp = max(peak_tcp, tcp); peak_udp = max(peak_udp, udp)
            peak_total = max(peak_total, total)
            last_tcp, last_udp = tcp, udp
            softcap_seen.add(sc)
            n_gauge += 1
            p = ph(pname); p["peak_total"] = max(p["peak_total"], total); p["gauge"] += 1
        mr = reap_re.search(msg)
        if mr:
            counts["reap_events"] += 1
            counts["flows_reaped"] += int(mr.group(3))
            ph(pname)["reaped"] += int(mr.group(3))
        if ride_re.search(msg):
            counts["admit_and_ride"] += 1
            ph(pname)["ride"] += 1
        for dom, key in domains.items():
            if dom in msg:
                counts[key] += 1
                if key == "pressure_evicted":
                    ph(pname)["evicted"] += 1
        if mtype in ("Error", "Fault") or life_re.search(msg):
            t.write(f"{ts}  [{pname}] [{mtype or 'Default'}]  {msg}\n")
            ml = msg.lower()
            if mtype in ("Error", "Fault"):
                counts["err"] += 1
            if "system sleep" in ml:
                counts["sleep"] += 1
            if "system wake" in ml:
                counts["wake"] += 1

# Probe-monitor freeze detection. Columns: epoch \t iso \t code. Failures
# inside the sleep-wake phase window are EXPECTED (the machine is asleep), so
# they're excluded from the freeze verdict.
probe_fail = probe_total = max_fail_run = probe_skipped = 0
ptl = os.path.join(out, "probe-timeline.txt")
if os.path.exists(ptl):
    run = 0
    with open(ptl) as f:
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            try:
                ep = int(parts[0])
            except ValueError:
                ep = None
            code = parts[-1]
            if phase_of(ep) == "sleep-wake":
                probe_skipped += 1
                run = 0
                continue
            probe_total += 1
            if not code.startswith("2"):
                probe_fail += 1
                run += 1
                max_fail_run = max(max_fail_run, run)
            else:
                run = 0

# Run metadata (what the script targeted) — context for the verdicts.
meta = {}
mf = os.path.join(out, "run-meta.tsv")
if os.path.exists(mf):
    with open(mf) as f:
        for ln in f:
            kv = ln.rstrip("\n").split("\t")
            if len(kv) == 2:
                meta[kv[0]] = kv[1]

# Fanout curl outcomes. These are DESCRIPTIVE only: the curls are dominated by
# our own teardown (we kill the still-running ones at hold-end) and our
# --max-time, so curl exit codes can't distinguish a proxy-dropped connection
# from our intentional stop. The trustworthy "active flows weren't dropped"
# signal is log-grounded (fanout-phase pressure-evicted == 0), computed below.
fo_ok = fo_bad = fo_term = 0
fof = os.path.join(out, "fanout.txt")
if os.path.exists(fof):
    with open(fof, errors="replace") as f:
        for ln in f:
            if ln.startswith("terminated-by-script"):
                try:
                    fo_term += int(ln.split()[1])
                except (IndexError, ValueError):
                    pass
                continue
            mm = re.match(r"\s*(\d{3})\s", ln)
            if mm:
                if mm.group(1).startswith(("2", "3")):
                    fo_ok += 1
                else:
                    fo_bad += 1
            elif "curl:" in ln:
                fo_bad += 1

# Idle-holder pool churn. Lines: "iso \t live_holders=N \t gauge_total=M".
# A sawtooth (live repeatedly dropping below target between 6s top-ups) means
# the server closed idle holders before they could age past the idle floor —
# the exact reason the eviction reaper may never get a victim on a long-floor
# build. holder_dips counts top-up rounds that had to refill.
holder_min = holder_max = None
holder_dips = holder_ticks = 0
hf = os.path.join(out, "holders.log")
idle_target = int(meta.get("idle_target", "0") or "0")
if os.path.exists(hf):
    with open(hf, errors="replace") as f:
        for ln in f:
            m = re.search(r"live_holders=(\d+)", ln)
            if not m:
                continue
            live = int(m.group(1))
            holder_ticks += 1
            holder_min = live if holder_min is None else min(holder_min, live)
            holder_max = live if holder_max is None else max(holder_max, live)
            if idle_target and live < idle_target:
                holder_dips += 1

with open(os.path.join(out, "extract-summary.txt"), "w") as s:
    def w(line=""):
        print(line); s.write(line + "\n")
    w("=== soak extract summary ===")
    w(f"ndjson rows parsed:       {len(rows)}")
    w(f"phases recorded:          {', '.join(p[0] for p in phases) or '(none)'}")
    w(f"softCap (from gauge):     {sorted(softcap_seen) or '(none seen)'}")
    w(f"flow-count gauge ticks:   {n_gauge}")
    w(f"peak flows:               tcp={peak_tcp} udp={peak_udp} total={peak_total}")
    if last_tcp is None:
        w("final flows:              (no gauge tick — was capture running 60s+?)")
    else:
        w(f"final flows:              tcp={last_tcp} udp={last_udp}")
        verdict = "GOOD — drained to 0" if (last_tcp == 0 and last_udp == 0) \
            else "!! flows did NOT drain to 0 — possible leak"
        w(f"leak verdict:             {verdict}")
    w("")
    w("--- flow-pressure reaper ---")
    w(f"reap events:              {counts['reap_events']}")
    w(f"flows reaped (sum):       {counts['flows_reaped']}")
    w(f"per-flow pressure-evicted:{counts['pressure_evicted']}")
    w(f"admit-and-ride (no idle): {counts['admit_and_ride']}")
    sc = max(softcap_seen) if softcap_seen else 0
    if sc > 0:
        head = sc - peak_total
        w(f"peak vs softCap:          peak_total={peak_total} softCap={sc} "
          f"({'UNDER cap by %d' % head if head >= 0 else 'OVER cap by %d (rode)' % (-head)})")
    # Honest verdict: distinguish eviction fired / rode-without-victim /
    # cap-never-reached, so an all-zero result is never read as silent success.
    if counts['pressure_evicted'] > 0:
        w(f"reaper verdict:           GOOD — idle-eviction fired: {counts['pressure_evicted']} "
          "idle flow(s) evicted toward low-water")
    elif counts['admit_and_ride'] > 0:
        w(f"reaper verdict:           reaper ENGAGED but found NO idle victims (admit-and-ride "
          f"x{counts['admit_and_ride']}).")
        w("                          The idle-EVICTION path was NOT exercised — holders almost")
        w("                          certainly closed (server-side) before reaching the idle floor.")
        w("                          To validate eviction, build with a short")
        w("                          defaultFlowPressureIdleFloorMs (e.g. 10s).")
    elif sc > 0 and peak_total >= sc:
        w("reaper verdict:           !! occupancy crossed softCap but the reaper logged NOTHING "
          "— investigate the admission trigger")
    elif sc > 0:
        w(f"reaper verdict:           occupancy never reached softCap (peak {peak_total} < {sc}) "
          "— raise FANOUT_TARGET/IDLE_TARGET to exercise the cap")
    else:
        w("reaper verdict:           (softCap unknown — cannot assess)")
    if holder_ticks:
        w(f"idle holders:             live min={holder_min} max={holder_max} over {holder_ticks} "
          f"ticks; {holder_dips} top-up rounds refilled")
        w("                          (sawtooth = server closed idle holders before the idle floor)")
    w("")
    w("--- other reapers / events ---")
    w(f"idle-timeout teardowns:   {counts['idle_timeout']}")
    w(f"drain-backstop fires:     {counts['drain_backstop']}")
    w(f"wake-dead-path resets:    {counts['wake_dead_path']}")
    w(f"sleep markers:            {counts['sleep']}")
    w(f"wake markers:             {counts['wake']}")
    w(f"error/fault lines:        {counts['err']}")
    w("")
    w("--- freeze detector (liveness probe; sleep-wake excluded) ---")
    w(f"probes:                   {probe_total} (failures {probe_fail}, "
      f"longest fail-run {max_fail_run}, sleep-wake skipped {probe_skipped})")
    if probe_fail == 0:
        w("freeze verdict:           GOOD — proxy stayed live throughout (no freeze)")
    else:
        w(f"freeze verdict:           !! {probe_fail} probe failures — investigate "
          f"(nexus exhaustion / network blip / sleep gap)")
    w("")
    w("--- fanout: active flows under pressure (reaper must NOT drop active flows) ---")
    fp = ph("fanout")
    w(f"curl outcomes (descriptive): launched~{meta.get('fanout_target', '?')} completed={fo_ok} "
      f"errored={fo_bad} terminated-by-script={fo_term}")
    w("                          (curl codes are polluted by our own teardown — NOT the signal)")
    w(f"fanout-phase gauge:       peak_total={fp['peak_total']} evicted={fp['evicted']} ride={fp['ride']}")
    # Active flows are never idle, so the reaper must evict ZERO during an
    # all-active burst. That log fact — not curl codes — is the integrity proof.
    if not any(name == "fanout" for name, _, _ in phases):
        w("integrity verdict:        (fanout phase did not run)")
    elif fp['evicted'] > 0:
        w(f"integrity verdict:        !! reaper EVICTED {fp['evicted']} flow(s) during an ALL-ACTIVE "
          "burst — active/user connections must never be evicted")
    elif sc > 0 and fp['peak_total'] >= sc:
        w("integrity verdict:        GOOD — occupancy crossed the cap yet the reaper evicted NO "
          "active flow; no user connection dropped")
    elif sc > 0:
        w(f"integrity verdict:        burst peaked {fp['peak_total']} < softCap {sc} — cap not reached; "
          "raise FANOUT_TARGET to test active-flow survival under real pressure")
    else:
        w("integrity verdict:        (softCap unknown — cannot assess)")
    w("")
    if phases:
        w("--- per-phase ---")
        w(f"{'phase':<14} {'peak_total':>10} {'reaped':>7} {'evicted':>8} {'ride':>5} {'ticks':>6}")
        for name, sp, ep in phases:
            p = ph(name)
            w(f"{name:<14} {p['peak_total']:>10} {p['reaped']:>7} "
              f"{p['evicted']:>8} {p['ride']:>5} {p['gauge']:>6}")
    w("")
    w("see flow-counts.txt (per-phase gauge), timeline.txt (lifecycle/errors),")
    w("probe-timeline.txt (freeze), holders.log + fanout.txt (load).")
PYEOF
else
  warn "python3 not found — falling back to grep (no per-phase summary)"
  grep -oE 'live-flow counts tcp=[0-9]+ udp=[0-9]+ total=[0-9]+ peak=[0-9]+ softCap=[0-9]+' \
    "$OUT/system.ndjson" > "$OUT/flow-counts.txt" 2>/dev/null || true
  grep -iE 'flow pressure|pressure-evicted|idle-timeout|drain-backstop|wake-dead-path|system sleep|system wake|watchdog:' \
    "$OUT/system.ndjson" > "$OUT/timeline.txt" 2>/dev/null || true
fi

# ── Bundle ────────────────────────────────────────────────────────────
hdr "done"
TARBALL="$OUT.tgz"
tar -czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null \
  && say "tarball:   $TARBALL" || warn "could not create tarball"
say "dir:       $OUT"
echo
[[ -f "$OUT/extract-summary.txt" ]] && cat "$OUT/extract-summary.txt"
echo
hdr "hand me: $OUT  (or the tarball)"
