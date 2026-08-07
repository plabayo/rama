#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILT_APP="${1:-$ROOT_DIR/.xcode-derived/tproxy-app-dev/Build/Products/Debug/RamaTransparentProxyExampleContainer.app}"
PROBE="$SCRIPT_DIR/modern_udp_e2e_probe.py"
INSTALLER="$SCRIPT_DIR/install_tproxy_app_bundle.sh"
CONTAINER_LOG="$HOME/Library/Logs/RamaTransparentProxyExampleContainer.log"

# Maintained public protocol endpoints. Override these when a runner's network
# filters a particular anycast service; IP literals keep provider-log assertions
# deterministic and avoid mixing resolver traffic into the target flow.
PASSTHROUGH_DNS="${RAMA_TPROXY_E2E_PASSTHROUGH_DNS:-1.1.1.1}"
INTERCEPT_NTP="${RAMA_TPROXY_E2E_INTERCEPT_NTP:-162.159.200.1}"
BLOCKED_DNS="${RAMA_TPROXY_E2E_BLOCKED_DNS:-8.8.8.8}"
HTTP3_URL="${RAMA_TPROXY_E2E_HTTP3_URL:-https://cloudflare.com/cdn-cgi/trace}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "modern UDP Network Extension E2E requires macOS" >&2
  exit 1
fi

MACOS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
CALLBACK_GENERATION="modern"
if (( MACOS_MAJOR < 15 )); then
  if [[ "${RAMA_TPROXY_ALLOW_LEGACY_UDP_E2E:-0}" != "1" ]]; then
    echo "modern UDP Network Extension E2E requires macOS 15 or newer" >&2
    echo "set RAMA_TPROXY_ALLOW_LEGACY_UDP_E2E=1 for the documented legacy run" >&2
    exit 1
  fi
  CALLBACK_GENERATION="legacy"
fi

if [[ ! -d "$BUILT_APP" ]]; then
  echo "signed app not found at $BUILT_APP; build it before running this test" >&2
  exit 1
fi

if ! command -v nscurl >/dev/null; then
  echo "nscurl is required for the public HTTP/3 UDP/443 probe" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/rama-modern-udp-e2e.XXXXXX)"
PROVIDER_LOG="$TMP_DIR/provider.log"
HTTP3_RESULT="$TMP_DIR/http3-result.log"
LOG_PID=""
PROFILE_NEEDS_RESTORE=0

cleanup() {
  if [[ -n "$LOG_PID" ]]; then
    kill "$LOG_PID" 2>/dev/null || true
  fi
  if [[ "$PROFILE_NEEDS_RESTORE" == "1" ]]; then
    echo "restoring default UDP test overrides after interrupted E2E" >&2
    "$INSTALLER" dev "$BUILT_APP" 0 \
      "--udp-passthrough-ports=" \
      "--udp-blocked-endpoints=" \
      > "$TMP_DIR/restore.log" 2>&1 || \
      echo "warning: automatic UDP policy restoration failed; see $TMP_DIR/restore.log" >&2
  fi
  echo "modern UDP E2E artifacts: $TMP_DIR"
}
trap cleanup EXIT

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
  local starting_line="$1"
  local connected=0
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
  if [[ "$connected" != "1" ]]; then
    echo "transparent proxy did not reach connected state" >&2
    tail -n 80 "$CONTAINER_LOG" 2>/dev/null || true
    exit 1
  fi
}

/usr/bin/log stream --level debug --style compact \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"' \
  > "$PROVIDER_LOG" 2>&1 &
LOG_PID=$!

# First install an unblocked profile. Besides exercising pass-through and
# intercept, this proves the future blocked endpoint is healthy immediately
# before the block rule is enabled.
CONTAINER_LOG_LINE="$(container_log_line)"
PROFILE_NEEDS_RESTORE=1
"$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=443" \
  "--udp-blocked-endpoints="
wait_for_connected "$CONTAINER_LOG_LINE"

# Ignore teardown/startup errors from the provider instance being replaced.
# The live error assertion below starts only after the fresh provider is
# connected and its startup log has drained, immediately before our probes.
sleep 1
UDP_ERROR_PROVIDER_LOG_LINE="$(provider_log_line)"

/usr/bin/python3 "$PROBE" dns --server "$PASSTHROUGH_DNS"
/usr/bin/python3 "$PROBE" ntp --server "$INTERCEPT_NTP"
/usr/bin/python3 "$PROBE" dns --server "$BLOCKED_DNS"

HTTP3_SEPARATOR='?'
if [[ "$HTTP3_URL" == *\?* ]]; then
  HTTP3_SEPARATOR='&'
fi
HTTP3_PROVIDER_LOG_LINE="$(provider_log_line)"
nscurl --http3-prior-knowledge -m 15 \
  "${HTTP3_URL}${HTTP3_SEPARATOR}rama_udp_e2e=$(date +%s)-$$" \
  > "$HTTP3_RESULT" 2>&1
if ! grep -Fq 'http=http/3' "$HTTP3_RESULT"; then
  echo "public UDP/443 probe did not complete over HTTP/3" >&2
  cat "$HTTP3_RESULT" >&2
  exit 1
fi

# Reinstall with one exact public DNS endpoint blocked. A new client socket is
# used below, so this must create a fresh NE flow and decision.
CONTAINER_LOG_LINE="$(container_log_line)"
"$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=443" \
  "--udp-blocked-endpoints=$BLOCKED_DNS:53"
wait_for_connected "$CONTAINER_LOG_LINE"

/usr/bin/python3 "$PROBE" dns --server "$BLOCKED_DNS" \
  --timeout 4 --expect-no-response

# Let os_log and the Rust tracing bridge flush the per-flow decision/service
# records before assertions.
sleep 2
kill "$LOG_PID" 2>/dev/null || true
wait "$LOG_PID" 2>/dev/null || true
LOG_PID=""

assert_log() {
  local pattern="$1"
  local description="$2"
  if ! grep -Fq "$pattern" "$PROVIDER_LOG"; then
    echo "missing provider log assertion: $description" >&2
    echo "expected: $pattern" >&2
    tail -n 200 "$PROVIDER_LOG" >&2
    exit 1
  fi
}

assert_log \
  "udp_e2e_decision rama_decision=passthrough remote_endpoint=$PASSTHROUGH_DNS:53 source_app=com.apple.python3" \
  "Rust pass-through decision for public DNS"
assert_log \
  "udp_e2e_decision rama_decision=intercept remote_endpoint=$INTERCEPT_NTP:123 source_app=com.apple.python3" \
  "Rust intercept decision for public NTP forwarding"
assert_log \
  "udp_e2e_decision rama_decision=blocked remote_endpoint=$BLOCKED_DNS:53 source_app=com.apple.python3" \
  "Rust blocked decision for an exact public DNS endpoint"

if ! tail -n "+$((HTTP3_PROVIDER_LOG_LINE + 1))" "$PROVIDER_LOG" | grep -E \
  'udp_e2e_decision rama_decision=passthrough remote_endpoint=.*:443 source_app=com\.apple\.nscurl' \
  >/dev/null; then
  echo "missing provider log assertion: public HTTP/3 UDP/443 pass-through" >&2
  tail -n 200 "$PROVIDER_LOG" >&2
  exit 1
fi

# Open/read/write markers are emitted only for errors the provider classifier
# considers unexpected. Benign teardown races have no public marker, so this
# assertion can cover the full active test window without app attribution.
if tail -n "+$((UDP_ERROR_PROVIDER_LOG_LINE + 1))" "$PROVIDER_LOG" | grep -E \
  'flow_callback_error operation=udp_flow\.(open|read|write)' >/dev/null; then
  echo "provider emitted an unexpected UDP flow error during the live test" >&2
  tail -n 200 "$PROVIDER_LOG" >&2
  exit 1
fi

# Do not leave a test-only block or pass-through override active on the host.
CONTAINER_LOG_LINE="$(container_log_line)"
"$INSTALLER" dev "$BUILT_APP" 0 \
  "--udp-passthrough-ports=" \
  "--udp-blocked-endpoints="
wait_for_connected "$CONTAINER_LOG_LINE"
PROFILE_NEEDS_RESTORE=0

echo "$CALLBACK_GENERATION UDP Network Extension E2E passed with public resources"
echo "pass-through DNS=$PASSTHROUGH_DNS:53 intercept NTP=$INTERCEPT_NTP:123 blocked DNS=$BLOCKED_DNS:53 UDP/443=$HTTP3_URL"
