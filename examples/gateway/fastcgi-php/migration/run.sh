#!/usr/bin/env bash
# End-to-end harness for the fastcgi_php_migration example.
#
#   curl ──HTTP──► rama router (this example) ─┬─► /api/health, /api/version  (Rust-native)
#                                              └─► everything else → FastCGI/Unix ──► php-fpm ──► app.php
#
# Modes (pass as first arg, default = test):
#   test  Boot the stack, run jq/curl assertions, exit. Used by CI.
#   run   Boot the stack and leave it running until Ctrl-C.
#
# Exits 77 (POSIX skip) if a required dependency (php-fpm, jq) is missing.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

parse_mode "${1:-}"
require_curl
require_jq
PHP_FPM_BIN="$(find_php_fpm)"

# Unix-socket pathnames are capped at 104/108 bytes on macOS/Linux. Keep the
# workdir short enough that "<workdir>/php-fpm.sock" fits comfortably.
WORKDIR="$(mktemp -d -t rfcgi-mg.XXXX)"

RAMA_PID=""
FPM_PID=""
CLEANED_UP=0

cleanup() {
    if (( CLEANED_UP )); then return 0; fi
    CLEANED_UP=1
    for pid in "$RAMA_PID" "$FPM_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ "$MODE" == "test" ]]; then
        rm -rf "$WORKDIR" 2>/dev/null || true
    else
        log "leaving workdir for inspection: $WORKDIR"
    fi
}

trap 'rc=$?; cleanup; exit $rc' EXIT
trap 'log "received signal, shutting down"; exit 130' INT TERM HUP

RAMA_FASTCGI_PHP_LISTEN="${RAMA_FASTCGI_PHP_LISTEN:-127.0.0.1:62081}"
BACKEND_SOCK="$WORKDIR/php-fpm.sock"
SCRIPT_PATH="$HERE/app.php"

# ── 1) Boot php-fpm on a Unix socket ─────────────────────────────────────
FPM_CONF="$(write_fpm_conf "$WORKDIR" "$BACKEND_SOCK")"
# Unix-socket listener overrides — replace allowed_clients (TCP-only) with
# listen.mode so the socket is reachable by the rama process.
sed -i.bak \
    -e 's/^listen\.allowed_clients.*/listen.mode = 0666/' \
    "$FPM_CONF"
rm -f "$FPM_CONF.bak"

log "starting php-fpm on $BACKEND_SOCK"
if [[ "$MODE" == "test" ]]; then
    "$PHP_FPM_BIN" --nodaemonize -y "$FPM_CONF" \
        >"$WORKDIR/php-fpm.out.log" 2>&1 &
else
    # Use process substitution (`> >(...)`) instead of a pipe so $! captures
    # php-fpm's PID directly. With `cmd | sed &` we'd get sed's PID and
    # cleanup would only kill sed, leaking the actual php-fpm.
    "$PHP_FPM_BIN" --nodaemonize -y "$FPM_CONF" \
        > >(sed -u 's/^/[php-fpm] /' >&2) 2>&1 &
fi
FPM_PID=$!
wait_for_unix_socket "$BACKEND_SOCK"
log "php-fpm ready"

# ── 2) Boot the rama example ─────────────────────────────────────────────
log "building rama example"
(cd "$REPO_ROOT" && cargo build --example fastcgi_php_migration \
    --features http-full,fastcgi) >/dev/null

log "starting rama migration server on http://$RAMA_FASTCGI_PHP_LISTEN"
if [[ "$MODE" == "test" ]]; then
    RAMA_FASTCGI_PHP_LISTEN="$RAMA_FASTCGI_PHP_LISTEN" \
    RAMA_FASTCGI_PHP_BACKEND_SOCKET="$BACKEND_SOCK" \
    RAMA_FASTCGI_PHP_SCRIPT_FILENAME="$SCRIPT_PATH" \
    RAMA_FASTCGI_PHP_DOCUMENT_ROOT="$HERE" \
        "$REPO_ROOT/target/debug/examples/fastcgi_php_migration" \
        >"$WORKDIR/rama.out.log" 2>&1 &
else
    # Process substitution (see php-fpm spawn above for the rationale).
    RAMA_FASTCGI_PHP_LISTEN="$RAMA_FASTCGI_PHP_LISTEN" \
    RAMA_FASTCGI_PHP_BACKEND_SOCKET="$BACKEND_SOCK" \
    RAMA_FASTCGI_PHP_SCRIPT_FILENAME="$SCRIPT_PATH" \
    RAMA_FASTCGI_PHP_DOCUMENT_ROOT="$HERE" \
    RUST_LOG="${RUST_LOG:-info}" \
        "$REPO_ROOT/target/debug/examples/fastcgi_php_migration" \
        > >(sed -u 's/^/[rama] /' >&2) 2>&1 &
fi
RAMA_PID=$!

IFS=':' read -r RAMA_HOST RAMA_PORT <<<"$RAMA_FASTCGI_PHP_LISTEN"
wait_for_tcp "$RAMA_HOST" "$RAMA_PORT"
log "rama migration server ready"

# ── 3) Mode-specific behaviour ───────────────────────────────────────────
BASE="http://$RAMA_FASTCGI_PHP_LISTEN"

if [[ "$MODE" == "run" ]]; then
    run_mode_hint "$BASE"
    wait_for_signal "$FPM_PID" "$RAMA_PID"
    exit 0
fi

# ── 4) Test mode: assertions ─────────────────────────────────────────────
log "Rust-served endpoints"
assert_jq_eq "$BASE/api/health"  '.source' 'rust'
assert_jq_eq "$BASE/api/health"  '.status' 'ok'
assert_jq_eq "$BASE/api/version" '.source' 'rust'

log "FastCGI fallback endpoints"
assert_jq_eq "$BASE/api/users" '.source'   'php'
assert_jq_eq "$BASE/api/users" '.users[0]' 'alice'
assert_jq_eq "$BASE/"          '.source'   'php'
assert_jq_eq "$BASE/anything"  '.source'   'php'

log "all assertions passed ✅"
