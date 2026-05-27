#!/usr/bin/env bash
# End-to-end harness for the fastcgi_php_gateway example.
#
#   curl ──HTTPS──► rama (this example) ──FastCGI/TCP──► php-fpm ──► app.php
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

WORKDIR="$(mktemp -d -t rfcgi-gw.XXXX)"

RAMA_PID=""
FPM_PID=""
CLEANED_UP=0

# Always run cleanup once, regardless of why we're exiting:
#   - normal exit (EXIT trap)
#   - Ctrl-C from the same terminal (SIGINT delivered to the process group)
#   - external `kill -TERM <pid>` outside the process group (only the script
#     gets it — children would otherwise orphan)
cleanup() {
    if (( CLEANED_UP )); then return 0; fi
    CLEANED_UP=1
    for pid in "$RAMA_PID" "$FPM_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            # Give it a moment to exit gracefully, then SIGKILL.
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

RAMA_FASTCGI_PHP_LISTEN="${RAMA_FASTCGI_PHP_LISTEN:-127.0.0.1:62443}"
RAMA_FASTCGI_PHP_BACKEND="${RAMA_FASTCGI_PHP_BACKEND:-127.0.0.1:62444}"
SCRIPT_PATH="$HERE/app.php"

# ── 1) Boot php-fpm on TCP ───────────────────────────────────────────────
FPM_CONF="$(write_fpm_conf "$WORKDIR" "$RAMA_FASTCGI_PHP_BACKEND")"
log "starting php-fpm on $RAMA_FASTCGI_PHP_BACKEND"
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

IFS=':' read -r BACKEND_HOST BACKEND_PORT <<<"$RAMA_FASTCGI_PHP_BACKEND"
wait_for_tcp "$BACKEND_HOST" "$BACKEND_PORT"
log "php-fpm ready"

# ── 2) Boot the rama example ─────────────────────────────────────────────
log "building rama example"
(cd "$REPO_ROOT" && cargo build --example fastcgi_php_gateway \
    --features http-full,fastcgi,rustls,aws-lc) >/dev/null

log "starting rama gateway on https://$RAMA_FASTCGI_PHP_LISTEN"
if [[ "$MODE" == "test" ]]; then
    RAMA_FASTCGI_PHP_LISTEN="$RAMA_FASTCGI_PHP_LISTEN" \
    RAMA_FASTCGI_PHP_BACKEND="$RAMA_FASTCGI_PHP_BACKEND" \
    RAMA_FASTCGI_PHP_SCRIPT_FILENAME="$SCRIPT_PATH" \
    RAMA_FASTCGI_PHP_DOCUMENT_ROOT="$HERE" \
        "$REPO_ROOT/target/debug/examples/fastcgi_php_gateway" \
        >"$WORKDIR/rama.out.log" 2>&1 &
else
    # Process substitution (see php-fpm spawn above for the rationale).
    RAMA_FASTCGI_PHP_LISTEN="$RAMA_FASTCGI_PHP_LISTEN" \
    RAMA_FASTCGI_PHP_BACKEND="$RAMA_FASTCGI_PHP_BACKEND" \
    RAMA_FASTCGI_PHP_SCRIPT_FILENAME="$SCRIPT_PATH" \
    RAMA_FASTCGI_PHP_DOCUMENT_ROOT="$HERE" \
    RUST_LOG="${RUST_LOG:-info}" \
        "$REPO_ROOT/target/debug/examples/fastcgi_php_gateway" \
        > >(sed -u 's/^/[rama] /' >&2) 2>&1 &
fi
RAMA_PID=$!

IFS=':' read -r RAMA_HOST RAMA_PORT <<<"$RAMA_FASTCGI_PHP_LISTEN"
wait_for_tcp "$RAMA_HOST" "$RAMA_PORT"
log "rama gateway ready"

# ── 3) Mode-specific behaviour ───────────────────────────────────────────
BASE="https://$RAMA_FASTCGI_PHP_LISTEN"

if [[ "$MODE" == "run" ]]; then
    run_mode_hint "$BASE"
    wait_for_signal "$FPM_PID" "$RAMA_PID"
    exit 0
fi

# ── 4) Test mode: assertions ─────────────────────────────────────────────
log "GET / — round-trip method/uri/source"
assert_jq_eq "$BASE/" '.source'        'php'
assert_jq_eq "$BASE/" '.method'        'GET'
assert_jq_eq "$BASE/" '.https'         'on'
assert_jq_eq "$BASE/" '.gateway'       'CGI/1.1'

log "GET /hello?foo=bar — path + query"
assert_jq_eq "$BASE/hello?foo=bar" '.request_uri' '/hello?foo=bar'
assert_jq_eq "$BASE/hello?foo=bar" '.query_string' 'foo=bar'

log "POST /submit — body round-trip"
assert_jq_eq "$BASE/submit" '.method' 'POST' -X POST --data-binary 'hello=world'
assert_jq_eq "$BASE/submit" '.body'   'hello=world' -X POST --data-binary 'hello=world'

log "custom header forwarded as HTTP_*"
assert_jq_eq "$BASE/" '.headers["x-rama-test"]' 'yes' -H 'X-Rama-Test: yes'

log "all assertions passed ✅"
