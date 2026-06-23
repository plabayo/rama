#!/usr/bin/env bash
#
# MITM OCSP-stapling gate.
#
# Stands up the `mitm_ocsp_relay_gate` example (a local upstream TLS+HTTP server
# behind the boring TlsMitmRelay proxy) across three upstream revocation
# profiles and asserts, with real external clients, that:
#
#   upstream advertises | curl (plain) | curl --cert-status | openssl -status
#   --------------------+--------------+--------------------+-----------------
#   OCSP responder      | trusts       | trusts             | successful/good
#   CRL distribution pt | trusts       | trusts             | successful/good
#   nothing             | trusts       | FAILS (no staple)  | (no response)
#
# The `none` row is the negative control: a genuinely revocation-less upstream
# where a strict client must NOT see a staple — proving the gate isn't a
# rubber stamp. Chain trust holds in all three.
#
# `curl --cert-status` needs an OpenSSL/GnuTLS-backed curl (not SecureTransport).
# On macOS that means a brew curl; the system one is skipped automatically.
# Set OCSP_GATE_REQUIRE=1 (CI) to turn "no suitable curl" into a hard failure.
# Overrides: OCSP_GATE_CURL, OCSP_GATE_OPENSSL.

set -euo pipefail
cd "$(dirname "$0")/.."

REQUIRE="${OCSP_GATE_REQUIRE:-0}"
OPENSSL="${OCSP_GATE_OPENSSL:-openssl}"

# Pick a curl that actually enforces --cert-status (OpenSSL/GnuTLS/wolfSSL
# backends). SecureTransport/LibreSSL builds list the flag but don't verify.
find_curl() {
    local c ver
    for c in "${OCSP_GATE_CURL:-}" curl \
        /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl; do
        [ -n "$c" ] || continue
        ver="$(command -v "$c" >/dev/null 2>&1 && "$c" -V 2>/dev/null)" || continue
        echo "$ver" | grep -qiE 'openssl|gnutls|wolfssl|boringssl' || continue
        echo "$ver" | grep -qi 'securetransport' && continue
        command -v "$c" 2>/dev/null || echo "$c"
        return 0
    done
    return 1
}

if ! CURL="$(find_curl)"; then
    msg="no curl with --cert-status support found (need an OpenSSL/GnuTLS-backed curl)"
    if [ "$REQUIRE" = "1" ]; then echo "FATAL: $msg" >&2; exit 1; fi
    echo "SKIP: $msg" >&2
    exit 0
fi
echo "curl:    $CURL"
echo "openssl: $OPENSSL"

cargo build --example mitm_ocsp_relay_gate --features=http-full,boring
BIN=target/debug/examples/mitm_ocsp_relay_gate

WORK="$(mktemp -d)"
PROXY_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

run_scenario() {
    local kind="$1"
    local ca="$WORK/ca-$kind.pem"
    local out="$WORK/out-$kind.log"

    "$BIN" --upstream-revocation "$kind" --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!

    local addr=""
    for _ in $(seq 1 100); do
        addr="$(sed -n 's/^READY proxy=\([^ ]*\) .*/\1/p' "$out" 2>/dev/null)"
        [ -n "$addr" ] && break
        kill -0 "$PROXY_PID" 2>/dev/null || { cat "$out"; fail "$kind: harness exited early"; }
        sleep 0.1
    done
    [ -n "$addr" ] || { cat "$out"; fail "$kind: harness never became READY"; }

    local port="${addr##*:}"
    local resolve="upstream.example:$port:127.0.0.1"
    local url="https://upstream.example:$port/"
    echo "[$kind] proxy=$addr"

    # Chain trust must hold in every scenario.
    "$CURL" -sS --cacert "$ca" --resolve "$resolve" "$url" >/dev/null \
        || fail "$kind: plain curl (chain trust) failed"

    local status
    status="$("$OPENSSL" s_client -connect "127.0.0.1:$port" \
        -servername upstream.example -status -CAfile "$ca" </dev/null 2>/dev/null || true)"

    case "$kind" in
    ocsp | crl)
        "$CURL" -sS --cert-status --cacert "$ca" --resolve "$resolve" "$url" >/dev/null \
            || fail "$kind: curl --cert-status rejected the stapled leaf"
        echo "$status" | grep -q "OCSP Response Status: successful" \
            || fail "$kind: openssl did not report a successful OCSP response"
        echo "$status" | grep -q "Cert Status: good" \
            || fail "$kind: openssl did not report 'Cert Status: good'"
        echo "[$kind] OK — staple present, valid, trusted by curl --cert-status"
        ;;
    none)
        if "$CURL" -sS --cert-status --cacert "$ca" --resolve "$resolve" "$url" >/dev/null 2>&1; then
            fail "none: curl --cert-status unexpectedly succeeded (a staple was sent?)"
        fi
        echo "[none] OK — no staple (parity), chain still trusted, --cert-status correctly fails"
        ;;
    esac

    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
}

# Real crates.io through the CONNECT proxy: mirror the live origin cert + staple,
# then prove a strict client (curl --cert-status) and cargo both accept it.
run_connect() {
    local ca="$WORK/ca-connect.pem"
    local out="$WORK/out-connect.log"

    "$BIN" --connect --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!

    local addr=""
    for _ in $(seq 1 100); do
        addr="$(sed -n 's/^READY proxy=\([^ ]*\) .*/\1/p' "$out" 2>/dev/null)"
        [ -n "$addr" ] && break
        kill -0 "$PROXY_PID" 2>/dev/null || { cat "$out"; fail "connect: harness exited early"; }
        sleep 0.1
    done
    [ -n "$addr" ] || { cat "$out"; fail "connect: harness never became READY"; }
    local proxy="http://$addr"
    echo "[connect] proxy=$addr -> real crates.io"

    "$CURL" -sS --cert-status --proxy "$proxy" --cacert "$ca" \
        -o /dev/null https://index.crates.io/config.json \
        || fail "connect: curl --cert-status rejected the mirrored crates.io leaf"
    echo "[connect] OK - curl --cert-status trusts the stapled crates.io mirror"

    local proj="$WORK/cargo-probe"
    mkdir -p "$proj/src"
    : >"$proj/src/lib.rs"
    printf '[package]\nname = "gate-probe"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\nitoa = "1"\n' >"$proj/Cargo.toml"
    CARGO_HOME="$WORK/cargo-home" \
        CARGO_HTTP_PROXY="$proxy" \
        CARGO_HTTP_CAINFO="$ca" \
        CARGO_HTTP_CHECK_REVOKE=true \
        cargo generate-lockfile --manifest-path "$proj/Cargo.toml" \
        || fail "connect: cargo failed to fetch crates.io through the MITM"
    grep -q 'name = "itoa"' "$proj/Cargo.lock" \
        || fail "connect: cargo did not resolve itoa through the MITM"
    echo "[connect] OK - cargo fetched crates.io through the MITM (CA trusted, staple OK)"

    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
}

# Wait for the harness READY line, echoing it; fails if the harness dies first.
wait_ready() {
    local out="$1" line
    for _ in $(seq 1 100); do
        line="$(grep '^READY' "$out" 2>/dev/null | head -1)"
        [ -n "$line" ] && { echo "$line"; return 0; }
        kill -0 "$PROXY_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# Proxy-hosted CRL endpoint: the re-signed leaf carries a CRL distribution point
# at our loopback responder, which serves a CA-signed CRL. Proves a
# revocation-strict verifier (openssl -crl_check) accepts the leaf via that CRL,
# and (negative) that -crl_check genuinely needs it.
run_crl_endpoint() {
    local ca="$WORK/ca-crlpt.pem" out="$WORK/out-crlpt.log" line addr revoc port
    "$BIN" --upstream-revocation crl --leaf-revocation crl --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!
    line="$(wait_ready "$out")" || { cat "$out"; fail "crl-endpoint: harness never READY"; }
    addr="$(echo "$line" | sed -n 's/.*proxy=\([^ ]*\).*/\1/p')"; port="${addr##*:}"
    revoc="$(echo "$line" | sed -n 's/.*revoc=\([^ ]*\).*/\1/p')"
    echo "[crl-endpoint] proxy=$addr revoc=$revoc"

    "$OPENSSL" s_client -connect "127.0.0.1:$port" -servername upstream.example </dev/null 2>/dev/null \
        | "$OPENSSL" x509 -out "$WORK/leaf-crlpt.pem" || fail "crl-endpoint: could not grab mirrored leaf"
    "$OPENSSL" x509 -in "$WORK/leaf-crlpt.pem" -noout -text | grep -q "$revoc" \
        || fail "crl-endpoint: leaf is missing our CRL distribution point"

    # Negative control: -crl_check with no CRL available must fail.
    if "$OPENSSL" verify -crl_check -CAfile "$ca" "$WORK/leaf-crlpt.pem" >/dev/null 2>&1; then
        fail "crl-endpoint: -crl_check unexpectedly passed without a CRL"
    fi

    "$CURL" -sS "http://$revoc/crl" | "$OPENSSL" crl -inform DER -out "$WORK/crlpt.pem" 2>/dev/null \
        || fail "crl-endpoint: could not fetch/parse the served CRL"
    "$OPENSSL" verify -crl_check -CAfile "$ca" -CRLfile "$WORK/crlpt.pem" "$WORK/leaf-crlpt.pem" >/dev/null \
        || fail "crl-endpoint: -crl_check rejected the leaf with our CRL"
    echo "[crl-endpoint] OK — leaf CDP + CA-signed CRL accepted by openssl -crl_check"

    kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=""
}

# Proxy-hosted OCSP endpoint: the re-signed leaf carries an AIA OCSP URL at our
# loopback responder. Proves an OCSP client (openssl ocsp) verifies the CA-signed
# response (incl. nonce echo) and reads status good.
run_ocsp_endpoint() {
    local ca="$WORK/ca-ocsppt.pem" out="$WORK/out-ocsppt.log" line addr revoc port status
    "$BIN" --upstream-revocation ocsp --leaf-revocation ocsp --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!
    line="$(wait_ready "$out")" || { cat "$out"; fail "ocsp-endpoint: harness never READY"; }
    addr="$(echo "$line" | sed -n 's/.*proxy=\([^ ]*\).*/\1/p')"; port="${addr##*:}"
    revoc="$(echo "$line" | sed -n 's/.*revoc=\([^ ]*\).*/\1/p')"
    echo "[ocsp-endpoint] proxy=$addr revoc=$revoc"

    "$OPENSSL" s_client -connect "127.0.0.1:$port" -servername upstream.example </dev/null 2>/dev/null \
        | "$OPENSSL" x509 -out "$WORK/leaf-ocsppt.pem" || fail "ocsp-endpoint: could not grab mirrored leaf"
    status="$("$OPENSSL" ocsp -issuer "$ca" -cert "$WORK/leaf-ocsppt.pem" \
        -url "http://$revoc/ocsp" -CAfile "$ca" 2>&1 || true)"
    echo "$status" | grep -q "Response verify OK" \
        || { echo "$status"; fail "ocsp-endpoint: response signature did not verify"; }
    echo "$status" | grep -q ": good" \
        || { echo "$status"; fail "ocsp-endpoint: status was not good"; }
    echo "[ocsp-endpoint] OK — POST transport accepted by openssl ocsp"

    # Also exercise the GET transport (base64-in-path), which is what schannel uses.
    local b64 enc
    "$OPENSSL" ocsp -issuer "$ca" -cert "$WORK/leaf-ocsppt.pem" -reqout "$WORK/ocsp-req.der" -no_nonce \
        >/dev/null 2>&1 || fail "ocsp-endpoint: could not build an OCSP request"
    b64="$(base64 < "$WORK/ocsp-req.der" | tr -d '\n')"
    enc="$(printf '%s' "$b64" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')"
    "$CURL" -sS "http://$revoc/ocsp/$enc" -o "$WORK/ocsp-resp.der" \
        || fail "ocsp-endpoint: GET request failed"
    "$OPENSSL" ocsp -respin "$WORK/ocsp-resp.der" -issuer "$ca" -cert "$WORK/leaf-ocsppt.pem" \
        -CAfile "$ca" -no_nonce 2>&1 | grep -q ": good" \
        || fail "ocsp-endpoint: GET response was not good"
    echo "[ocsp-endpoint] OK — GET (base64-in-path) transport also accepted"

    kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=""
}

# Revoked-serial control: a serial put in the responder's ledger is reported
# revoked by an OCSP client and listed in the CRL, while an unrelated serial
# stays good — proving the ledger actually drives a "fail closed" outcome.
run_revoked_control() {
    local ca="$WORK/ca-revoked.pem" out="$WORK/out-revoked.log" line revoc
    local serial="deadbeefdeadbeef"
    "$BIN" --upstream-revocation ocsp --leaf-revocation both --revoke-serial "$serial" \
        --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!
    line="$(wait_ready "$out")" || { cat "$out"; fail "revoked: harness never READY"; }
    revoc="$(echo "$line" | sed -n 's/.*revoc=\([^ ]*\).*/\1/p')"
    echo "[revoked] revoc=$revoc serial=$serial"

    "$OPENSSL" ocsp -issuer "$ca" -serial "0x$serial" -url "http://$revoc/ocsp" -CAfile "$ca" 2>&1 \
        | grep -qi "revoked" || fail "revoked: OCSP did not report the serial revoked"
    "$OPENSSL" ocsp -issuer "$ca" -serial "0x01" -url "http://$revoc/ocsp" -CAfile "$ca" 2>&1 \
        | grep -q ": good" || fail "revoked: an unrelated serial was not reported good"
    "$CURL" -sS "http://$revoc/crl" | "$OPENSSL" crl -inform DER -text -noout 2>/dev/null \
        | tr -d ' :' | grep -qi "$serial" || fail "revoked: serial not listed in CRL"
    echo "[revoked] OK — revoked serial reported revoked (OCSP) and listed (CRL)"

    kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=""
}

for kind in ocsp crl none; do run_scenario "$kind"; done
run_crl_endpoint
run_ocsp_endpoint
run_revoked_control

# Real-crates.io leg needs network; CI always has it, local dev may not.
if "$CURL" -sS --max-time 15 -o /dev/null https://index.crates.io/config.json 2>/dev/null; then
    run_connect
else
    msg="cannot reach index.crates.io (no network?); skipping real-crates.io checks"
    [ "$REQUIRE" = "1" ] && fail "$msg"
    echo "SKIP: $msg" >&2
fi

echo "ALL OCSP RELAY GATE SCENARIOS PASSED"
