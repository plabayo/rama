#!/bin/bash
set -eu

client=/opt/c-icap/bin/c-icap-client
mode=${1:-normal}
host=${2:-127.0.0.1}
port=${3:-1344}
backend=${4:-reference}
work=$(mktemp -d)

case "$backend" in
    reference|rama) ;;
    *)
        printf 'backend must be reference or rama, got: %s\n' "$backend" >&2
        exit 2
        ;;
esac

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

small="$work/small.txt"
large="$work/large.txt"
html="$work/page.html"
plain_html="$work/plain.html"

printf 'rama ICAP oracle body\n' > "$small"
dd if=/dev/zero bs=2048 count=1 2>/dev/null | tr '\000' x > "$large"
printf '<html><body>rama ICAP oracle</body></html>\n' > "$html"
printf '<body>no html element</body>\n' > "$plain_html"

scenario() {
    printf 'reference matrix: %s\n' "$1"
}

options() {
    service=$1
    "$client" -i "$host" -p "$port" -s "$service" -v > "$work/options-$service.txt" 2>&1
    grep -F 'ICAP/1.0 200' "$work/options-$service.txt" >/dev/null
    grep -F 'Methods:' "$work/options-$service.txt" >/dev/null
    grep -F 'ISTag:' "$work/options-$service.txt" >/dev/null
    grep -F 'Preview:' "$work/options-$service.txt" >/dev/null
}

echo_body() {
    name=$1
    method=$2
    input=$3
    shift 3
    output="$work/$name.out"
    rm -f "$output"
    "$client" -i "$host" -p "$port" -s echo -f "$input" -o "$output" "$method" \
        http://example.test/resource "$@"
    cmp "$input" "$output"
}

expect_204() {
    name=$1
    method=$2
    shift 2
    output="$work/$name.out"
    transcript="$work/$name.txt"
    rm -f "$output"
    "$client" -i "$host" -p "$port" -s echo -f "$small" -o "$output" \
        "$method" http://example.test/resource "$@" -v > "$transcript" 2>&1
    grep -F 'ICAP/1.0 204' "$transcript" >/dev/null
    test ! -e "$output"
}

probe_206() {
    name=$1
    input=$2
    expected_offset=$3
    expected_content_length=$4
    expected_marker=$5
    response="$work/$name.response"
    body_len=$(wc -c < "$input")
    request_headers=$'GET http://example.test/resource HTTP/1.1\r\nHost: example.test\r\n\r\n'
    printf -v response_headers 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "$body_len"
    res_body_offset=$((${#request_headers} + ${#response_headers}))

    exec 3<>"/dev/tcp/$host/$port"
    printf 'RESPMOD icap://%s/ex206 ICAP/1.0\r\n' "$host" >&3
    printf 'Host: %s\r\n' "$host" >&3
    printf 'Allow: 204, 206\r\n' >&3
    printf 'Preview: %s\r\n' "$body_len" >&3
    printf 'Connection: close\r\n' >&3
    printf 'Encapsulated: req-hdr=0, res-hdr=%s, res-body=%s\r\n\r\n' \
        "${#request_headers}" "$res_body_offset" >&3
    printf '%s%s' "$request_headers" "$response_headers" >&3
    printf '%x\r\n' "$body_len" >&3
    cat "$input" >&3
    printf '\r\n0; ieof\r\n\r\n' >&3
    timeout 10 cat <&3 > "$response"
    exec 3>&-

    grep -aF 'ICAP/1.0 206 Partial Content' "$response" >/dev/null
    grep -aF "Content-Length: $expected_content_length" "$response" >/dev/null
    grep -aF "0; use-original-body=$expected_offset" "$response" >/dev/null
    if test -n "$expected_marker"; then
        grep -aF "$expected_marker" "$response" >/dev/null
    fi
}

probe_complete_206() {
    response="$work/full206.response"
    body_len=$(wc -c < "$html")
    response_headers=$'HTTP/1.1 200 OK\r\nContent-Length: 43\r\n\r\n'

    exec 3<>"/dev/tcp/$host/$port"
    printf 'RESPMOD icap://%s/full206 ICAP/1.0\r\n' "$host" >&3
    printf 'Host: %s\r\n' "$host" >&3
    printf 'Allow: 204, 206\r\n' >&3
    printf 'Preview: %s\r\n' "$body_len" >&3
    printf 'Connection: close\r\n' >&3
    printf 'Encapsulated: res-hdr=0, res-body=%s\r\n\r\n' \
        "${#response_headers}" >&3
    printf '%s' "$response_headers" >&3
    printf '%x\r\n' "$body_len" >&3
    cat "$html" >&3
    printf '\r\n0; ieof\r\n\r\n' >&3
    timeout 10 cat <&3 > "$response"
    exec 3>&-

    grep -aF 'ICAP/1.0 206 Partial Content' "$response" >/dev/null
    grep -aF 'Content-Length: 22' "$response" >/dev/null
    grep -aF 'fully adapted by rama' "$response" >/dev/null
    if grep -aF 'use-original-body' "$response" >/dev/null; then
        return 1
    fi
}

probe_trailers() {
    response="$work/trailers.response"
    request_headers=$'POST http://example.test/resource HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Rama-Oracle\r\n\r\n'
    body_len=$(wc -c < "$small")

    exec 3<>"/dev/tcp/$host/$port"
    printf 'REQMOD icap://%s/echo ICAP/1.0\r\n' "$host" >&3
    printf 'Host: %s\r\n' "$host" >&3
    printf 'Connection: close\r\n' >&3
    printf 'Encapsulated: req-hdr=0, req-body=%s\r\n\r\n' \
        "${#request_headers}" >&3
    printf '%s' "$request_headers" >&3
    printf '%x\r\n' "$body_len" >&3
    cat "$small" >&3
    printf '\r\n0\r\nX-Rama-Oracle: complete\r\n\r\n' >&3
    timeout 10 cat <&3 > "$response"
    exec 3>&-

    grep -aF 'ICAP/1.0 200 OK' "$response" >/dev/null
    grep -aF 'rama ICAP oracle body' "$response" >/dev/null
    if test "$backend" = rama; then
        grep -aF 'X-Rama-Oracle: complete' "$response" >/dev/null
    elif grep -aF 'X-Rama-Oracle: complete' "$response" >/dev/null; then
        return 1
    fi
}

case "$mode" in
    normal)
        scenario 'OPTIONS echo'
        options echo
        scenario 'OPTIONS ex206'
        options ex206

        scenario 'REQMOD without an encapsulated body'
        "$client" -i "$host" -p "$port" -s echo -req http://example.test/resource

        scenario 'REQMOD Preview ending with ieof'
        echo_body reqmod-preview-ieof -req "$small"
        scenario 'REQMOD Preview followed by 100 Continue'
        echo_body reqmod-preview-continue -req "$large"
        scenario 'REQMOD zero-byte Preview'
        echo_body reqmod-preview-zero -req "$small" -w 0
        scenario 'REQMOD without Preview'
        echo_body reqmod-no-preview -req "$large" -nopreview

        scenario 'RESPMOD Preview ending with ieof'
        echo_body respmod-preview-ieof -resp "$small"
        scenario 'RESPMOD Preview followed by 100 Continue'
        echo_body respmod-preview-continue -resp "$large"
        scenario 'RESPMOD zero-byte Preview'
        echo_body respmod-preview-zero -resp "$small" -w 0
        scenario 'RESPMOD without Preview'
        echo_body respmod-no-preview -resp "$large" -nopreview

        scenario 'RESPMOD 206 with use-original-body'
        probe_206 ex206-modified "$html" 6 104 \
            '<!--A simple comment added by the  ex206 C-ICAP service-->'

        scenario 'RESPMOD 206 retaining the complete original body'
        probe_206 ex206-original "$plain_html" 0 29 ''

        scenario 'RESPMOD without 206 negotiation falls back to 204'
        output="$work/ex206-disabled.out"
        transcript="$work/ex206-disabled.txt"
        "$client" -i "$host" -p "$port" -s ex206 -f "$html" -o "$output" \
            -resp http://example.test/resource -v > "$transcript" 2>&1
        grep -F 'ICAP/1.0 204' "$transcript" >/dev/null
        test ! -e "$output"

        if test "$backend" = rama; then
            scenario 'RESPMOD 206 with a complete adapted body'
            probe_complete_206
        fi
        scenario 'REQMOD with encapsulated HTTP trailers'
        probe_trailers
        ;;
    204)
        scenario 'OPTIONS always-204 echo'
        options echo
        scenario 'REQMOD Preview returning 204'
        expect_204 reqmod-preview -req
        scenario 'REQMOD without Preview returning 204'
        expect_204 reqmod-no-preview -req -nopreview
        scenario 'RESPMOD Preview returning 204'
        expect_204 respmod-preview -resp
        scenario 'RESPMOD without Preview returning 204'
        expect_204 respmod-no-preview -resp -nopreview
        ;;
    *)
        printf 'usage: %s normal|204 [host [port [reference|rama]]]\n' "$0" >&2
        exit 2
        ;;
esac

printf 'reference matrix (%s): OK\n' "$mode"
