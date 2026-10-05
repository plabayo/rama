#!/usr/bin/env bash
set -euo pipefail

endpoints=(
    "http://echo.ramaproxy.org;--http1.1"
    "http://echo.ramaproxy.org;--http2"
    "https://echo.ramaproxy.org;--http1.1"
    "https://echo.ramaproxy.org;--http2"
    "https://fp.ramaproxy.org;--http1.1"
    "https://fp.ramaproxy.org;--http2"
    "http://fp.ramaproxy.org;--http1.1"
    "http://fp.ramaproxy.org;--http2"
    "https://h1.fp.ramaproxy.org;--http1.1"
    "http://h1.fp.ramaproxy.org;--http1.1"
    "http://ipv4.ramaproxy.org;--http1.1"
    "http://ipv4.ramaproxy.org;--http2"
    "https://ipv4.ramaproxy.org;--http1.1"
    "https://ipv4.ramaproxy.org;--http2"
    # Do not test ipv6 one as some networks,
    # including in CI can have flaky IPv6 support... sigh
    # "https://ipv6.ramaproxy.org;--http1.1"
    # "https://ipv6.ramaproxy.org;--http2"
    "http://http-test.ramaproxy.org;--http1.1"
    "http://http-test.ramaproxy.org;--http2"
    "https://http-test.ramaproxy.org;--http1.1"
    "https://http-test.ramaproxy.org;--http2"
    "https://echo.ramaproxy.org;--http3"
    "https://ipv4.ramaproxy.org;--http3"
    "https://http-test.ramaproxy.org;--http3"
)

# curl rarely ships HTTP/3: those checks use rama itself, a local binary when
# RAMA_BIN is set or else the published image.
http3_check() {
  if [ -n "${RAMA_BIN:-}" ]; then
    "$RAMA_BIN" --http3 --fail --max-time 15 -o /dev/null "$1"
  else
    docker run --rm "${RAMA_IMAGE:-glendc/rama:edge}" --http3 --fail --max-time 15 -o /dev/null "$1"
  fi
}

failed=0

for entry in "${endpoints[@]}"; do
  IFS=";" read -r url flags <<< "$entry"

  echo "Checking $url"
  echo "Flags: ${flags:-<none>}"

  if [ "$flags" = "--http3" ]; then
    if http3_check "$url"; then
      echo "OK $url over HTTP/3"
    else
      echo "FAIL $url over HTTP/3"
      failed=1
    fi
    echo
    continue
  fi

  status=$(curl -s -o /dev/null -w "%{http_code}" $flags "$url" || echo "curl_failed")

  if [ "$status" = "curl_failed" ]; then
    echo "Request failed for $url"
    failed=1
  elif [ "$status" -ge 200 ] && [ "$status" -lt 400 ]; then
    echo "OK $url returned $status"
  else
    echo "FAIL $url returned $status"
    failed=1
  fi

  echo
done

if [ "$failed" -ne 0 ]; then
  echo "One or more endpoints failed"
  exit 1
fi

echo "All endpoints healthy"
