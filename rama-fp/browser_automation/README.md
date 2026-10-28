# Shared browser capture journey

`workflow.run_capture_flow` drives the fp application's own page. Both the nightly
BrowserStack collector and local/CI round-trip tests call this function. It does
not recreate fetch, XHR, WebSocket or form requests in Python: the browser runs
`rama-cli/assets/script.js`, then Selenium clicks the native form buttons.

| Operation | Request | Profile initiator |
| --- | --- | --- |
| Navigation | GET /report | Navigate |
| Fetch | POST /api/fetch/number/{number}, JSON body | Fetch |
| XMLHttpRequest | POST /api/xml/number/{number}, JSON body | Xhr |
| WebSocket | /api/ws, requested subprotocols a and b, greeting, UTF-8 echo and normal close | Ws |
| POST form | POST /form, URL-encoded body | Form |
| GET form | GET /form?source=web&turtles=yes | Form |

WebSockets use HTTP/1 Upgrade with a 101 response or HTTP/2/3 Extended CONNECT
with a successful 2xx response. An H3 page does not establish an H3 WebSocket:
the workflow requires the requested HTTP version and records the WebSocket's
actual transport separately.
The POST form response contains a second GET form; both submissions are required.
The page requires one browser-to-server UTF-8 message and its exact server echo,
then a clean normal close, before reporting success. This tests one bidirectional
text round trip; sustained traffic, binary messages and compression comparisons
remain separate coverage.

## Responsibilities

- `workflow.py`: the shared six-operation journey and per-flow protocol assertions.
- `drivers.py`: local/remote session ownership and guaranteed `quit()` after a
  workflow failure. Selenium Manager discovers executables; pinned installations
  may pass a binary explicitly. No macOS application path is embedded here.
- `../browserstack/main.py`: remote capabilities, storage authorization cookies,
  scheduling, and BrowserStack status. Failures propagate to the process exit.
- Local round-trip runner: isolated database and CLI fp server, packet capture,
  profile export, CLI replay, independent wire decoding and comparisons.

The browser's protocol report is an early check, not independent fingerprint
proof. The round-trip runner must compare decoded reference packets with captured
profile fields, then compare replay packets with the selected profile/reference.
TLS/QUIC secrets must stay in private temporary files while tshark decrypts; they
must be removed and pcapng decryption-secrets blocks stripped before publishing
artifacts. The CLI fp server's key log also supports browsers such as Safari that
do not expose a browser key-log launch option.

## Local driver configuration

Python and Selenium come from the locked uv environment in `examples/tests`. Selenium manages a matching
driver. Node 18+ runs the page-script regressions in the common test checker.
If an old driver in PATH overrides it, `SE_SKIP_DRIVER_IN_PATH=true` asks
Selenium Manager to resolve a compatible driver instead. Explicit browser paths
are optional; a fresh profile is mandatory for Chrome, Edge and Firefox. Safari
uses SafariDriver's isolated Automation windows and requires Remote Automation to
already be enabled. The runner does not change that system preference.

`prepare_profile(path)` can install a fixture CA before Chrome/Firefox starts.
Certificate verification remains enabled. A fixture-specific Chrome SPKI exception
can be supplied through options; global certificate-check disabling is unnecessary.
Shared options retain default protocol capabilities, including WebSocket transport.
The local isolated H3 fixture still seeds its loopback route explicitly; those
runs are labeled configured conformance evidence, not default-browser profiles.

## Current implementation status

The shared journey runs in BrowserStack and the common local/CI
`examples/tests/browser_profile/run.py` entry point. The local runner supports
plaintext/TLS H1 and TLS H2/H3 capture and CLI replay. All six operations must
complete. The five HTTP flows must use the requested version; WebSocket uses
its actual negotiated transport, which may differ from the page's version.

Independent packet checks cover request fields/bodies, retained TLS/QUIC facts,
connection joints and bidirectional WebSocket text/close frames. H1 checks
Upgrade/accept; H2/H3 check Extended CONNECT. H3 control/QPACK prefix checks
remain partial: packet arrival does not establish the application's exact freeze
or scheduling across streams. Full browser/platform coverage, sustained/binary
WebSocket traffic, compression comparisons and final acceptance remain open.
See the local runner's README for detailed checks and evidence limits.

Unit checks run identically in normal and optimized Python; use unittest checks,
not Python `assert`, for required validation. Guard experiments cover missing-flow
rejection, protocol fallback rejection, session cleanup, and inherited key-log
isolation. The real local/CI command must use all flows by default.

Chromium feature reference: https://chromium.googlesource.com/chromium/src/net/+/534118ccefa7635f959d4e6ea2fa511aec9930aa

Run all shared journey, collector and local-verifier unit tests with
`just rama-fp/test-tools`; this checks normal and optimized Python.

Nightly collection and local tests keep default WebSocket capabilities. The
isolated local H3 fixture explicitly selects its loopback QUIC route. A failed
WebSocket still allows both forms to be captured, then fails the cell; generic
browser errors cannot identify unsupported negotiation versus a network failure.
Two explicit WebSocket exceptions, detected from the user agent and, for Safari,
the session's OS release, follow shipped browser support: Safari before OS 26 and
Chrome 114 or older on the H2-only origin (Safari takes WebSocket over HTTP/2,
RFC 8441, from the OS 26 network stack, so Safari 26 on macOS 15 falls back to an
HTTP/1 Upgrade, as was observed for Chrome 114), and every browser except Safari on
OS 26.0 on the H3-only origin (the only shipped WebSocket over HTTP/3, RFC 9220;
26.1 opens WebSockets over TCP again). There an "unavailable" WebSocket raises `UnsupportedFlow`
once every other flow and both forms validated strictly; BrowserStack records
the cell as `unsupported` with an `unsupported_reason` and does not fail the
job. A WebSocket that reports a protocol is validated as usual.

The H3-only origin's TCP port serves a JS-free bootstrap door ("ラマ | HTTP/3")
that sends `Alt-Svc: h3` and refreshes once. If loading the report fails or
times out while the browser still shows that door, the cell is `unsupported`:
"browser stayed on TCP: did not switch to HTTP/3" when it returned over TCP, or
"browser did not leave the HTTP/3 bootstrap" on the switching page. Only
browsers observed to stay on TCP there (Safari, every iOS browser and every
Android browser) may be `unsupported`; desktop Chromium or Firefox stuck on the
door fails the cell, and BrowserStack fails the job when every H3 cell stayed on
the door. Such a cell also records `h3_control`, the transport the same session
gets from a public HTTP/3 site: on BrowserStack these browsers stay on HTTP/2
there too. BrowserStack starts Android Chrome behind an HTTP proxy, which rules out
QUIC, so the nightly job launches it with `--no-proxy-server`; Firefox for Android
and Safari offer no such switch there. Chromium moves a plain-HTTP navigation to
HTTPS when the origin also serves HTTPS (HTTPS-Upgrades) or publishes a DNS HTTPS
record, so its `http://` cells run with both features disabled; iOS Safari upgrades
too and has no such switch. Once the fp report is visible, every later
failure stays a failure, as does any other failure.

BrowserStack visits `https://fp` and `https://h3.fp` twice in one session, so later
connections (resumed handshakes) are captured too and a slow HTTP/3 switch gets a
second chance; the receipt lists each visit under `visits`. Profile analysis keeps a
resumed handshake only next to a full one on the same transport: a browser seen only
resuming over QUIC gets neither TLS/QUIC nor QUIC nor HTTP/3 in its profile.

Because BrowserStack's proxy keeps Safari and Firefox for Android off HTTP/3, the
nightly workflow runs the same collector on hosts it drives directly
(`just rama-fp/device OUTPUT KIND`): desktop Safari on GitHub's macOS runners, Safari
on every iOS Simulator runtime (`device-ios-simulators`) and Mozilla's Firefox for
Android builds on an emulator (`device-firefox-android`). Simulator and emulator run
the device's own browser and network code, so their captures are stored like
BrowserStack's. Each device run also asks `https://echo.ramaproxy.org` whether the
browser's TLS fingerprint (JA4) matches the embedded profile for its User-Agent,
recorded in `echo.json`: a mismatch fails the job, a User-Agent without a profile is
only recorded. JA4H is recorded too, without failing the job, because its
Accept-Language part follows the device locale.

BrowserStack retries a failed cell once in a fresh session (never an
`unsupported` one); the receipt records `attempts` and, after a retry, the
first attempt's `first_failure_stage` and `first_failure_reason`. Only a cell
failing both attempts fails the job. A device run also retries an H3 cell that
stayed on TCP: nothing there keeps QUIC away, so that is the browser's Alt-Svc timing.
