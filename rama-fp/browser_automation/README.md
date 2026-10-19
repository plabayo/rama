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

Install `requirements.txt` using Python 3.11 or newer. Selenium manages a matching
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
`just test-browser-automation`; this checks normal and optimized
Python and is the same prerequisite used by the local integration recipes.

Nightly collection and local tests keep default WebSocket capabilities. The
isolated local H3 fixture explicitly selects its loopback QUIC route. A failed
WebSocket still allows both forms to be captured, then fails the cell; generic
browser errors cannot identify unsupported negotiation versus a network failure.
