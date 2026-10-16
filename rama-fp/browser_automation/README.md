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
| WebSocket | /api/ws, requested subprotocols a and b, server greeting | Ws |
| POST form | POST /form, URL-encoded body | Form |
| GET form | GET /form?source=web&turtles=yes | Form |

WebSockets use HTTP/1 Upgrade with a 101 response or HTTP/2/3 Extended CONNECT
with a successful 2xx response. An H3 page does not establish an H3 WebSocket:
the workflow checks each reported protocol separately and rejects fallback.
The POST form response contains a second GET form; both submissions are required.
The page currently closes the WebSocket after the server greeting, so this journey
alone does not test long-lived bidirectional WebSocket traffic.

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
driver. If an old driver in PATH overrides it, `SE_SKIP_DRIVER_IN_PATH=true` asks
Selenium Manager to resolve a compatible driver instead. Explicit browser paths
are optional; a fresh profile is mandatory for Chrome, Edge and Firefox. Safari
uses SafariDriver's isolated Automation windows and requires Remote Automation to
already be enabled. The runner does not change that system preference.

`prepare_profile(path)` can install a fixture CA before Chrome/Firefox starts.
Certificate verification remains enabled. A fixture-specific Chrome SPKI exception
can be supplied through options; global certificate-check disabling is unnecessary.
All protocol-forcing/experimental flags must be recorded with evidence, since they
change the conditions of capture. Chromium's WebSocket-over-H3 implementation has
an `EnableWebsocketsOverHttp3` feature gate; a feature-enabled run must not be
presented as an unmodified-default-browser profile.

## Current implementation status

The shared journey is integrated with BrowserStack and the common local/CI
`examples/tests/browser_profile/run.py` entry point. H1 verifies strict replay;
H2/H3 currently verify original capture only. Full CLI validation is ongoing.
Real Chrome smoke runs pass all six operations over plain H1, TLS H1, H2 and H3.
Tshark decrypts the TLS H1/H2/H3 captures; H2/H3 show CONNECT /api/ws with
:protocol=websocket and 200 responses. H2/H3 joint capture header order and retained literal values also match tshark
for all six operations. Request-bound values are reported separately because the
profile does not retain them. TLS/QUIC fields, compression, bodies, full replay,
portability of capture/process control, and CI wiring remain unfinished. These
checks do not establish complete capture/emulation fidelity. Existing H1 packet validators retain their name
because their header parsing and Upgrade rules are specific to HTTP/1.

Unit checks run identically in normal and optimized Python; use unittest checks,
not Python `assert`, for required validation. Guard experiments cover missing-flow
rejection, protocol fallback rejection, session cleanup, and inherited key-log
isolation. The real local/CI command must use all flows by default.

Chromium feature reference: https://chromium.googlesource.com/chromium/src/net/+/534118ccefa7635f959d4e6ea2fa511aec9930aa

Run all shared journey, collector and local-verifier unit tests with
`python3 scripts/ci/check_browser_automation.py`; this checks normal and optimized
Python and is the same prerequisite used by the local integration recipes.

Nightly public collection keeps default browser options. Explicit H3 WebSocket
feature flags are confined to local/CI conformance fixtures; a BrowserStack session
label alone does not partition profiles by configuration. Unsupported/fallback
nightly cells remain visible failures, and the remote matrix still needs live
validation with BrowserStack credentials before claiming full coverage.
