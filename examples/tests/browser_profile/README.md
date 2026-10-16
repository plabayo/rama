# Browser capture and replay checks

The browser runs the same journey as the nightly BrowserStack collector:
[`rama-fp/browser_automation`](../../../rama-fp/browser_automation/README.md).
Selenium drives the fp page's existing JavaScript and native forms. It does not
reimplement fetch, XHR or WebSocket requests in Python.

| Operation | Browser request |
| --- | --- |
| Navigation | GET `/report` |
| Fetch | POST `/api/fetch/number/{number}` with JSON and browser API observations |
| XHR | POST `/api/xml/number/{number}` with JSON |
| WebSocket | `/api/ws`, subprotocol offers `a,b`, server greeting and close |
| POST form | POST `/form`, `source=web&rating=3` |
| GET form | GET `/form?source=web&turtles=yes` |

The CLI fp server captures profiles and reports fingerprints. `rama ua export`
writes an archive. `rama send --emulate` is the replay client. Tshark independently
decodes browser/client packets; comparing the server's two profile archives alone
would not independently establish accurate capture.

## Setup

Use Python 3.11 or newer, Docker with a locally cached `postgres:17-alpine` image,
a supported browser, and tshark/dumpcap with loopback capture permission. Install
`rama-fp/browser_automation/requirements.txt` into your Python environment.
TLS fixtures also need OpenSSL. Selenium Manager discovers browser executables
and compatible drivers; explicit binary paths remain optional. Node is unnecessary.

Local packet/process integration currently supports macOS and Linux. Selenium's
shared journey is portable, but Windows packet/process integration has not been
validated. Default interfaces are `lo0` and `lo`; pass `--interface` to override.

## HTTP/1 capture and strict replay

```sh
just test-browser-profile /absolute/path/to/new-evidence h1 chrome
just test-browser-profile /absolute/path/to/another-new-evidence h1 firefox
```

The recipe runs all six operations by default. Use `test-browser-profile-release`
for the optimized CLI. The fourth argument `navigate` explicitly limits H1
coverage to navigation. All recipes and CI use `run.py --browser chrome|firefox|edge --protocol h1|h2|h3`.
Custom installations can pass `--browser-binary`; no application path is hardcoded.
H1 currently uses plaintext; H2/H3 use TLS. TLS H1 remains an uncovered matrix cell.

Each run provisions a disposable database, captures original browser traffic,
exports the profile, and replays each operation into a second isolated database.
The archive comparison requires complete retained coverage in all-flow mode.
The independent HTTP/1 validator checks method, path, ordered repeated headers,
values, bodies and the WebSocket Upgrade/accept exchange. Host/Origin and the
WebSocket nonce are normalized only after checking their request bindings.
`wire.py` owns H1/H2/H3 decoding and checks; `flows.py` owns flow classification
and replay inputs, and `capture.py` owns the protocol fixtures. Protocol-specific
functions preserve the distinct H1 Upgrade and H2/H3 stream semantics.

## H2/H3 original-traffic capture

With a CLI containing the JSON profile viewer:

```sh
python3 examples/tests/browser_profile/run.py \
  --rama target/debug/rama --protocol h3 --output /absolute/path/to/new-evidence
```

Use `--protocol h2` for HTTP/2. The current TLS fixture supports Chrome and Edge
(`--browser edge`). BrowserStack and these local runs share the journey and
protocol assertions. The fixture uses a temporary certificate with a specific
SPKI exception; it does not disable certificate verification globally. Configured
Chromium H3 runs explicitly enable its WebSocket-over-H3 feature and record flags.

Browser SSLKEYLOGFILE output lets tshark decrypt TLS/QUIC. The runner waits until
all operations are independently decoded before stopping capture. It checks
joint regular/pseudo-header order, multiplicity, retained literal values, request
body semantics, final successful responses, and the decoded WebSocket greeting.
Request-bound values are counted separately because profiles do not retain them. The same
bounded PDML output includes ClientHello evidence. `tls_wire.py` checks retained
TLS versions, cipher and extension order, and extension metadata against each
request-bearing connection; keys and ciphertext are excluded from the projection.
Preconnections without requests are reported separately.

**This TLS command currently verifies original capture, not strict replay.**
TLS/QUIC connection compilation, complete compression/connection comparisons and
the full replay matrix remain unfinished. Neither command proves long-lived
bidirectional WebSocket traffic or distribution fidelity.

## Evidence and maintenance

Output directories must be new. They contain archives, packet captures, decoded
packets, comparisons and logs. TLS private keys and session logs are deleted after
decoding, including failures; private browser profiles are removed. Keep output
private: decoded packets contain fixture traffic. No transparent proxy is enabled.

Fixed seed, connection and request keys make profile draws reproducible within an
archive. They do not make independently collected browser profiles identical.

Run the shared journey, BrowserStack collector and packet-verifier unit checks:

```sh
python3 scripts/ci/check_browser_automation.py
```

This runs normal and optimized Python so required checks cannot disappear under
`-O`. The local integration recipes use this same prerequisite. Reversion guards
must demonstrate that changing a check makes its regression fail in both modes.
