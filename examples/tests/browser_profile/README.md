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
TLS fixtures also need OpenSSL; Firefox TLS needs NSS `certutil`. Selenium Manager
discovers browser executables
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

## TLS H2 replay and H3 original-traffic capture

With a CLI containing the JSON profile viewer:

```sh
python3 examples/tests/browser_profile/run.py \
  --rama target/debug/rama --protocol h3 --output /absolute/path/to/new-evidence
```

Use `--protocol h2` for HTTP/2. The TLS H2 fixture supports Chrome, Edge and
Firefox (`--browser firefox`).
Firefox trusts only the fixture CA in a new NSS profile, which is removed after
the run; certificate checks remain enabled. H3 currently supports Chrome and Edge
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

For H3, `quic_wire.py` also compares the complete first flight, transport
parameters and client SETTINGS together with TLS from the same retained joint.
The decoder keeps fragment-only Initial packets, checks raw integer/frame
extents, and verifies parameter order/literals or redacted binding lengths.
Packet numbers are tshark's decrypted results; their encrypted bytes are not
interpreted as plaintext.

`h3_sequence_wire.py` checks the retained decoder context, unidirectional stream
IDs/types and control-frame prefix contents against bounded reassembly of
independently decoded QUIC STREAM payloads. It handles out-of-order fragments
and retransmissions, and rejects gaps, conflicting overlaps and incomplete frame
extents. The decoder context comes from the server's SETTINGS; the browser's
own SETTINGS describe the other direction. Role/capability advertisements are
separate from that decoder context.

These sequence facts must match the same retained TLS/QUIC joint. Reports mark
Http3Sequence as partially verified: packet arrival cannot establish the exact
application first-request freeze or relative parser scheduling across streams.
A later control frame does not invalidate an earlier captured prefix.

`qpack_wire.py` verifies encoder instruction prefixes too. Raw prefixes determine
instruction kinds, indices, capacities and Huffman flags; tshark independently
decodes Huffman names. Its instruction bytes must reconstruct the entire decoded
encoder stream exactly, preventing missing, duplicated or reordered dissection
from proving a match. Inserted values remain discarded, and names contribute only
their decoded lengths. A nonempty retained instruction prefix also requires its
encoder stream in the captured stream events. Instructions retain their own
stream order; no order relative to control events is invented.

These checks establish retained capture dimensions, not native H3 replay support
or every possible wire property. The exact recorder cutoff remains unverified
for both control frames and encoder instructions.

HTTP/2 also replays all six operations for every retained connection variant.
Each CLI process uses the fixture CA through `--cacert` and explicit newly generated
fixture trust IDs through `--tls-requested-trust-anchors` when the original browser
advertised them. These IDs replace discarded per-connection identifiers; they do
not configure certificate verification. Negative probes require missing CA/ID
bindings to fail. Every replay request must match one complete original method,
path, ordered-header and body tuple. TLS and H2 SETTINGS/WINDOW_UPDATE/PRIORITY
prefixes must match the same retained connection joint; peer-driven SETTINGS ACKs
are excluded from this fingerprint projection, as they are from native replay.
The optional first-request stream WINDOW_UPDATE is checked against the same
stream immediately after its complete HEADERS (including CONTINUATION), allowing
intervening peer ACKs. It is a recorded per-request window policy; the exact
application dispatch cutoff is not inferred from packet arrival. Requestless
preconnections cannot contribute prefix evidence or invalidate used connections.
Firefox's `TE: trailers` remains an explicit current request binding on every flow.
The drain waits for every expected variant, not only one complete set of flows.
TLS replay also runs `rama ua compare --replay` against separate replay storage.
That mode excludes only H2 SETTINGS acknowledgements and reports the exclusion;
all remaining retained fields and complete joint membership stay exact.
`--literal` remains available for byte-exact retained tuples and can report a
legitimate peer-ACK timing difference.

**HTTP/3 still verifies original capture without native QUIC replay.** Its TLS,
transport-parameter, first-flight and control/QPACK sequence compilation remains
unfinished. The full protocol matrix, compression comparisons, long-lived
bidirectional WebSocket traffic and distribution fidelity remain separate work.

## Evidence and maintenance

Output directories must be new. They contain archives, packet captures, decoded
packets, comparisons and logs. TLS private keys and session logs are deleted after
decoding, including failures; private browser profiles are removed. Keep output
private: decoded packets contain fixture traffic. No transparent proxy is enabled.

Fixed seed, connection and request keys make profile draws reproducible within an
archive. TLS H2 tests also pin each retained connection variant explicitly, so a
fixed draw cannot silently miss a different GREASE order or ECH shape. These keys
do not make independently collected browser profiles identical.

Run the shared journey, BrowserStack collector and packet-verifier unit checks:

```sh
python3 scripts/ci/check_browser_automation.py
```

This runs normal and optimized Python so required checks cannot disappear under
`-O`. The local integration recipes use this same prerequisite. Reversion guards
must demonstrate that changing a check makes its regression fail in both modes.
