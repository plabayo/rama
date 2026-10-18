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
| WebSocket | `/api/ws`, subprotocol offers `a,b`, greeting, browser UTF-8 text, exact server echo and normal close |
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
and compatible drivers; explicit binary paths remain optional. Node 18+ runs the shared page-script regressions.

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
H1 uses plaintext by default. Pass `--tls` to `run.py`, or `true` as the fifth
recipe argument, for HTTPS/WSS. H2/H3 always use TLS. TLS runs require all six
operations and the same fixture-local certificate trust as H2/H3:

```sh
just test-browser-profile /absolute/path/to/new-tls-evidence h1 chrome all true
```

TLS H1 replays every retained connection variant, verifies the missing-CA refusal,
and checks the retained ClientHello fields/shapes on each request-bearing TCP
stream against independently decrypted traffic. `tls-comparison.json` records
these checks separately from exact H1 request tuples and archive comparisons.
Both the original and replayed H1 headers are independently compared with the
original inspected archive: exact spelling/order/multiplicity and retained literal
values must match one observation from the same browser and flow. Request-owned
values remain checked by the separate wire bindings. The independent WebSocket
frame checks described below cover both plaintext and TLS H1. Daily CI includes plaintext and TLS
H1 cells in debug and release; it runs this same entry point.

Each run provisions a disposable database, captures original browser traffic,
exports the profile, and replays each operation into a second isolated database.
The archive comparison requires complete retained coverage in all-flow mode.
The independent HTTP/1 validator checks method, path, ordered repeated headers,
values, bodies and the WebSocket Upgrade/accept exchange. Host/Origin and the
WebSocket nonce are normalized only after checking their request bindings.
`wire.py` owns H1/H2/H3 decoding and checks; `flows.py` owns flow classification
and replay inputs, and `capture.py` owns the protocol fixtures. Protocol-specific
functions preserve the distinct H1 Upgrade and H2/H3 stream semantics.

## TLS H2/H3 capture and replay

With a CLI containing the JSON profile viewer:

```sh
python3 examples/tests/browser_profile/run.py \
  --rama target/debug/rama --protocol h3 --output /absolute/path/to/new-evidence
```

Use `--protocol h2` for HTTP/2. The TLS fixtures accept Chrome, Edge and
Firefox (`--browser firefox`); acceptance still requires every requested flow
to use the selected protocol.
Firefox trusts only the fixture CA in a new NSS profile, which is removed after
the run; certificate checks remain enabled. Firefox H3 seeds a profile-local
[Alt-Svc test route](https://github.com/mozilla/gecko-dev/blob/master/netwerk/protocol/http/nsHttpHandler.cpp#L2665)
to the owned UDP listener and permits that private test root
without disabling certificate validation. BrowserStack and these local runs share the journey and
protocol assertions. Chromium uses the temporary certificate’s specific
SPKI exception; certificate verification is not disabled globally. Configured
Chromium H3 fixtures seed only the local QUIC route and certificate trust.
WebSocket support follows the installed browser defaults; experimental protocol
features are not enabled.

Firefox158 locally completed navigation/fetch/XHR over H3 but attempted TCP for
the WebSocket endpoint, which the UDP-only fixture correctly refused. That is an
incomplete cell, not H3 WebSocket coverage; the runner does not accept fallback
or skip the failed flow. Chrome provides the verified H3 WebSocket cell. The
local Edge launcher is shared with Chromium, but Edge is not installed on the
current verification host; accepting its arguments is not a local runtime pass.

Browser SSLKEYLOGFILE output lets tshark decrypt TLS/QUIC. The runner waits until
all operations are independently decoded before stopping capture. It checks
joint regular/pseudo-header order, multiplicity, retained literal values, request
body semantics, final successful responses, and the decoded WebSocket greeting
and bidirectional text payloads.
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
That mode reports two exclusions: H2 SETTINGS acknowledgements and QPACK dynamic
reference indexes, which address each connection's own compression table. Field
families, static indexes, Huffman/N flags, order and complete joint membership
remain exact. For H3, `replay-qpack-policy.json` independently compares those
choices with the original joint using raw field prefixes and tshark's resolved
name/value fields. The separate replay-capture check retains exact raw indexes.
Neither check claims byte-identical dynamic-table history or distribution fidelity.
The optional initial-request bootstrap is checked separately with the independent
ls-qpack decoder: its retained request ID must resolve in the same profile and
connection context, and every insertion must match the actual initial field's
name and value. Those values remain temporary; reports retain only counts.
Evicted or unavailable associations cannot establish a verified bootstrap.
`--literal` remains available for byte-exact retained tuples and can report a
legitimate peer-ACK timing difference.

HTTP/3 capture and native replay are under acceptance testing. The local runner
exercises TLS, QUIC first flights/parameters, startup controls and all six flows;
this does not by itself close the full protocol/browser/platform matrix. Later
critical-stream allocation evidence, independent relay transparency and long-lived
compression/session behavior still require their own checks.

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

## WebSocket application data

The page reports WebSocket success only after its greeting, one UTF-8 text
round trip and a clean normal close. Both nightly BrowserStack and local tests
drive this same page. The endpoint imposes a deadline so a silent client cannot
hold a probe open. CLI replay keeps stdin open while waiting for the echo;
closing stdin immediately would race the CLI's close handshake.

All three protocols use the same greeting and text-echo contract. H2/H3 packet
checks bind it to the HTTP stream. H1 checks bind every decoded frame to its
Upgrade TCP connection, verify client/server masking, and require normal close
frames in both directions. TLS H1 uses the browser and replay keylogs for the
same checks. `websocket-comparison.json` records the H1 results; the decoded
`*.websocket.pdml` files remain available after ephemeral keys are deleted.

This is one text exchange: binary messages, sustained traffic, deliberate
fragmentation and a compression-negotiation matrix remain separate coverage work.
Tshark decompresses the text from the actual negotiated browser session.


H3 wire verification requires tshark 4.6 or newer, including per-frame stream
identities. Both runners check that schema before allocating fixtures or databases;
packet-wide stream guessing would be unsafe when QUIC multiplexes streams. The
daily browser/native jobs use Ubuntu 26.04, whose distribution package supplies
that decoder. Older tshark versions remain usable for H1/H2.
