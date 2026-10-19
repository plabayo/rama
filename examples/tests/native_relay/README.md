# Native relay wire test

Runs an independent Go client → Rama MITM relay → Go origin over TLS/H1,
TLS/H2 or QUIC/H3 (v1/v2). Rama uses `http-full,boring` with UA disabled.
Both network legs are captured and decrypted independently with tshark.

## Run

Requires Linux or macOS, Python 3.11+, Rust, Go (see `peer/go.mod`), OpenSSL,
and Wireshark with loopback capture permission. H3 needs tshark 4.6+.
No browser, Docker or system certificate installation is required.

```sh
python3 -m pip install -r examples/tests/native_relay/requirements.txt

just test-native-relay-contract /absolute/path/to/new-evidence h1 debug
just test-native-relay-contract /absolute/path/to/other-evidence h2 release
just test-native-relay-contract /absolute/path/to/quic-evidence h3 release 2
```

Use a new output directory for each run. Local tests and daily CI share this
runner. See `run.py --help` for offline runs, prebuilt binaries and interfaces.
The broad `--without-mirroring` control disables ingress-derived TLS and QUIC
mirroring; H2 SETTINGS and initial credit are always mirrored by the relay.
Owned processes and temporary private keys/keylogs are cleaned up afterward.
`artifacts/` contains the decoded reports shared with CI, including failed runs.
Raw captures and executables stay in the run directory and are not uploaded.

For fast tool regressions without builds or capture, install the shared browser
dependencies too (`rama-fp/browser_automation/requirements.txt`), then run
`just test-profile-tools`. Regular CI runs the same command.

## Coverage and limits

- HTTP: nine GET/POST/HEAD contracts, fixed-length and streamed bodies (including
  empty streams), trailers, 204/304 responses and connection reuse.
- Headers: exact spelling/order/duplicates, with exotic H1 casing in both directions;
  H2/H3 names follow their required lowercase encoding.
- WebSocket: H1 Upgrade or H2/H3 Extended CONNECT; greeting, text/binary echo,
  fragmentation, ping/pong and normal close. Tunnel bytes must match literally.
- Wire: supported TLS offer facts and fresh cryptographic values; ordered
  H2/H3 SETTINGS; H3 Initial layouts, transport parameters and connection IDs.

Initial H2 connection credit is checked separately for HTTP and WebSocket
captures through each sender's first complete decoded HEADERS. Targets compare
cumulatively; frame counts remain visible, and credit after opposite-role DATA
before that boundary is refused. The client's target must match on both hops,
even with `--allow-differences`; each server's credit is its own and reported only. HTTP and WebSocket captures use the same native
TLS/SETTINGS/QUIC connection checks, with each result retained separately. Reduced
WebSocket fixtures check tunnel bytes and credit only; complete handshake evidence
is required by the actual runner.

**A passing contract does not establish full fingerprint transparency.** The
`just` recipe and daily job allow measured differences, recorded explicitly in
`comparison.json`: TLS extension membership, H1 hop framing, per-hop SETTINGS
and QUIC layouts/parameters can differ. Compression history, negotiated
WebSocket compression and sustained traffic are outside this bounded test.

Relay behaviour behind these limits:

- The H3 relay waits (within its settings timeout) for the client's SETTINGS
  before it opens egress, so the mirrored SETTINGS are the client's own.
- Only QUIC transport parameters and H2/H3 SETTINGS this stack implements, plus
  GREASE, are relayed: a peer may act on an extension it understands and the relay
  does not. Dropped entries and lowered values are traced at debug level.
- Server push is not relayed: the relay refuses any PUSH_PROMISE it receives
  from the origin.
- HPACK/QPACK dynamic-table history, steady-state H2 WINDOW_UPDATE cadence and
  H1 chunk boundaries are per-hop and never preserved; H1 framing kind
  (chunked vs Content-Length) is.

For strict fingerprint comparison, invoke `run.py` directly; it fails on
measured differences unless `--allow-differences` is supplied.

H3 fixtures exclude Retry; production address validation is unchanged.
`--retry ingress|egress` and `--without-mirroring` provide negative controls.
Checked-in fixtures contain synthetic decoded traffic, not keys or customer data.
