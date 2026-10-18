# Native relay contract and wire differences

This test places Rama between an independent Go client and Go origin. Rama is
built through the umbrella crate with `--no-default-features --features
http-full,boring`. Both its normal/build/dev dependency graph and the running
fixture's feature flag must exclude UA. The test uses no profile archive,
profile selection or emulation adapter.

The TCP driver covers TLS/H1 and TLS/H2. The independent peer also speaks H3 for
QUIC interoperability fixtures; this driver does not claim QUIC/H3 verification.
The existing QUIC relay tests cover that transport separately.

## Run locally

Use Python 3.11+, Rust, the Go toolchain selected by `peer/go.mod`, OpenSSL and
Wireshark's `dumpcap`/`tshark`. Loopback capture permission is required. Linux and
macOS process/capture integration are supported; Windows has not been validated.
No Selenium, browser, Docker or system certificate installation is needed.

```sh
just test-native-relay-contract /absolute/path/to/new-evidence h1 debug
just test-native-relay-contract /absolute/path/to/other-evidence h2 release
```

The recipes and daily CI use `run.py`. It builds only the dedicated native test
executable and independent peer, starts owned loopback processes, and always
stops them and removes ephemeral private keys/keylogs. `--offline` requires all
Cargo/Go dependencies and the requested Go toolchain to be cached. Optional
`--fixture` and `--peer` paths allow reusing prebuilt binaries; their hashes are
recorded. Output must be a new directory. `--interface` overrides `lo0`/`lo`.

The CA signs a separate origin leaf and the relay's mirrored certificates. Go's
client verifies the CA chain and localhost identity. Each endpoint writes its
own keylog: ingress is decrypted with the external client's keys, egress with
the external origin's keys. The relay also writes its native keylog, but the
comparison does not depend on it. Decoded PDML remains available after cleanup.

## What is checked

One client connection carries GET and POST through the same relay/origin
connection. POST includes a body and request trailer; both responses include a
trailer. Duplicate request fields exercise multiplicity and ordering. The H1
client explicitly advertises `TE: trailers` and names TE in Connection; Rama's
existing H1 server policy omits response trailer values without that offer.

The independent decoder checks status, path, bodies, trailers, end-to-end field
spelling/order/values, connection reuse, supported mirrored TLS offer facts and
fresh random/key-share material. Hop fields are compared separately, not silently
called preserved. H2 SETTINGS retain their actual order and literal values in
both directions. No compressed HPACK byte-history equality is claimed.

Normal and optimized Python regressions use sanitized actual loopback
ClientHello/HTTP dissections under `tests/fixtures`. They contain public handshake
and known fixture bytes, not session keys, private keys or external/customer
traffic. Expected JSON snapshots describe the actual current differences.

## Strict fingerprint comparison

`run.py` defaults to strict comparison and fails after saving `comparison.json`
when any measured TLS/header/SETTINGS fingerprint differs. The contract recipe
and daily contract job pass `--allow-differences`: all functional/native contract
checks still apply, and `fingerprint_match` remains false when equality fails.
A green contract job therefore **does not establish full fingerprint
transparency**. For the strict result, run:

```sh
python3 examples/tests/native_relay/run.py --protocol h2 \
  --output /absolute/path/to/strict-evidence
```

Current Go 1.26/native Boring results expose these limitations:

- TLS extension membership differs for EC point formats and PSK exchange modes.
  The provider has no general knob for those choices at a TLS 1.3 minimum.
- Native mirroring's default unknown-value policy drops the two P-curve/ML-KEM
  hybrid groups and `signature_algorithms_cert` from this Go offer. These drops
  are reported; they are not evidence of a new missing opaque-extension provider
  API. Native configuration already has an explicit unknown-value policy.
- H1 hop framing is regenerated, including TE/Connection and transfer-coding
  field placement/case. End-to-end fields remain checked literally.
- The current H2 relay starts and configures each hop independently, so its
  SETTINGS differ. Exact startup mirroring requires additional native protocol
  coordination; a UA feature or profile wrapper cannot fix that boundary.

These are observable differences, not accepted fingerprint matches. The native
comparison reports them without relaxing UA replay admission or patching the
provider. Binary/fragmented WebSockets, sustained traffic and deliberate failure
injection are outside this small native TCP contract; browser journey checks
cover the supported WebSocket application exchange separately.

`--without-mirroring` is a negative control: the same native termination/HTTP
relay remains, but it does not consume the peeked ClientHello. Its changed
supported TLS offer must fail the contract even with `--allow-differences`.
