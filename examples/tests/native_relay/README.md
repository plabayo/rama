# Native relay contract and wire differences

This test places Rama between an independent Go client and Go origin. Rama is
built through the umbrella crate with `--no-default-features --features
http-full,boring`. Both its normal/build/dev dependency graph and the running
fixture's feature flag must exclude UA. The test uses no profile archive,
profile selection or emulation adapter.

The same driver covers TLS/H1, TLS/H2 and QUIC/H3 over QUIC v1 and v2.
The fixture selects native TCP/TLS or UDP/QUIC composition from that protocol;
HTTP and WebSocket probes and comparisons share the same runner.

## Run locally

Use Python 3.11+, Rust, the Go toolchain selected by `peer/go.mod`, OpenSSL and
Wireshark's `dumpcap`/`tshark`. Loopback capture permission is required. Linux and
macOS process/capture integration are supported; Windows has not been validated.
Install the pinned decoder libraries once in your Python environment:

```sh
python3 -m pip install -r examples/tests/native_relay/requirements.txt
```

No Selenium, browser, Docker or system certificate installation is needed.

```sh
just test-native-relay-contract /absolute/path/to/new-evidence h1 debug
just test-native-relay-contract /absolute/path/to/other-evidence h2 release
just test-native-relay-contract /absolute/path/to/quic-evidence h3 release 2
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
comparison does not depend on it. Decoded PDML and bounded TLS-follow plaintext remain available after cleanup;
all payloads belong to the generated fixture.

## What is checked

One client connection carries GET and POST through the same relay/origin
connection. POST includes a body and request trailer; both responses include a
trailer. Duplicate request fields exercise multiplicity and ordering. The H1
client explicitly advertises `TE: trailers` and names TE in Connection; Rama's
existing H1 server policy omits response trailer values without that offer.

The independent decoder checks status, path, bodies, trailers, end-to-end field
spelling/order/values, connection reuse, supported mirrored TLS offer facts and
fresh random/key-share material. Hop fields are compared separately, not silently
called preserved. H2/H3 SETTINGS retain actual order and literal values in both directions.
H3 also compares measured Initial flight layout and ordered transport parameters,
requires the requested wire version and checks fresh connection identities
separately from their fingerprint lengths. No compressed HPACK/QPACK byte-history
equality is claimed. Measured QUIC/SETTINGS differences remain explicit.

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
  SETTINGS differ. H3 likewise negotiates settings and QPACK independently.
  A UA feature or profile wrapper cannot fix that boundary.
- H3 Initial layout/CID lengths, added version-information and route-dependent
  parameters may differ under the native bounded mirror policy. The report lists
  both complete measured flights/parameter/settings offers and each equality
  result; legal per-hop differences are not silently called preserved.

These are observable differences, not accepted fingerprint matches. The native
comparison reports them without relaxing UA replay admission or patching the
provider. Each run also opens a WebSocket through the same running native relay. H1
uses Upgrade/101; H2 and H3 use Extended CONNECT/200. The peer requires a greeting,
UTF-8 text echo, binary echo, fragmented text echo, ping/pong and a normal 1000
close. The fixture uses Rama’s existing upgrade middleware with its byte-forward
service, without UA or WebSocket message rewriting. The owned Go peers enable
`GODEBUG=http2xconnect=1` to opt into x/net’s Extended CONNECT implementation.

Tshark decrypts each leg independently; h11 admits H1 Upgrade, the shared PDML decoder binds H2/H3 CONNECT, and wsproto
independently decodes WebSocket frames. The
verifier compares reassembled tunnel bytes literally, including frame masks and
fragmentation, and requires every probe in both directions. Wireshark’s WebSocket subdissector is disabled for this export because its
application reassembly can hide continuation bytes across DATA writes; TLS and
HTTP decoding stay enabled. H1 exports the decoded TLS stream, while H2/H3 use
reassembled DATA bytes from the shared PDML decoder. Sustained traffic and negotiated WebSocket compression remain
outside this bounded probe; no compression equality is claimed.

`--without-mirroring` is a negative control: the same native termination/HTTP
relay remains, but it does not consume the peeked ClientHello. Its changed
supported TLS offer must fail the contract even with `--allow-differences`.


H3 wire verification requires tshark 4.6 or newer, including per-frame stream
identities. Both runners check that schema before allocating fixtures or databases;
packet-wide stream guessing would be unsafe when QUIC multiplexes streams. The
daily browser/native jobs use Ubuntu 26.04, whose distribution package supplies
that decoder. Older tshark versions remain usable for H1/H2.


The native H3 fixture deliberately measures one Initial ClientHello flight per
leg. Both owned QUIC servers explicitly disable Retry for this bounded contract;
production relay address validation retains its normal default. Any Retry in a
captured leg fails with an explicit scope error before TLS/flight/tunnel matching.
The verifier does not merge tshark connection numbers across Retry or claim
Retry-aware fingerprint preservation. `--retry ingress|egress` deliberately
forces that unsupported path as a live negative control. Production Retry
behavior remains covered by its separate QUIC integration tests.
