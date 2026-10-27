# Independent HTTP/3 interop

This standalone Cargo project exercises Rama against the pinned quic-go peer in
[`examples/tests/masque_interop/peer`](../../../examples/tests/masque_interop/peer/).
It shares that Go module and lockfile with the CONNECT-UDP tests. No second copy
of quic-go or masque-go is maintained here.

Both directions require correct status, HTTP/3 version, exact body bytes, and
SHA-256 response trailers. The workload includes a 2 MiB streamed upload, eight
concurrent requests, cancellation of a 16 MiB response, and a subsequent request
on the same QUIC connection. Small receive windows force both MAX_DATA and
MAX_STREAM_DATA updates, which are asserted from Rama's counters. The Rama
server test also requires STOP_SENDING and RESET_STREAM counters, and requires
the cancelled response producer to drop before completing the follow-up request.
It joins its connection tasks so background failures fail the test.

```sh
go -C examples/tests/masque_interop/peer build -o /tmp/rama-http-peer .
just examples/tests/http3-interop /tmp/rama-http-peer boring
just examples/tests/http3-interop /tmp/rama-http-peer rustls-ring
just examples/tests/http3-interop /tmp/rama-http-peer rustls-aws-lc
```

The tests are ignored in ordinary `cargo test` because they require the external
binary. The recipe explicitly includes them and requires `RAMA_HTTP_INTEROP_PEER`;
an absent peer fails rather than silently skipping. PR CI runs all three backends.
Ephemeral test certificates are trusted explicitly in these direct H3 tests.

quic-go uses static QPACK/literal fields. A separate live aioquic/ls-qpack test
uses the existing locked `aioquic-interop` uv environment (uv must be installed).
It requires dynamic references and encoder/decoder instructions in both directions.
The independent peer sends response field sections before their insertions and
holds the encoder stream at an explicit barrier. Only after Rama's qlog records
`field_section_blocked` does the test release those insertions; it then requires
`field_section_unblocked`, the exact decoded headers, and response body. This
covers live compression state and blocked-stream progress without timing races.

These tests are interoperability coverage, not exhaustive HTTP/3 conformance.
WebTransport and MASQUE CONNECT-IP are outside their scope. See the shared
harness for CONNECT-UDP and tunneled HTTP/3 coverage.
