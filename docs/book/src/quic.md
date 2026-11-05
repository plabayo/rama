# QUIC

QUIC is a transport protocol that runs over UDP and builds TLS 1.3 into its handshake.
It gives an application what TCP and TLS give it together, and some things they cannot:
several ordered, reliable streams on one connection that do not block each other,
unreliable datagrams next to those streams, and a handshake that authenticates the peer
before any application data moves. HTTP/3 runs on top of it, but QUIC is a transport of
its own and can run any protocol you design.

See [`rama::quic`](https://ramaproxy.org/docs/rama/quic/index.html) for the API.
It is available with the `quic` feature, plus a TLS backend (see below).

## What Rama offers

- **Endpoints**: an `Endpoint` owns one UDP socket and multiplexes connections over it.
  The same endpoint can accept connections (with a `ServerConfig`) and dial them.
- **Connections**: a `Connection` opens and accepts streams, sends and reads datagrams,
  reports its negotiated TLS parameters and statistics, and closes with an application
  error code.
- **Streams**: bidirectional (`open_bi` / `accept_bi`) and unidirectional
  (`open_uni` / `accept_uni`) streams. Each stream is ordered and reliable on its own;
  loss on one stream does not delay the others.
- **Datagrams**: unreliable DATAGRAM frames (RFC 9221) through `send_datagram` and
  `read_datagram`, bounded by `max_datagram_size`.
- **Versions**: QUIC v1 (RFC 9000) and v2 (RFC 9369), with compatible version negotiation
  (RFC 9368) between them. See the [Transport Protocols](./transport.md) chapter for the
  version policies.
- **0-RTT**: resumed clients can send early data when you enable it (off by default). See
  [Early data and HTTP 425](./http/early_data.md) for how Rama keeps replay decisions
  explicit.
- **Observability**: qlog recording, connection and endpoint statistics, and optional
  OpenTelemetry metrics (`opentelemetry` feature).
- **Wire profiles**: [`rama::quic::proto`](https://ramaproxy.org/docs/rama/quic/proto/index.html)
  is the packet and frame codec without the engine. Its profiles describe a client's
  observable wire image, used for user-agent emulation and fingerprinting.

## TLS backend

QUIC always uses TLS 1.3. Rama builds the QUIC TLS configuration from the same
`TlsClientConfig` and `TlsServerConfig` used for TCP (see [TLS and certificates](./tls.md)),
through `ClientConfig::try_from_rama_tls` and `ServerConfig::try_from_rama_tls`.
Pick one backend:

- `quic,boring` for BoringSSL;
- `quic,rustls,ring` or `quic,rustls,aws-lc` for Rustls with a crypto provider.

A custom TLS implementation can be plugged in through `rama::quic::tls::provider`.

## Where it fits

QUIC follows the same service model as TCP and UDP:

- On the server side, `Endpoint::serve` hands every established `Connection` to a
  `Service<Connection>`, each in its own task, with graceful shutdown.
- On the client side, `QuicConnector` is a connector service for a `ConnectRequest`,
  like a TLS connector over a stream connector. It races resolved addresses and can run
  over a shared endpoint or one endpoint per connection, including a UDP tunnel through
  a [MASQUE proxy](./proxies/masque.md).
- [`rama::quic::proxy`](https://ramaproxy.org/docs/rama/quic/proxy/index.html) provides
  interception building blocks: admission limits, a ClientHello peek on the Initial
  flight, a terminating relay, and (with BoringSSL) a MITM relay.

## Examples

- [/examples/src/quic_client_server.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_client_server.rs):
  an authenticated QUIC client and server exchanging a bidirectional request and a
  unidirectional upload, with optional qlog recording.
- [/examples/src/quic_terminating_relay.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_terminating_relay.rs):
  a QUIC stream proxy that terminates TLS on both sides and relays each client stream.
- [/examples/src/quic_h3_mitm_proxy.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_h3_mitm_proxy.rs):
  peek each ClientHello, terminate HTTP/3 for selected server names and forward everything else.
- [/examples/src/http3_client_server.rs](https://github.com/plabayo/rama/blob/main/examples/src/http3_client_server.rs):
  HTTP/3 on top of QUIC, see the [HTTP/3](./http/http3.md) chapter.
