# HTTP/3

HTTP/3 (RFC 9114) runs HTTP over [QUIC](../quic.md) instead of TCP. Each request gets
its own QUIC stream, so a lost packet only delays the request it belongs to, and the TLS
handshake is part of the QUIC handshake. Header compression uses QPACK (RFC 9204).

In Rama, HTTP/3 uses the same `Request`, `Response`, body and `Service` types as HTTP/1.1
and HTTP/2. A web service written for TCP serves HTTP/3 without changes; only the server
and connector around it differ.

HTTP/3 needs the `http-backend` and `quic` features and a TLS backend: `boring`, or
`rustls` with `ring` or `aws-lc`. `http-full` includes `quic` and everything the default
client needs.

## Servers

`HttpServer::auto` serves HTTP/1.1 and HTTP/2 over a TCP stream.
`HttpServer::new_http3` serves QUIC connections that negotiated the `h3` ALPN. Its
`service` method turns your HTTP service into a service for QUIC connections, which a QUIC
[`Endpoint`](https://ramaproxy.org/docs/rama/quic/struct.Endpoint.html) configured with an
`h3` TLS config can `serve`. See
[`HttpServer`](https://ramaproxy.org/docs/rama/http/server/struct.HttpServer.html) and the
[`http3_client_server`](https://github.com/plabayo/rama/blob/main/examples/src/http3_client_server.rs)
example.

`server.http3().configure_transport(..)` applies the HTTP/3 receive limits to the QUIC
transport config. On graceful shutdown the server sends GOAWAY and finishes in-flight
requests.

Browsers first connect over TCP and learn about HTTP/3 from an `Alt-Svc` response header.
To offer both, run an `auto` server on TCP and an HTTP/3 server on UDP, and advertise the
UDP port with the typed `AltSvc` header from `rama::http::headers`.

## Clients

With a QUIC TLS backend enabled, `DefaultHttpWebClient` supports HTTP/3 in two ways:

- a request with `Version::HTTP_3` goes straight to HTTP/3;
- otherwise the client learns `Alt-Svc` advertisements and uses HTTP/3 for later requests
  to the same origin, falling back to the origin connection when that fails.

For your own stack, build an `Http3Connector` and add it with
`EasyHttpConnectorBuilder::with_http3_support`. HTTP/3 connections share the multiplexed
connection pool with HTTP/2. See
[Alternative services and custom connectors](./http_clients.md#alternative-services-and-custom-connectors)
for discovery, caching and the contracts for custom connectors.

## Early data, WebSockets and MASQUE

- **Early data**: resumed clients can send requests in QUIC 0-RTT. This is off by default.
  See [Early data and HTTP 425](./early_data.md).
- **WebSockets**: RFC 9220 bootstraps a WebSocket with Extended CONNECT on an HTTP/3
  stream. Servers opt in by setting `extended_connect` in the HTTP/3 config. See
  [WebSockets](./ws.md#h3-websocket-support).
- **MASQUE**: HTTP/3 supports HTTP datagrams (RFC 9297), which
  [MASQUE proxies](../proxies/masque.md) use to tunnel UDP and IP.

The `rama` CLI supports HTTP/3 too: `rama send --http3 <url>` requires it, and
`rama serve echo --mode https` serves HTTP/3 next to HTTP/1.1 and HTTP/2.

## API

- [`rama::http::server`](https://ramaproxy.org/docs/rama/http/server/index.html): `HttpServer`.
- [`rama::http::client::h3`](https://ramaproxy.org/docs/rama/http/client/h3/index.html): the HTTP/3 connector.
- [`rama::http::core::h3`](https://ramaproxy.org/docs/rama/http/core/h3/index.html): the HTTP/3 engine, connection config and QPACK.
- [`rama::http::layer::alt_svc`](https://ramaproxy.org/docs/rama/http/layer/alt_svc/index.html): Alt-Svc discovery.

## Examples

- [/examples/src/http3_client_server.rs](https://github.com/plabayo/rama/blob/main/examples/src/http3_client_server.rs):
  an HTTP/3 server echoing a streamed body with trailers, and a pooled client.
- [/examples/src/ws_over_h3.rs](https://github.com/plabayo/rama/blob/main/examples/src/ws_over_h3.rs):
  WebSockets over HTTP/3, client and server.
- [/examples/src/http_early_data.rs](https://github.com/plabayo/rama/blob/main/examples/src/http_early_data.rs):
  an HTTP/3 client, an HTTP/3 gateway and an HTTP/1 origin handling 425 recovery.
- [/examples/src/quic_h3_mitm_proxy.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_h3_mitm_proxy.rs):
  terminate HTTP/3 for selected server names and forward the rest.
- [/examples/src/masque_connect_udp_proxy.rs](https://github.com/plabayo/rama/blob/main/examples/src/masque_connect_udp_proxy.rs):
  HTTP/3 through a CONNECT-UDP proxy.
