# TLS and certificates

TLS authenticates the peer and encrypts the bytes of a connection. In Rama it is a layer
like any other: a TLS acceptor wraps a stream (for example from a `TcpListener`) before the
HTTP server sees it, and a TLS connector wraps the stream a client connector establishes.
QUIC uses the same configuration for its built-in TLS 1.3 handshake (see [QUIC](./quic.md)).

See [`rama::tls`](https://ramaproxy.org/docs/rama/tls/index.html) for the API.

## Backends and shared config

Rama has two TLS backends:

| Backend | Feature | Module |
| --- | --- | --- |
| BoringSSL | `boring` | [`rama::tls::boring`](https://ramaproxy.org/docs/rama/tls/boring/index.html) |
| Rustls | `rustls`, with `aws-lc` or `ring` as crypto provider | [`rama::tls::rustls`](https://ramaproxy.org/docs/rama/tls/rustls/index.html) |

Both are configured with the backend-neutral `TlsClientConfig` and `TlsServerConfig`
from `rama::tls::client` and `rama::tls::server`: ALPN, protocol versions, server
authentication, client verification, trust and keylog. Each backend has a
`TlsAcceptorLayer` that takes a `TlsServerConfig` and a `TlsConnectorLayer` for clients.
Settings that only one backend supports go through its extension traits
(`BoringServerConfigExt`, `RustlsServerConfigExt` and their client counterparts).

BoringSSL also offers what browser emulation needs, such as precise ClientHello control,
certificate compression and Encrypted Client Hello. Rustls is a pure Rust option.
The backend-neutral types also cover ClientHello parsing and peeking, JA3/JA4 fingerprints
and NSS keylog files, so a proxy can accept with one backend and connect with the other.

## Server certificates

A server presents `ServerAuthData`: a certificate chain and private key, loaded from PEM or
generated (self-signed, or issued by a generated CA) for tests and local tools.
To choose a certificate per connection:

- With BoringSSL, implement `DynamicCertIssuer` and configure it through
  `BoringServerConfigExt`. Issuance is async, can use the ClientHello and is cached.
- With Rustls, plug in a rustls certificate resolver, or select a whole server config per
  ClientHello with a dynamic config provider.

## Trust and verification

Clients verify servers against a `ServerTrustSource`:

- `Native` (default): the operating system's root store, read once, with the
  `SSL_CERT_FILE` / `SSL_CERT_DIR` overrides. If no native roots are found, the bundled
  WebPKI roots are used.
- `WebPki`: the bundled Mozilla roots, independent of the host.
- `Custom`: only the trust anchors you supply.
- `Platform`: the operating system's verifier decides (Apple platforms, Windows and Android).
  This follows enterprise trust settings and the platform's distrust and revocation policy.

The loaders and the platform verifier live in
[`rama::crypto`](https://ramaproxy.org/docs/rama/crypto/index.html) and work with both
backends.

On top of normal verification a client can pin the server leaf with `TlsServerCertPins`,
by SPKI SHA-256 digest or exact certificate, optionally scoped to server names.
See [server certificate pinning](./http/http_clients.md#server-certificate-pinning).

## Client authentication (mTLS)

A server asks for client certificates with `ClientVerifyMode::ClientAuth`, and can keep the
verified chain in the connection's negotiated parameters. A client presents its certificate
through `ClientAuth` on its `TlsClientConfig`.

## ACME

With the `acme` feature, [`rama::tls::acme`](https://ramaproxy.org/docs/rama/tls/acme/index.html)
provides an ACME client (`AcmeClient`) and the protocol types to obtain certificates
from a CA such as Let's Encrypt. You complete the HTTP-01 or TLS-ALPN-01 challenge with
regular Rama services.

## Termination proxies

For proxies that terminate TLS and forward the plain stream, see
[TLS Termination proxies](./proxies/tls.md).

## Examples

- [/examples/src/tls_rustls_termination.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_rustls_termination.rs)
  and [/examples/src/tls_boring_termination.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_boring_termination.rs):
  the same TLS termination proxy with each backend.
- [/examples/src/tls_boring_dynamic_certs.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_boring_dynamic_certs.rs)
  and [/examples/src/tls_rustls_dynamic_certs.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_rustls_dynamic_certs.rs):
  choose a server certificate per connection.
- [/examples/src/tls_rustls_dynamic_config.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_rustls_dynamic_config.rs):
  choose a Rustls server config based on the ClientHello.
- [/examples/src/tls_rustls_cert_pinning.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_rustls_cert_pinning.rs)
  and [/examples/src/tls_boring_cert_pinning.rs](https://github.com/plabayo/rama/blob/main/examples/src/tls_boring_cert_pinning.rs):
  only accept a server whose leaf matches a pin.
- [/examples/src/mtls_tunnel_and_service.rs](https://github.com/plabayo/rama/blob/main/examples/src/mtls_tunnel_and_service.rs):
  an mTLS tunnel proxy and an mTLS web service.
- [/examples/src/acme_http_challenge.rs](https://github.com/plabayo/rama/blob/main/examples/src/acme_http_challenge.rs),
  [/examples/src/acme_tls_challenge_using_rustls.rs](https://github.com/plabayo/rama/blob/main/examples/src/acme_tls_challenge_using_rustls.rs)
  and [/examples/src/acme_tls_challenge_using_boring.rs](https://github.com/plabayo/rama/blob/main/examples/src/acme_tls_challenge_using_boring.rs):
  complete ACME challenges against a local Pebble CA.
