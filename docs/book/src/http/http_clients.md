# Http Clients

In [The "🗼 Services all the way down 🐢" chapter](../intro/services_all_the_way_down.md) you can read and learn that a big pillar of Rama's architecture is build on top of the [`Service`][rama-service] concept. A [`Service`][rama-service] takes a `Request`, and uses it to serve either a `Response` or `Error`. Such a [`Service`][rama-service] can produce the response "directly" (also called ☘️ Leaf services) or instead pass the request to an inner [`Service`][rama-service] which it wraps around (so called 🍔 Middlewares).

[rama-service]: https://ramaproxy.org/docs/rama/service/trait.Service.html

It's a powerful concept, originally introduced to Rust by [the Tower ecosystem](https://github.com/tower-rs/tower) and allows you build complex stacks specialised to your needs in a modular and easy manner. Even cooler is that this works for both clients and servers alike.

Rama provides an [`EasyHttpWebClient`](https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html) which sends your _Http_ `Request` over the network and returns the `Response` if it receives and read one or an `Error` otherwise. Combined with [the many Layers (middleware)](https://ramaproxy.org/docs/rama/http/layer/index.html) that `Rama` provides and perhaps also some developed by you it is possible to create a powerful _Http_ client suited to your needs.

As a 🍒 cherry on the cake you can import the [`HttpClientExt`](https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html) trait in your Rust module to be able to use your _Http_ Client [`Service`][rama-service] stack using a high level API to build and send requests with ease.

> [!NOTE]
> The same client-side composition model is also used by
> Rama's gRPC support. See the dedicated [gRPC chapter](./grpc.md)
> for how a regular Rama HTTP client can act as the transport
> substrate for typed gRPC clients.

## Http Client Example

See for a full and tested "high level" example of _a_ http client at <https://github.com/plabayo/rama/tree/main/examples/src/http_high_level_client.rs>.

More client examples:

- [/examples/src/http3_client_server.rs](https://github.com/plabayo/rama/tree/main/examples/src/http3_client_server.rs):
  an authenticated HTTP/3 client and server using common request, response and body types,
  with pooled requests, streaming uploads, trailers and graceful shutdown;
- [/examples/src/http_blocking_https_client.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_blocking_https_client.rs):
  a blocking HTTPS client that creates and owns its runtime thread;
- [/examples/src/http_pooled_client.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_pooled_client.rs):
  an example demonstrating how to create a pooled HTTP client that can be used to make concurrent requests to the same host;

## Alternative services and custom connectors

The easy client enables Alt-Svc discovery by default. With a QUIC TLS provider,
this can open UDP connections for HTTP/3. Use `without_alt_svc()` to disable
advertised-endpoint selection; explicit HTTP/3 requests remain supported.
Clear shared discovery with `AltSvcCache::clear_all()`, and report network changes
with `network_changed()`. Apply destination restrictions in your connector so
they cover origins, advertisements and DNS results alike.

Alternative services change where and how Rama connects, while preserving the
request's origin and certificate identity. The easy client selects a service
before choosing a proxy route and consulting the connection pool.

`HttpServiceConnector` returns the underlying connection unchanged. Compose
`AltSvcLayer::new(cache)` separately with `MapEstablishedConnection`; the easy
client does this automatically. The layer resolves each request’s origin, learns response
headers and sets `Alt-Used` from the established endpoint. An optional H2 observer
feeds ALTSVC frames into the same cache. Advertisements are not automatically
forwarded. To send H2 advertisements, enable `set_alt_svc(true)` before the server
handshake and use `AltSvcSender`; ordinary connections allocate no sender queue.

Selection tries alternatives sequentially, with a configurable 300 ms
`attempt_timeout` including DNS and TLS. Increase it for slower networks. There
is no overall deadline unless `timeout` is set. Failed alternatives back off;
selection can fall back to the origin with the same TLS policy. Explicit version
requirements remain binding. A completed response resets backoff; reconnecting
or re-advertising does not. Request-specific TLS trust cannot change shared discovery.

Custom connectors use these contracts:

| Type | Responsibility |
| --- | --- |
| `HttpServiceSelection` | Request-local advertisement snapshot, index and lookup route plan; never store it on a pooled connection. |
| `EstablishedHttpService` | Verified connection endpoint and logical origin; selection alone proves neither. |
| `TlsTunnel::from_extensions` | Resolve routing-supplied tunnel settings before caller settings; preserve their distinct reuse scopes. |
| `TargetHttpVersion` | Honor the requested version; report the established version. |
| `ConnectorTarget` / `ConnectorTargetStream` | Dial the selected endpoint using matching DNS results, preserving the origin. |
| `TlsServerAuthentication` / `NegotiatedTlsParameters` | Report verified origin identity and actual ALPN; missing proof prevents alternative use. |
| `ConnectionReuse` | Publish endpoint reuse rules after connecting; pools check them against each request. |
| `AltSvcObserverExtension` | Install before H2 handshake; authorize origins and process frames promptly. |
| `ConnectionAttempt` / `ConnectionPolicyScope` | Check peer requirements and restrict request-specific DNS/TLS policy; preserve failure scope across timeouts and pool hits. |

TLS configuration stays in its connector. Built-in connectors publish reuse rules
automatically. Custom components publish owned `TlsPoolComponent::Identity`
values: equal identities permit reuse. `with_shared_instance` instead retains an
existing `Arc` and compares allocation identity without boxing a snapshot.
Policy changes need a new identity. Custom secure connectors without reuse rules
receive fresh connections. Apply request-policy
middleware outside the pool so lookup and establishment see the same input.
Unclassified policy failures never suppress shared alternatives.
Connectors report unsupported protocols or routes as local capability failures;
clients need no separate protocol-support list. These refusals preserve cache health.
In the CLI, `--alt-svc` enables command-local discovery; `--http3` requires H3
directly. Disk persistence and DNS HTTPS/SVCB discovery are not implemented yet.

## Server certificate pinning

Rama clients can pin the server leaf through `TlsServerCertPins`, backend
agnostic for rustls and BoringSSL. The standard pin is the SHA-256 of the
leaf's public key (`TlsServerCertPin::SpkiSha256`), exchanged in the usual
`sha256/<base64>` format and printed by `rama probe tls`. Parsing also accepts
a PEM certificate, deriving its key pin. It survives
certificate renewal as long as the key pair is unchanged. Pin the exact
DER-encoded certificate (`TlsServerCertPin::ExactDer`) only when you control
the certificate file itself.

With the default `ServerVerifyMode::Auto`, both the pin and normal certificate
verification must succeed. `ServerVerifyMode::Disable` makes the applicable
pins the only certificate check.

Pins are grouped in sets: pins within a set and applicable sets are
alternatives (e.g. the current and next key during rotation). A set without
server names applies globally; otherwise only when the effective TLS server
name matches — never inferred from certificate contents. If no set applies,
pinning imposes no check and normal verification continues.

```rust
let pins = TlsServerCertPins::new(
    TlsServerCertPinSet::try_new([api_current_key_pin, api_next_key_pin])?
        .with_server_name(Host::from_static("api.example.com")),
)
.with_pin_set(
    TlsServerCertPinSet::new("sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M=".parse::<TlsServerCertPin>()?)
        .with_server_name(Host::from_static("login.example.com")),
);
```

The default trust roots come from the native store, with Rama's bundled Mozilla
(CCADB) roots as an empty-store fallback. Extend those roots with a private CA,
or select the bundled roots explicitly for OS-independent behavior:

```rust
let tls_config = TlsClientConfig::default_http()
    .try_with_extra_server_trust_anchors(private_ca_certificates.clone())?;

let portable_tls_config = TlsClientConfig::default_http()
    .with_webpki_roots()
    .try_with_extra_server_trust_anchors(private_ca_certificates)?;
```

Use `try_with_server_trust_anchors` instead for a custom-only store. These common
settings have the same semantics with rustls and BoringSSL. Normal chain,
validity, usage, and server-name checks remain enabled, and certificate pins can
be required in addition.

- [/examples/src/tls_rustls_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/src/tls_rustls_cert_pinning.rs):
  HTTPS certificate pinning using rustls;
- [/examples/src/tls_boring_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/src/tls_boring_cert_pinning.rs):
  HTTPS certificate pinning using BoringSSL.
