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

See for a full and tested "high level" example of _a_ http client at <https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs>.

More client examples:

- [/examples/http_pooled_client.rs](https://github.com/plabayo/rama/tree/main/examples/http_pooled_client.rs):
  an example demonstrating how to create a pooled HTTP client that can be used to make concurrent requests to the same host;

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

For a private CA or a self-signed server certificate that is suitable as a
trust anchor, replace the default trust anchors directly from a certificate
list:

```rust
let tls_config = TlsClientConfig::default_http()
    .try_with_server_trust_anchors(certificates)?;
```

This common API builds the native rustls or BoringSSL verification store. Normal
chain, validity, usage, and server-name checks remain enabled. It can be combined
with `TlsServerCertPins` when both trust verification and a leaf pin must
succeed. These anchors replace the system trust store; they are not added to it.
Use a pin instead of treating an arbitrary CA-issued server leaf as a trust
anchor.

- [/examples/tls_rustls_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_cert_pinning.rs):
  HTTPS certificate pinning using rustls;
- [/examples/tls_boring_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_boring_cert_pinning.rs):
  HTTPS certificate pinning using BoringSSL.
