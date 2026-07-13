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

Rama clients can require the exact DER-encoded server leaf certificate through
`TlsServerCertPins`. Pins are backend-agnostic and can be used with rustls or
BoringSSL. With the default `ServerVerifyMode::Auto`, both the pin and normal
certificate verification must succeed. `ServerVerifyMode::Disable` makes the
applicable pins the only certificate check.

`TlsServerCertPins::new(pin)` creates one global, single-certificate pin set.
Use `try_new_set` for several alternative certificates, such as the current and
next certificates during rotation. Use `with_pin` or `try_with_pin_set` to start
additional sets. Pin sets can be scoped explicitly and added fluently:

```rust
let pins = TlsServerCertPins::try_new_set([api_current, api_next])?
    .for_server_name(Host::from_static("api.example.com"))
    .try_with_pin_set([login_current, login_next])?
    .for_server_name(Host::from_static("login.example.com"));
```

Pins within a set and applicable sets are alternatives. A set without server
names applies globally. If no set applies to the effective TLS server name,
pinning imposes no check and normal verification continues. Rama does not infer
host scopes from certificate DNS names.

For a private CA or a self-signed server certificate that is suitable as a
trust anchor, replace the default trust anchors directly from a certificate
list:

```rust
let tls_config = TlsClientConfig::default_http()
    .try_with_server_trust_anchors(certificates)?;
```

This common API builds the native rustls or BoringSSL verification store. Normal
chain, validity, usage, and server-name checks remain enabled. It can be combined
with `TlsServerCertPins` when both trust verification and an exact leaf pin must
succeed. These anchors replace the system trust store; they are not added to it.
Use a pin instead of treating an arbitrary CA-issued server leaf as a trust
anchor.

- [/examples/tls_rustls_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_cert_pinning.rs):
  HTTPS certificate pinning using rustls;
- [/examples/tls_boring_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_boring_cert_pinning.rs):
  HTTPS certificate pinning using BoringSSL.
