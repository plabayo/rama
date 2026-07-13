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
pin the only certificate check.

Pins apply to every connection using that `TlsClientConfig`; Rama does not infer
host scopes from certificate DNS names.

The examples use Rama's checked-in `example.com` certificate and local dynamic
TLS servers. Normal certificate and server-name verification remains enabled by
default. Their local self-signed workflow explicitly uses `--insecure`, which
disables those additional checks but still requires the leaf pin.

- [/examples/tls_rustls_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_cert_pinning.rs):
  HTTPS certificate pinning using rustls;
- [/examples/tls_boring_cert_pinning.rs](https://github.com/plabayo/rama/tree/main/examples/tls_boring_cert_pinning.rs):
  HTTPS certificate pinning using BoringSSL.
