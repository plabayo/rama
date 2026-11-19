🦙 **rama** (ラマ) is a modular Rust framework for building network clients,
servers, proxies, and gateways.

A [`Service`] handles an input, such as a connection or an HTTP request. A
[`Layer`] wraps a service to add behavior. The same model works across network
layers and protocols, so you can start with a built-in stack and plug in your
own Rust code where you need it. For synchronous callers, [`BlockingService`]
and [`rt::blocking`] provide a blocking boundary around an async stack.

> **Tip for newcomers**
>
> Start with the [project README] to see how the pieces fit together, or visit
> [ramaproxy.org](https://ramaproxy.org/) to explore what you can build.

## Common entry points

| Goal | API |
|---|---|
| Implement a service or wrap one in middleware | [`Service`], [`Layer`] |
| Serve HTTP requests and route them to handlers | [`http::server`], [`http::service::web`] |
| Send HTTP requests with a configurable client | [`http::client::EasyHttpWebClient`], [`http::service::client::HttpClientExt`] |
| Use an HTTP client from synchronous code | [`http::client::BlockingHttpWebClient`] |
| Send selected or unmatched requests to a FastCGI backend | [`gateway::fastcgi`] |
| Capture or inspect traffic | [`inspect`] |
| Build HTTP proxy flows | [`http::proxy`] |
| Adapt HTTP through ICAP | [`icap::http::layer`] |
| Build standalone ICAP services | [`icap::client`], [`icap::server`] |
| Build SOCKS5 proxy flows | [`proxy::socks5`] |
| Build MASQUE CONNECT-UDP and CONNECT-IP clients and proxies | [`proxy::masque`] |
| Build Linux transparent proxy flows | [`linux_tproxy_tcp.rs`](https://github.com/plabayo/rama/blob/main/examples/src/linux_tproxy_tcp.rs) |
| Build Apple transparent proxy flows | [`ffi/apple/examples/transparent_proxy`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy) |

## Main API areas

| API | Purpose |
|---|---|
| [`Service`], [`Layer`] | Core service and middleware traits |
| [`BlockingService`], [`rt::blocking`] | Synchronous boundaries for async services, streams, and I/O |
| [`http`] | HTTP/1.1, HTTP/2 and HTTP/3 clients, servers, services, layers, WebSockets, gRPC |
| [`icap`] | Internet Content Adaptation Protocol (ICAP) |
| [`gateway`] | Application server gateways such as FastCGI |
| [`ttrpc`] | ttRPC clients and servers |
| [`proxy`] | Proxy primitives, SOCKS5, MASQUE (CONNECT-UDP, CONNECT-IP), HAProxy PROXY protocol |
| [`tcp`], [`udp`], `unix` | Transport listeners, connectors, and streams |
| [`quic`] | QUIC endpoints, connections, ordered streams, and unreliable datagrams |
| [`tls`] | TLS abstractions, Rustls, BoringSSL, ACME |
| [`crypto`] | Certificates, PEM, ASN.1, OCSP, CRL, JOSE, digests and native root certificates |
| [`dns`] | DNS resolvers and related types |
| [`net`] | Network addresses, sockets, forwarding, fingerprints, and Apple platform integrations in `net::apple` |
| [`ua`] | User-Agent parsing, profiles, and emulation |
| [`inspect`] | Protocol-independent inspection, interception and capture storage |
| [`json`] | Streaming JSON tokenizer, JSONPath selection and rewriting |
| [`js`] | Embedded JavaScript runtime and Proxy Auto-Configuration (PAC) support via [`js::pac`] |
| [`telemetry`] | Tracing spans, OpenTelemetry metrics, and dial9 recordings of runtime and protocol activity |
| [`utils`] | Utilities, including Tower compatibility |

## Feature flags

The default feature is `std`. Enable the features for the APIs you use. For
example, `http-full` enables the HTTP client and server stacks. The docs.rs
build enables all features, so it also shows APIs you can opt into separately.

## Explore a working stack

The [client and server example] applies the same HTTP tracing layer to outbound
requests and incoming routes. Run it, then try changing the layers on either
side. The [examples directory] has more starting points, including transparent
proxies and application gateways. Check the example’s run instructions for its feature flags.

The [Rama Book] explains the service model and has guides to [proxies],
[HTTP services], and the [Rama CLI]. The [project README] maps the available
building blocks to network roles and protocols. Use [docs.rs] for published
versions and the [edge docs] for the API on `main`.

[client and server example]: https://github.com/plabayo/rama/blob/main/examples/src/http_high_level_client.rs
[examples directory]: https://github.com/plabayo/rama/tree/main/examples
[Rama Book]: https://ramaproxy.org/book/intro.html
[proxies]: https://ramaproxy.org/book/proxies/intro.html
[HTTP services]: https://ramaproxy.org/book/web_servers.html
[Rama CLI]: https://ramaproxy.org/book/deploy/rama-cli.html
[project README]: https://github.com/plabayo/rama#how-the-pieces-fit-together
[docs.rs]: https://docs.rs/rama
[edge docs]: https://ramaproxy.org/docs/rama
