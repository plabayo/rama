🦙 **rama** (ラマ) is a modular service framework for building network
services in Rust.

Rama is intentionally explicit: clients, servers, transports, protocols,
middleware, and state are composed as services and layers. This keeps the
shape of your network stack visible in code.

## Start here

| If you want to... | Go here |
|---|---|
| Learn the model | <https://ramaproxy.org/book/intro.html> |
| Understand why Rama exists | <https://ramaproxy.org/book/why_rama.html> |
| Run examples | <https://github.com/plabayo/rama/tree/main/examples> |
| Build proxies | <https://ramaproxy.org/book/proxies/intro.html> |
| Build HTTP services | <https://ramaproxy.org/book/web_servers.html> |
| Use the CLI | <https://ramaproxy.org/book/deploy/rama-cli.html> |

## Main API areas

| API | Purpose |
|---|---|
| [`Service`], [`Layer`] | Core service and middleware traits |
| [`http`] | HTTP clients, servers, services, layers, WebSockets, gRPC |
| [`proxy`] | Proxy primitives, SOCKS5, HAProxy PROXY protocol |
| [`tcp`], [`udp`], [`unix`] | Transport listeners, connectors, and streams |
| [`tls`] | TLS abstractions, Rustls, BoringSSL, ACME |
| [`dns`] | DNS resolvers and related types |
| [`net`] | Network addresses, sockets, forwarding, fingerprints |
| [`ua`] | User-Agent parsing, profiles, and emulation |
| [`telemetry`] | tracing and OpenTelemetry integration |
| [`utils`] | Utilities, including Tower compatibility |

## Common entry points

| Goal | API |
|---|---|
| Write a service | [`Service`] |
| Add middleware | [`Layer`] |
| Build an HTTP server | [`http::server`] |
| Route HTTP requests | [`http::service::web`] |
| Build an HTTP client | [`http::client::EasyHttpWebClient`] |
| Use high-level client helpers | [`http::service::client::HttpClientExt`] |
| Build HTTP proxy flows | [`http::proxy`] |
| Build SOCKS5 proxy flows | [`proxy::socks5`] |
| Build Linux transparent proxy flows | [`linux_tproxy_tcp.rs`](https://github.com/plabayo/rama/blob/main/examples/linux_tproxy_tcp.rs) |
| Build Apple transparent proxy flows | [`ffi/apple/examples/transparent_proxy`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy) |

## Feature flags

The top-level `rama` crate is modular. Many modules are enabled through feature
flags. The docs on docs.rs are built with all features enabled.

## More

- Website and full feature overview: <https://ramaproxy.org/#features-table>
- Book: <https://ramaproxy.org/book>
- Examples: <https://github.com/plabayo/rama/tree/main/examples>
- README and crate overview: <https://github.com/plabayo/rama>
- Edge docs: <https://ramaproxy.org/docs/rama>
