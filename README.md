[![rama banner](./docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![rust version][rust-version-badge]][rust-version-url]
[![Build Status][actions-badge]][actions-url]
[![Lines of Code][loc-badge]][loc-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.96+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/actions/workflows/CI.yml/badge.svg?branch=main
[actions-url]: https://github.com/plabayo/rama/actions/workflows/CI.yml
[loc-badge]: https://img.shields.io/endpoint?url=https://ghloc.vercel.app/api/plabayo/rama/badge?filter=.rs,.swift,.c,.h$&style=flat&logoColor=white&label=LoC
[loc-url]: https://github.com/plabayo/rama

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo
[paypal-badge]: https://img.shields.io/badge/paypal-contribution?style=for-the-badge&color=blue
[paypal-url]: https://www.paypal.com/donate/?hosted_button_id=P3KCGT2ACBVFE

🦙 rama® (ラマ) is a modular service framework for the 🦀 Rust language.

Rama is intentionally explicit. Your network stack is built from services,
layers, transports, protocols, and state that you compose yourself. That makes
the shape of the system visible in the code, instead of hidden behind framework
magic or configuration.

This makes Rama a good fit not only for proxies, but for network services where
the stack itself matters: how traffic enters, how it is decoded, where state
lives, what gets inspected, what gets transformed, and where it goes next.

Whether you're inspecting traffic for security analysis, writing a web service,
emulating clients with custom user agents, controlling connection behavior for
advanced testing, or building high-performance proxies, Rama provides a clean
and composable [Tokio](https://tokio.rs/)-native foundation for network services
in Rust.

Rama is used in production for network security, data extraction, API gateways,
routing, and other networked systems. Commercial support and partner offerings
are available at [ramaproxy.com](https://ramaproxy.com).

> Rama is developed and maintained by [Plabayo](https://plabayo.tech),
> a European software studio based in Gent, Belgium, focused on building resilient,
> interoperable, and secure digital infrastructure.

## Start here

The book explains the ideas, the examples show working stacks, and the Rust docs
are the API reference.

| If you want to... | Go here |
|---|---|
| Understand why Rama exists | [Why Rama](https://ramaproxy.org/book/why_rama.html) |
| Learn the core model | [Intro to Rama](https://ramaproxy.org/book/intro.html) |
| Run working code | [Examples](https://github.com/plabayo/rama/tree/main/examples) |
| Build a proxy | [Intro to proxies](https://ramaproxy.org/book/proxies/intro.html) and [proxy examples](https://github.com/plabayo/rama/tree/main/examples#proxies) |
| Operate advanced proxy stacks | [Operate Proxies](https://ramaproxy.org/book/proxies/operate/intro.html) |
| Build an HTTP service | [Web servers](https://ramaproxy.org/book/web_servers.html) and [HTTP service examples](https://github.com/plabayo/rama/tree/main/examples#http-servers-and-services) |
| Build an HTTP client | [HTTP clients](https://ramaproxy.org/book/http/http_clients.html) and [`http_high_level_client.rs`](https://github.com/plabayo/rama/blob/main/examples/http_high_level_client.rs) |
| Use Rama from the terminal | [`rama` CLI](https://ramaproxy.org/book/deploy/rama-cli.html) |
| Look up APIs | [docs.rs](https://docs.rs/rama) or [edge docs](https://ramaproxy.org/docs/rama) |
| Get commercial support | [ramaproxy.com](https://ramaproxy.com) |

## What can you build?

Rama is built for programmable network services: software that accepts, opens,
inspects, transforms, routes, proxies, or generates network traffic.

| Area | Examples |
|---|---|
| Proxies | reverse proxies, HTTP(S) proxies, SOCKS5 proxies, SNI proxies, MITM proxies, transparent proxies, HAProxy PROXY protocol |
| HTTP services | routers, static files, APIs, health checks, WebSockets, SSE, gRPC, FastCGI |
| HTTP clients | high-level clients, pooled clients, proxy-aware clients, user-agent emulation, redirect and middleware stacks |
| TLS and identity | Rustls, BoringSSL, TLS termination, dynamic certificates, mTLS, ACME |
| Traffic inspection | protocol inspection, TLS and HTTP fingerprinting, HAR recording, curl export, diagnostics |
| Lower-level networking | TCP, UDP, Unix sockets, DNS, transport middleware, connection pooling |
| Platform integrations | Apple Network Extension, Apple XPC, CLI tooling |

For the full capability overview, see the [website feature table](https://ramaproxy.org/#features-table)
and the [API docs](https://docs.rs/rama).

For advanced proxy operation, see the [Operate Proxies](https://ramaproxy.org/book/proxies/operate/intro.html)
chapters. For Apple transparent proxying, see the
[Apple transparent proxy example](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy).

## Core ideas

- **Services all the way down:** Rama uses the same service model across clients,
  servers, middleware, and lower network layers.
- **Explicit stacks:** transports, TLS, protocols, state, and middleware are
  composed in code, so the path traffic takes stays visible.
- **Transport-to-HTTP control:** work at the HTTP layer when that is enough, or
  reach into TCP, UDP, TLS, DNS, and connection state when needed.
- **Modular crates:** use the top-level `rama` crate, or depend on smaller crates
  when you want a focused dependency graph.
- **Tower interop:** Rama has its own service traits, with compatibility for
  Tower where that helps.

## Examples

The [`examples`](https://github.com/plabayo/rama/tree/main/examples) directory
contains tested examples for common stacks.

| Goal | Example |
|---|---|
| Minimal HTTP service | [`http_service_hello.rs`](https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs) |
| HTTP router | [`http_web_router.rs`](https://github.com/plabayo/rama/blob/main/examples/http_web_router.rs) |
| High-level HTTP client | [`http_high_level_client.rs`](https://github.com/plabayo/rama/blob/main/examples/http_high_level_client.rs) |
| HTTP CONNECT proxy | [`http_connect_proxy.rs`](https://github.com/plabayo/rama/blob/main/examples/http_connect_proxy.rs) |
| SOCKS5 proxy | [`socks5_connect_proxy.rs`](https://github.com/plabayo/rama/blob/main/examples/socks5_connect_proxy.rs) |
| MITM proxy | [`http_mitm_proxy_boring.rs`](https://github.com/plabayo/rama/blob/main/examples/http_mitm_proxy_boring.rs) |
| Linux transparent proxy | [`linux_tproxy_tcp.rs`](https://github.com/plabayo/rama/blob/main/examples/linux_tproxy_tcp.rs) |
| Apple transparent proxy | [`ffi/apple/examples/transparent_proxy`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy) |
| Tower integration | [`http_rama_tower.rs`](https://github.com/plabayo/rama/blob/main/examples/http_rama_tower.rs) |

Most examples can be run with `cargo` and the required feature flags:

```bash
cargo run --example http_service_hello --features=http-full
cargo run --example http_connect_proxy --features=http-full
cargo run --example socks5_connect_proxy --features=dns,socks5
```

Check each example's module documentation for exact usage and feature
requirements.

## `rama` binary

The `rama` binary lets you use parts of Rama without writing Rust code. It can
act as an HTTP client, run local IP/echo/fingerprinting services, and run
configured proxy stacks.

Learn how to install and use it in the [`rama` CLI chapter](https://ramaproxy.org/book/deploy/rama-cli.html).

> [!IMPORTANT]
> Learn more about the Rama CLI code signing and privacy policy at
> <https://ramaproxy.org/book/deploy/rama-cli.html#code-signing>.
> Applicable to macOS and Windows platforms only.

## Status

- **MSRV:** Rama requires Rust `1.96`.
- **Platforms:** Linux, macOS, and Windows are tier 1 platforms. Android and iOS
  targets are checked in CI.
- **Safety:** Rama avoids unsafe code where possible. Low-level protocol code and
  FFI-backed crates use unsafe where needed.
- **Supply chain:** dependencies are audited with [`cargo vet`](https://github.com/mozilla/cargo-vet).
- **Performance:** Rama's default HTTP implementation is based on Hyper internals
  and is designed for production network services.
- **Roadmap:** planned work is tracked in [GitHub milestones](https://github.com/plabayo/rama/milestones).

## All rama and other crates developed by Plabayo

Most users can start with [`rama`](https://crates.io/crates/rama). The smaller
crates exist for users who want finer control over dependencies or extension
points.

See the [ecosystem chapter](https://ramaproxy.org/book/ecosystem.html) for more
context.

Rama crates in this repository:

- [`rama`](https://crates.io/crates/rama): top-level crate
- [`rama-error`](https://crates.io/crates/rama-error): error utilities for rama and its users
- [`rama-macros`](https://crates.io/crates/rama-macros): contains the procedural macros used by `rama`
- [`rama-utils`](https://crates.io/crates/rama-utils): utilities crate for rama
- [`rama-ws`](https://crates.io/crates/rama-ws): WebSocket (WS) support for rama
- [`rama-core`](https://crates.io/crates/rama-core): core crate containing the service and layer traits
  used by all other `rama` code, as well as some other _core_ utilities
- [`rama-crypto`](https://crates.io/crates/rama-crypto): rama crypto primitives and dependencies
- [`rama-net`](https://crates.io/crates/rama-net): rama network types and utilities
- [`rama-net-apple-networkextension`](https://crates.io/crates/rama-net-apple-networkextension): Apple Network Extension support for rama
- [`rama-net-apple-xpc`](https://crates.io/crates/rama-net-apple-xpc): Apple XPC support for rama
- [`rama-dns`](https://crates.io/crates/rama-dns): DNS support for rama
- [`rama-unix`](https://crates.io/crates/rama-unix): Unix (domain) socket support for rama
- [`rama-tcp`](https://crates.io/crates/rama-tcp): TCP support for rama
- [`rama-udp`](https://crates.io/crates/rama-udp): UDP support for rama
- [`rama-tls-acme`](https://crates.io/crates/rama-tls-acme): ACME support for rama
- [`rama-tls-boring`](https://crates.io/crates/rama-tls-boring): [Boring](https://github.com/plabayo/rama-boring) TLS support for rama
- [`rama-tls-rustls`](https://crates.io/crates/rama-tls-rustls): [Rustls](https://github.com/rustls/rustls) support for rama
- [`rama-proxy`](https://crates.io/crates/rama-proxy): proxy types and utilities for rama
- [`rama-socks5`](https://crates.io/crates/rama-socks5): SOCKS5 support for rama
- [`rama-fastcgi`](https://crates.io/crates/rama-fastcgi): FastCGI support for rama
- [`rama-haproxy`](https://crates.io/crates/rama-haproxy): rama HAProxy support
- [`rama-ua`](https://crates.io/crates/rama-ua): User-Agent (UA) support for `rama`
- [`rama-http-types`](https://crates.io/crates/rama-http-types): http types and utilities
- [`rama-http-headers`](https://crates.io/crates/rama-http-headers): typed http headers
- [`rama-json`](https://crates.io/crates/rama-json): streaming JSON tokenizer, JSONPath selection, and rewriting utilities
- [`rama-grpc`](https://crates.io/crates/rama-grpc): gRPC support for rama
- [`rama-grpc-build`](https://crates.io/crates/rama-grpc-build): gRPC codegen support for rama
- [`rama-http`](https://crates.io/crates/rama-http): rama http services, layers and utilities
- [`rama-http-macros`](https://crates.io/crates/rama-http-macros): proc-macros powering the type-safe HTML templating in `rama-http::protocols::html`
- [`rama-http-backend`](https://crates.io/crates/rama-http-backend): default http backend for `rama`
- [`rama-http-core`](https://crates.io/crates/rama-http-core): http protocol implementation driving `rama-http-backend`
- [`rama-http-hyperium`](https://crates.io/crates/rama-http-hyperium): conversions between rama and the hyperium `http` crate
- [`rama-tower`](https://crates.io/crates/rama-tower): [tower](https://github.com/tower-rs/tower) compatibility for `rama`

Related Plabayo crates and projects:

- [`rama-boring`](https://crates.io/crates/rama-boring): BoringSSL bindings for rama
- [`rama-boring-sys`](https://crates.io/crates/rama-boring-sys): FFI bindings to BoringSSL for rama
- [`rama-boring-tokio`](https://crates.io/crates/rama-boring-tokio): Tokio SSL streams backed by BoringSSL
- [`rama-boringssl`](https://github.com/plabayo/rama-boringssl): BoringSSL fork used by `rama-boring`
- [`tokio-graceful`](https://crates.io/crates/tokio-graceful): graceful shutdown utilities for Tokio
- [`venndb`](https://crates.io/crates/venndb): set and relation matching utilities used by Rama proxy components
- [`homebrew-rama`](https://github.com/plabayo/homebrew-rama): Homebrew formula for the `rama` CLI

## Community

[![Discord][discord-badge]][discord-url]

Questions, ideas, and project discussion are welcome on [Discord][discord-url].
Bug reports and feature requests can be opened as
[GitHub issues](https://github.com/plabayo/rama/issues).

Rama also has a public channel on the official Discord of the Tokio project:
<https://discord.com/channels/500028886025895936/1349098858831024209>.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](https://github.com/plabayo/rama/blob/main/CONTRIBUTING.md)
before opening a pull request.

Good places to start:

- [`good first issue`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
- [`easy`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3Aeasy)
- [`mentor available`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22mentor+available%22)
- [`low prio`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22low+prio%22)

Some issues have a [`needs input`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22needs+input%22+)
label. These usually need discussion, research, or design work before
implementation starts.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `rama` by you shall be licensed as both [MIT](https://github.com/plabayo/rama/blob/main/LICENSE-MIT)
and [Apache-2.0](https://github.com/plabayo/rama/blob/main/LICENSE-APACHE),
without any additional terms or conditions.

## License

Rama is licensed under either of:

- [MIT](https://github.com/plabayo/rama/blob/main/LICENSE-MIT)
- [Apache-2.0](https://github.com/plabayo/rama/blob/main/LICENSE-APACHE)

## Sponsors and support

[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![Paypal Donation][paypal-badge]][paypal-url]

Rama is free and open-source software. Sponsorships help fund development,
infrastructure, testing, and maintenance.

Commercial support, consulting, training, and custom development are available
through [ramaproxy.com](https://ramaproxy.com). More background is available in
the [Sponsor chapter](https://ramaproxy.org/book/sponsor.html).

## Alternatives

If Rama is not the right fit for your proxy work, you may also want to look at
[`pingora`](https://github.com/cloudflare/pingora) by Cloudflare and
[`g3proxy`](https://github.com/bytedance/g3) by ByteDance.

The [Why Rama](https://ramaproxy.org/book/why_rama.html) chapter explains how
Rama fits between off-the-shelf proxies and building a stack from scratch.

## FAQ

Available at <https://ramaproxy.org/book/faq.html>.

## ⭐ | Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=plabayo/rama&type=Date)](https://star-history.com/#plabayo/rama&Date)

[![original (OG) rama logo](./docs/book/src/img/old_logo.png)](https://ramaproxy.org/)

> [!TIP]
>
> 📚 If you like Rama, you might also like [Netstack.FM](https://netstack.fm),
> a podcast about networking, Rust, and everything in between.
