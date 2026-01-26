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
[rust-version-badge]: https://img.shields.io/badge/rustc-1.91+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/actions/workflows/CI.yml/badge.svg?branch=main
[actions-url]: https://github.com/plabayo/rama/actions/workflows/CI.yml
[loc-badge]: https://img.shields.io/endpoint?url=https://ghloc.vercel.app/api/plabayo/rama/badge?filter=.rs$&style=flat&logoColor=white&label=LoC
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

It gives you programmable control over how packets move through your stack, so you can build:

- a foundation for building networked systems at any position in the input or output path
- reusable primitives for composing clients, servers, and intermediaries
- fine grained control over transports, protocols, and data flow
- designed for high performance, correctness, and long running production workloads

**rama is already used in production by companies at scale for use cases such as network security,
data extraction, API gateways and routing**. We also offer **commercial support**.
Service contracts and partner offerings are available at [ramaproxy.com](https://ramaproxy.com).

> [!TIP]
> 📖 New to rama
>
> 1. Read the ["Why rama" chapter](https://ramaproxy.org/book/why_rama) for background.
> 2. Run one of the [examples](https://github.com/plabayo/rama/tree/main/examples).
> 3. Use the [rama book](https://ramaproxy.org/book) and [edge Rust docs](https://ramaproxy.org/docs/rama)
> as reference while building your own stack.

Whether you're intercepting traffic for security analysis, writing a web service,
emulating clients with custom user agents, hijacking connections for advanced testing, or building high-performance proxies, rama provides a clean and composable [Tokio](https://tokio.rs/)-native foundation to program network services in Rust.

It's not just a toolkit—it's a mindset shift for how
to design and operate dynamic, programmable network services.

Network protocols supported and implemented by rama allow you to build servers,
clients and proxies.

[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![Paypal Donation][paypal-badge]][paypal-url]
[![Discord][discord-badge]][discord-url]

> [!TIP]
> 💬 Come join us at [Discord][discord-url] on the `#rama` public channel.
> To ask questions, discuss ideas and ask how rama may be useful for you.

Read further below or skip to one of the following chapters instead:

- [Who is rama for](#who-is-rama-for)
- [For organisations](#for-organisations)
- [Experimental](#--experimental)
- [Proxies and other use cases](#-proxies-and-other-use-cases)
- [rama binary](#rama-binary)
- [rama ecosystem](#--rama-ecosystem)
  - [rama crates](#--rama-crates)
- [Web Services](#--web-services)
- [Web Clients](#--web-clients)
- [Performance](#--performance)
- [Safety](#--safety)
- [Compatibility](#--compatibility)
  - [Minimum supported Rust version](#minimum-supported-rust-version)
- [Roadmap](#--roadmap)

## Who is rama for

- **Developers and teams** who want fine grained control over transport, TLS and HTTP while staying in safe Rust.
- **Organisations** that need a long term partner to:
  - maintain and evolve a proxy or network platform
  - build custom features on top of rama
  - get support and training for internal teams

rama ships with batteries included for transports, HTTP, TLS, DNS, proxy protocols,
telemetry, fingerprinting and more.

The table below shows the current state of the ecosystem to use or build upon, next to the
middleware, services and stacks you'll build yourself:

| category | support list |
|-|-|
| ✅ [transports](https://ramaproxy.org/docs/rama/net/stream/index.html) | ✅ [tcp](https://ramaproxy.org/docs/rama/tcp/index.html) ⸱ ✅ [udp](https://ramaproxy.org/docs/rama/udp/index.html) ⸱ ✅ [Unix (UDS)](https://ramaproxy.org/docs/rama/unix/index.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/net/stream/layer/index.html) |
| ✅ [http](https://ramaproxy.org/docs/rama/http/index.html) | ✅ [auto](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.auto) ⸱ ✅ [http/1.1](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.http1) ⸱ ✅ [h2](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.h2) ⸱ 🏗️ h3 <sup>(2)</sup> ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/http/layer/index.html) |
| ✅ web server | ✅ [fs](https://ramaproxy.org/docs/rama/http/service/fs/index.html) ⸱ ✅ [router](https://ramaproxy.org/docs/rama/http/service/web/struct.Router.html) ⸱ ✅ [dyn router](https://ramaproxy.org/docs/rama/http/service/web/struct.WebService.html) ⸱ ✅ [static router](https://docs.rs/rama-http/latest/rama_http/service/web/macro.match_service.html) ⸱ ✅ [handler extractors](https://ramaproxy.org/docs/rama/http/service/web/extract/index.html) ⸱ ✅ [k8s healthcheck](https://ramaproxy.org/docs/rama/http/service/web/k8s/index.html) |
| ✅ [client](https://ramaproxy.org/docs/rama/http/client/index.html) | ✅ [easy client](https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html) ⸱ ✅ [high level API](https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html) ⸱ ✅ [BoringSSL Connect](https://ramaproxy.org/docs/rama/tls/boring/client/struct.TlsConnectorLayer.html) ⸱ ✅ [Rustls Connect](https://ramaproxy.org/docs/rama/tls/rustls/client/struct.TlsConnectorLayer.html) ⸱ ✅ [HTTP Proxy Connect](https://ramaproxy.org/docs/rama/http/client/proxy/layer/struct.HttpProxyConnector.html) ⸱ ✅ [Socks5 Proxy Connect](https://ramaproxy.org/docs/rama/proxy/socks5/struct.Socks5ProxyConnectorLayer.html) ⸱ ❌ [Chromium Http](https://github.com/plabayo/rama/issues/189) <sup>(3)</sup> |
| ✅ [tls](https://ramaproxy.org/docs/rama/tls/index.html) | ✅ [Rustls](https://ramaproxy.org/docs/rama/tls/rustls/index.html) ⸱ ✅ [BoringSSL](https://ramaproxy.org/docs/rama/tls/boring/index.html) ⸱ ❌ NSS <sup>(3)</sup> |
| ✅ [dns](https://ramaproxy.org/docs/rama/dns/index.html) | ✅ [DNS Resolver](https://ramaproxy.org/docs/rama/dns/trait.DnsResolver.html) |
| ✅ [proxy protocols](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [PROXY protocol](https://ramaproxy.org/docs/rama/proxy/haproxy/index.html) ⸱ ✅ [http proxy](https://github.com/plabayo/rama/blob/main/examples/http_connect_proxy.rs) ⸱ ✅ [https proxy](https://github.com/plabayo/rama/blob/main/examples/https_connect_proxy.rs) ⸱ ✅ [socks5(h) proxy](https://github.com/plabayo/rama/blob/main/examples/socks5_connect_proxy.rs) |
| ✅ web protocols | ✅ [SSE](https://ramaproxy.org/docs/rama/http/sse/index.html) ⸱ ✅ [WS](https://ramaproxy.org/docs/rama/http/ws/index.html) ⸱ ❌ Web Transport <sup>(1)</sup> ⸱ ✅ [gRPC](https://ramaproxy.org/docs/rama/http/grpc/index.html) |
| ✅ [async-method trait](https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html) services | ✅ [Service](https://ramaproxy.org/docs/rama/service/trait.Service.html) ⸱ ✅ [Layer](https://ramaproxy.org/docs/rama/layer/trait.Layer.html) ⸱ ✅ [extensions](https://ramaproxy.org/docs/rama/extensions/index.html) ⸱ ✅ [dyn dispatch](https://ramaproxy.org/docs/rama/service/struct.BoxService.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/layer/index.html) |
| ✅ [telemetry](https://ramaproxy.org/docs/rama/telemetry/index.html) | ✅ [tracing](https://tracing.rs/tracing/) ⸱ ✅ [opentelemetry](https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html) ⸱ ✅ [http metrics](https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html) ⸱ ✅ [transport metrics](https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html) |
| ✅ Diagnostics | ✅ [curl export](https://ramaproxy.org/docs/rama/http/convert/curl/index.html) ⸱ ✅ [HAR](https://ramaproxy.org/docs/rama/http/layer/har/index.html) |
| ✅ upstream [proxies](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [MemoryProxyDB](https://ramaproxy.org/docs/rama/proxy/struct.MemoryProxyDB.html) ⸱ ✅ [Username Config](https://ramaproxy.org/docs/rama/username/index.html) ⸱ ✅ [Proxy Filters](https://ramaproxy.org/docs/rama/proxy/struct.ProxyFilter.html) |
| ✅ [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) | ✅ [Http Emulation](https://ramaproxy.org/docs/rama/ua/profile/struct.HttpProfile.html) ⸱ ✅ [Tls Emulation](https://ramaproxy.org/docs/rama/ua/profile/struct.TlsProfile.html) ⸱ ✅ [UA Parsing](https://ramaproxy.org/docs/rama/ua/struct.UserAgent.html) |
| ✅ [Fingerprinting](https://ramaproxy.org/docs/rama/net/fingerprint/index.html) | ✅ [Ja3](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja3.html) ⸱ ✅ [Ja4](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja4.html) ⸱ ✅ [Ja4H](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja4H.html) ⸱ ✅ [Akamai passive h2](https://ramaproxy.org/docs/rama/net/fingerprint/struct.AkamaiH2.html) ⸱ ✅ [Peetprint (tls)](https://ramaproxy.org/docs/rama/net/fingerprint/struct.PeetPrint.html) |
| ✅ utilities | ✅ [error handling](https://ramaproxy.org/docs/rama/error/index.html) ⸱ ✅ [graceful shutdown](https://ramaproxy.org/docs/rama/graceful/index.html) ⸱ ✅ [Connection Pooling](https://ramaproxy.org/docs/rama/net/client/pool/index.html) ⸱ ✅ [Tower Adapter](https://ramaproxy.org/docs/rama/utils/tower/index.html) ⸱ 🏗️ IP2Loc <sup>(1)</sup> |
| 🏗️ Graphical Interface | 🏗️ traffic logger <sup>(3)</sup> ⸱ 🏗️ [TUI implementation](https://ratatui.rs/) <sup>(3)</sup> ⸱ ❌ traffic intercept <sup>(3)</sup> ⸱ ❌ traffic replay <sup>(3)</sup> |
| ✅ binary | ✅ [prebuilt binaries](https://ramaproxy.org/book/deploy/rama-cli) ⸱ 🏗️ proxy config <sup>(3)</sup> ⸱ ✅ http client ⸱ ❌ WASM Plugins <sup>(3)</sup> |
| 🏗️ data scraping | 🏗️ Html Processor <sup>(3)</sup> ⸱ ❌ Json Processor <sup>(3)</sup> |
| ❌ browser | ❌ JS Engine <sup>(3)</sup> ⸱ ❌ [Web API](https://developer.mozilla.org/en-US/docs/Web/API) Emulation <sup>(3)</sup> |

> 🗒️ _Footnotes_
>
> * <sup>(1)</sup> Part of [`v0.3.0` milestone (ETA: 2025 Q4)](https://github.com/plabayo/rama/milestone/2)
> * <sup>(2)</sup> Part of [`v0.4.0` milestone (ETA: 2026 Q1)](https://github.com/plabayo/rama/milestone/3)
> * <sup>(3)</sup> No immediate plans, but on our radar. Please [open an issue](https://github.com/plabayo/rama/issues) to request this feature if you have an immediate need for it. Please add sufficient motivation/reasoning and consider [becoming a sponsor](#--sponsors) to help accelerate its priority.
>
> Starting from `v0.3.0` we'll switch things up. Releases will be in frequent ~ 6 week release trains,
> with no more alpha releases in between.

## Commercial support and services

Rama can be backed by professional commercial service contracts
for organizations that need long term support, guaranteed response times,
strategic guidance, or dedicated development capacity.

These offerings cover areas such as support and maintenance, proactive improvements,
architectural guidance, priority development, custom integrations, and training,
tailored to different team sizes and operational needs.

For up to date information about available
service contracts and commercial offerings, please visit:

👉 <https://ramaproxy.com>

## 🧪 | Experimental

🦙 rama (ラマ) is to be considered experimental software for the foreseeable future.
In the meanwhile it is already used in production by ourselves and others alike.
This gives us real world feedback to improve the framework. If you run Rama in production,
your feedback is very valuable. As such,
if you use rama do let us know feedback over
[Discord][discord-url], [email](mailto:hello@plabayo.tech)
or a [GitHub issue](https://github.com/plabayo/rama/issues).

> [!TIP]
> Contact us at [hello@plabayo.tech](mailto:hello@plabayo.tech) to arrange a service contract.
> Among other benefits, this allows you to request migration of rama versions within
> your own codebase and stay up to date without hassle, even when major releases introduce
> breaking changes. While these changes are typically minimal and mechanical,
> this service can be especially helpful for organisations that do not have
> the developer resources to handle them directly.

# Proxies and other use cases

The primary focus of rama is to aid you in your development
of [proxies](https://ramaproxy.org/book/proxies/intro.html):

- 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
- 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
- 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
- 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5);
- 🔓 [SNI proxies](https://ramaproxy.org/book/proxies/sni);
- 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
- 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).
- 🧭 [HAProxy (PROXY protocol)](https://ramaproxy.org/book/proxies/haproxy).

And pretty much any other kind of proxy, such as API Gateways.
Is your usecase not yet supported sufficiently? Do let us know via
[Discord][discord-url], [email](mailto:hello@plabayo.tech)
or a [GitHub issue](https://github.com/plabayo/rama/issues).

> [!TIP]
> Check out [the "Intro to Proxies" chapters in the rama book](https://ramaproxy.org/book/proxies/intro.html)
> to learn more about the different kind of proxies. It might help in case you are new to developing proxies.

The [Distortion proxies](https://ramaproxy.org/book/proxies/distort) support
comes with [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) emulation capabilities. The emulations are made possible by patterns
and data extracted using [`rama-fp`](https://github.com/plabayo/rama/tree/main/rama-fp/). The service is publicly exposed at
<https://fp.ramaproxy.org>, made possible by our sponsor host <https://fly.io/>.

## Public echo service

🔁 <https://echo.ramaproxy.org/> is another service publicly exposed.
In contrast to the Fingerprinting Service it is aimed at developers
and allows you to send any http request you wish in order to get an insight
on the Tls Info and Http Request Info the server receives
from you when making that request.

```bash
curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
  -H 'x-magic: 42' --data 'whatever forever'
```

Feel free to make use of while crafting distorted http requests,
but please do so with moderation. In case you have ideas on how to improve
the service, please let us know [by opening an issue](https://github.com/plabayo/rama/issues).
Using the [`rama` binary](https://ramaproxy.org/book/deploy/rama-cli.html)
you can also run both the `echo` and `fp` service yourself, locally or as an
external facing web service.

The echo service also has websocket support to echo back your messages,
similar to <echo.websocket.org>. As an extra it has support for subprotocols
to uppercase (`echo-upper`) or lowercase (`echo-lower`) your messages. Default,
including if none is requested is `echo`. Example that will open a TUI client:

```sh
rama wss://echo.ramaproxy.org
```

Learn more about the rama CLI at <https://ramaproxy.org/book/deploy/rama-cli.html>.

> Please run your own echo service instead of using `echo.ramaproxy.org`
> in case you are planning to send a lot of traffic to the echo service.

[BrowserStack](https://browserstack.com) sponsors rama by providing automated cross-platform browser testing
on real devices, which [uses the public fingerprinting service](./rama-fp/browserstack/main.py) to aid in automated fingerprint collection
on both the Http and Tls layers. By design we do not consider Tcp and Udp fingerprinting.

Next to proxies, rama can also be used to develop [Web Services](#--web-services) and [Web Clients](#--web-clients).

- Learn more by reading the rama book at <https://ramaproxy.org/book>;
- or checkout the framework Rust docs at <https://docs.rs/rama>;
    - edge docs (for main branch) can be found at <https://ramaproxy.org/docs/rama>.

> [!NOTE]
> rama also has a public channel on the official Discord of the tokio project.
> Feel free to join us there instead or as well: <https://discord.com/channels/500028886025895936/1349098858831024209>

## rama binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It comes with a working http client for CLI, which emulates
User-Agents and has other utilities. And it also comes with IP/Echo services.

It also allows you to run a `rama` proxy, configured to your needs.

Learn more about the `rama` binary and how to install it at <https://ramaproxy.org/book/deploy/rama-cli>.

> [!IMPORTANT]
> Learn more about the rama CLI code signing- and privacy policy at
> <https://ramaproxy.org/book/deploy/rama-cli.html#code-signing>.
> Applicable to MacOS and Windows platforms only.

## 📣 | rama ecosystem

For now there are only the rama crates found in this repository, also referred to as "official" rama crates.

We welcome however community contributions not only in the form of contributions to this repository,
but also have people write their own crates as extensions to the rama ecosystem.
E.g. perhaps you wish to support an alternative http/tls backend.

In case you have ideas for new features or stacks please let us know first.
Perhaps there is room for these within an official rama crate.
In case it is considered out of scope you are free to make your own community rama crate.
Please prefix all rama community crates with "rama-x", this way the crates are easy to find,
and are sufficiently different from "official" rama crates".

Once you have such a crate published do let us know it, such that we can list them here.

### 📦 | rama crates

The `rama` crate can be used as the one and only dependency.
However, as you can also read in the "DIY" chapter of the book
at <https://ramaproxy.org/book/diy.html#empowering>, you are able
to pick and choose not only what specific parts of `rama` you wish to use,
but also in fact what specific (sub) crates.

Here is a list of all `rama` crates:

- [`rama`](https://crates.io/crates/rama): one crate to rule them all
- [`rama-error`](https://crates.io/crates/rama-error): error utilities for rama and its users
- [`rama-macros`](https://crates.io/crates/rama-macros): contains the procedural macros used by `rama`
- [`rama-utils`](https://crates.io/crates/rama-utils): utilities crate for rama
- [`rama-ws`](https://crates.io/crates/rama-ws): WebSocket (WS) support for rama
- [`rama-core`](https://crates.io/crates/rama-core): core crate containing the service and layer traits
  used by all other `rama` code, as well as some other _core_ utilities
- [`rama-crypto`](https://crates.io/crates/rama-crypto): rama crypto primitives and dependencies
- [`rama-net`](https://crates.io/crates/rama-net): rama network types and utilities
- [`rama-dns`](https://crates.io/crates/rama-dns): DNS support for rama
- [`rama-unix`](https://crates.io/crates/rama-unix): Unix (domain) socket support for rama
- [`rama-tcp`](https://crates.io/crates/rama-tcp): TCP support for rama
- [`rama-udp`](https://crates.io/crates/rama-udp): UDP support for rama
- [`rama-tls-acme`](https://crates.io/crates/rama-tls-acme): ACME support for rama
- [`rama-tls-boring`](https://crates.io/crates/rama-tls-boring): [Boring](https://github.com/plabayo/rama-boring) tls support for rama
- [`rama-tls-rustls`](https://crates.io/crates/rama-tls-rustls): [Rustls](https://github.com/rustls/rustls) support for rama
- [`rama-proxy`](https://crates.io/crates/rama-proxy): proxy types and utilities for rama
- [`rama-socks5`](https://crates.io/crates/rama-socks5): SOCKS5 support for rama
- [`rama-haproxy`](https://crates.io/crates/rama-haproxy): rama HAProxy support
- [`rama-ua`](https://crates.io/crates/rama-ua): User-Agent (UA) support for `rama`
- [`rama-http-types`](https://crates.io/crates/rama-http-types): http types and utilities
- [`rama-http-headers`](https://crates.io/crates/rama-http-headers): typed http headers
- [`rama-grpc`](https://crates.io/crates/rama-grpc): Grpc support for rama
- [`rama-grpc-build`](https://crates.io/crates/rama-grpc-build): Grpc codegen support for rama
- [`rama-http`](https://crates.io/crates/rama-http): rama http services, layers and utilities
- [`rama-http-backend`](https://crates.io/crates/rama-http-backend): default http backend for `rama`
- [`rama-http-core`](https://crates.io/crates/rama-http-core): http protocol implementation driving `rama-http-backend`
- [`rama-tower`](https://crates.io/crates/rama-tower): provide [tower](https://github.com/tower-rs/tower) compatibility for `rama`

`rama` crates that live in <https://github.com/plabayo/rama-boring> (forks of `cloudflare/boring`):

- [`rama-boring`](https://crates.io/crates/rama-boring): BoringSSL bindings for rama
- [`rama-boring-sys`](https://crates.io/crates/rama-boring-sys): FFI bindings to BoringSSL for rama
- [`rama-boring-tokio`](https://crates.io/crates/rama-boring-tokio): an implementation of SSL streams for Tokio backed by BoringSSL in function of rama

repositories in function of rama that aren't crates:

- <https://github.com/plabayo/rama-boringssl>:
  Fork of [mirror of BoringSSL](https://github.com/plabayo/rama-boringssl)
  in function of [rama-boring](https://github.com/plabayo/rama-boring)
- <https://github.com/plabayo/homebrew-rama>: Homebrew formula for the rama Cli tool

Repositories that we maintain and are re exported by the root `rama` crate:

- <https://github.com/plabayo/tokio-graceful>: Graceful shutdown util for Rust projects using the Tokio Async runtime.

## 🌐 | Web Services

> [!TIP]
> See all HTTP(S) server examples at:
>
> <https://github.com/plabayo/rama/tree/main/examples#http-servers-and-services>
>
> On that README you also find other kind of server examples listed.

Developing proxies are the primary focus of rama (ラマ). It can however also be used to develop
any kind of web service you wish. Be it dynamic endpoints, serving static data,
websockets, SSE or [Datastar](#datastar). rama does it all. This comes with many of the same benefits
that you get when developing proxies using rama:

* Use Async Method Traits;
* Reuse modular middleware;
* Have the ability to be in full control of your web stack from Transport Layer (Tcp, Udp)
  through Tls and Http/Ws;
* If all you care about is the Http layer then that is fine too.
* Be able to trust that your incoming Application Http data has not been modified
  (e.g. Http header casing and order is preserved);
* Easily develop your service at a Request layer and High level functions alike,
  choices are yours and can be combined.

Even when building proxies a (local/private) web service can often still be useful, for example:

- a k8s health service ([/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs));
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a Graphical Interface / control panel;

> [!TIP]
> 📖 Learn more about developing web services
> in the rama book: <https://ramaproxy.org/book/web_servers.html>.

Next to https clients you can use any other protocol supported by Rama as a client.

### Datastar

> Datastar helps you build reactive web applications with the simplicity of server-side rendering and the power of a full-stack SPA framework.
>
> — <https://data-star.dev/>

rama has built-in support for [🚀 Datastar](https://data-star.dev).
You can see it in action in [Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/http_sse_datastar_hello.rs](https://github.com/plabayo/rama/tree/main/examples/http_sse_datastar_hello.rs):
  SSE Example, showcasing a very simple datastar example,
  which is supported by rama both on the client as well as the server side.

rama rust docs:

- SSE datastar support: <https://ramaproxy.org/docs/rama/http/sse/datastar/index.html>
- Extractor support (`ReadSignals`): <https://ramaproxy.org/docs/rama/http/service/web/extract/datastar/index.html>
- Embedded JS Script: <https://ramaproxy.org/docs/rama/http/service/web/response/struct.DatastarScript.html>

## 🧑‍💻 | Web Clients

In [The rama book](https://ramaproxy.org/book) you can read and learn that a big pillar of rama's architecture is built on top of [the Service concept](https://ramaproxy.org/book/intro/services_all_the_way_down.html). A [`Service`][rama-service] takes a `Request`, and uses it to serve either a `Response` or `Error`. Such a [`Service`][rama-service] can produce the response "directly" (also called ☘️ Leaf services) or instead pass the request to an inner [`Service`][rama-service] which it wraps around (so called 🍔 Middlewares).

[rama-service]: https://ramaproxy.org/docs/rama/service/trait.Service.html

It's a powerful concept, originally introduced to Rust by [the Tower ecosystem](https://github.com/tower-rs/tower) and allows you build complex stacks specialised to your needs in a modular and easy manner. Even cooler is that this works for both clients and servers alike.

rama provides an [`EasyHttpWebClient`](https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html) which sends your _Http_ `Request` over the network and returns the `Response` if it receives and read one or an `Error` otherwise. Combined with [the many Layers (middleware)](https://ramaproxy.org/docs/rama/http/layer/index.html) that `rama` provides and perhaps also some developed by you it is possible to create a powerful _Http_ client suited to your needs.

As a 🍒 cherry on the cake you can import the [`HttpClientExt`](https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html) trait in your Rust module to be able to use your _Http_ Client [`Service`][rama-service] stack using a high level API to build and send requests with ease.

> [!TIP]
> An end-to-end tested http client example can be found at:
> [/examples/http_high_level_client.rs](https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs).

## 💪 | Performance

Here's a list of external benchmarks:

- http server benchmark @ <https://web-frameworks-benchmark.netlify.app/result>
- http server + client benchmark @ <https://sharkbench.dev/web>

Please [open an issue](https://github.com/plabayo/rama/issues) or Pull Request (PR) in case
you are aware of any other benchmarks of interest in regards to servers,
clients or proxies.

## ⛨ | Safety

The Rama crates avoid unsafe code as much as possible, and use it only where there is no reasonable alternative.
The boring crates contain FFI bindings and the rama-http-core deals with low level primitives.
These are examples of crates with more unsafe than others. Do contact us if you see opportunity
for even less unsafe code than what we already have.

We also make use of [`cargo vet`](https://github.com/mozilla/cargo-vet)
to [audit our supply chain](./supply-chain/).

## 🦀 | Compatibility

### Tier 1 Platforms

rama (ラマ) is developed mostly on MacOS M-Series and Windows 11 x64 machines.
Most organisations running rama in production do so on a variety of Linux systems. These are tier 1 platforms.

| platform | tested | test platform |
|----------|--------|---------------|
| MacOS    | ✅     | developer machine (arm64) + [GitHub Action](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners) (arm64 and intel) |
| Linux    | ✅     | AMD x64 developer machine with Ubuntu 25 + [GitHub Action (Ubuntu 24.04)](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners) (arm64 and amd64) |
| Windows  | ✅     | Windows 11 AMD x64 developer machine + [GitHub Action](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners) (arm64 and amd64) |

### Tier 2 Platforms

Tier 2 platforms run `cargo check` and also `cargo build` tests.
These platforms do however not run tests, let alone integration tests.

Some users of rama do run actual Rama production code on these platforms.

Targets checked in CI:

- `armv7-linux-androideabi`
- `aarch64-linux-android`
- `i686-linux-android`
- `x86_64-linux-android`
- `aarch64-apple-ios`
- `x86_64-apple-ios`

### Other Platforms

Please [open a ticket](https://github.com/plabayo/rama/issues) in case you have compatibility issues for your setup/platform.
Our goal is not to support all possible platforms in the world, but we do want to
support as many as we reasonably can. Such platforms will only happen
and continue to happen with community/ecosystem support.

### Minimum supported Rust version

rama's MSRV is `1.91`.

[Using GitHub Actions we also test](https://github.com/plabayo/rama/blob/main/.github/workflows/CI.yml)
if `rama` on that version still works on the stable and beta versions of _rust_ as well.

## 🧭 | Roadmap

Please refer to <https://github.com/plabayo/rama/milestones> to know what's on the roadmap. Is there something not on the roadmap for the next version that you would really like? Please [create a feature request](https://github.com/plabayo/rama/issues) to request it and [become a sponsor](#--sponsors) if you can.

We also provide special-purpose feature development contracts for commercial organisations
which require a feature beyond the planned scope or to have it developed with priority.
Contact us at [email](mailto:hello@plabayo.tech) if you have a need for this

## 📰 | Media Appearances

rama (`0.2`)  was featured in a 📻 Rustacean episode on the 19th of May 2024, and available to listen at <https://rustacean-station.org/episode/glen-de-cauwsemaecker/>. In this episode [Glen](https://www.glendc.com/) explains the history of rama, why it exists, how it can be used and more.

On the 19th of August 2025 we released [the first episode][netstack-one] of [Netstack.FM](https://netstack.fm), a
new podcast about networking, Rust and everything in between. In [the first episode][netstack-one]
we went over the origins of [Glen](https://www.glendc.com), rama and why the podcast was created.

[netstack-one]: https://netstack.fm/#episode-1

rama is also frequently featured in newsletters
such as <https://this-week-in-rust.org/>.

## 💼 | License

This project is dual-licensed under both the [MIT license][mit-license] and [Apache 2.0 License][apache-license].

## 👋 | Contributing

🎈 Thanks for your help improving the project! We are so happy to have
you! We have a [contributing guide][contributing] to help you get involved in the
`rama` project.

Contributions often come from people who already know what they want, be it a fix for a bug they encountered,
or a feature that they are missing. Please do always make a ticket if one doesn't exist already.

It's possible however that you do not yet know what specifically to contribute, and yet want to help out.
For that we thank you. You can take a look at the open issues, and in particular:

- [`good first issue`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22): issues that are good for those new to the `rama` codebase;
- [`easy`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3Aeasy): issues that are seen as easy;
- [`mentor available`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22mentor+available%22): issues for which we offer mentorship;
- [`low prio`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22low+prio%22): low prio issues that have no immediate pressure to be finished quick, great in case you want to help out but can only do with limited time to spare;

In general, any issue not assigned already is free to be picked up by anyone else. Please do communicate in the ticket
if you are planning to pick it up, as to avoid multiple people trying to solve the same one.

> [!NOTE]
> Some issues have a [`needs input`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22needs+input%22+) label.
> These mean that the issue is not yet ready for development. First of all prior to starting working on an issue you should always look for
> alignment with the rama maintainers. However these
> [`needs input`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22needs+input%22+) issues require also prior R&D work:
>
> - add and discuss missing knowledge or other things not clear;
> - figure out pros and cons of the solutions (as well as what if we choose to not resolve the issue);
> - discuss and brainstorm on possible implementations, desire features, consequences, benefits, ...
>
> Only once this R&D is complete and alignment is confirmed, shall the feature be started to be implemented.

Should you want to contribute to this project but you do not yet know how to program in Rust, you could start learning Rust with as goal to contribute as soon as possible to `rama` by using "[the Rust 101 Learning Guide](https://rust-lang.guide/)" as your study companion. Glen can also be hired as a mentor or teacher to give you paid 1-on-1 lessons and other similar consultancy services. You can find his contact details at <https://www.glendc.com/>.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `rama` by you, shall be licensed as both [MIT][mit-license] and [Apache 2.0][apache-license],
without any additional terms or conditions.

[contributing]: https://github.com/plabayo/rama/blob/main/CONTRIBUTING.md
[mit-license]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[apache-license]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE

### Acknowledgements

Special thanks goes to all involved in developing, maintaining and supporting [the Rust programming language](https://www.rust-lang.org/), the [Tokio ecosystem](https://tokio.rs/) and [all other crates](./Cargo.toml) that we depend upon. This also includes [Hyper and its ecosystem](https://github.com/hyperium) as without those projects rama would not be. The core http module of rama is a specialised fork of `hyper` and use the underlying `h2` and `h3` crates as dependencies.

Extra credits also go to [Axum](https://github.com/tokio-rs/axum), from which ideas and code were copied as it's a project very much in line with the kind of software we want rama to be, but for a different purpose. Our hats also go off to [Tower][Tower], its inventors and all the people and creatures that help make it be every day. The service concept is derived from [Tower][Tower] and many of our layers are a [Tower][Tower] fork, adapted where required or desired.

An extra big shoutout goes also to the online communities surrounding and part of these ecosystems. They are a great place to hangout and always friendly and helpful. Thanks.

[Tower]: https://github.com/tower-rs/tower

## 💖 | Sponsors

rama is **completely free, open-source software** which needs lots of effort and time to develop and maintain.

You can become a regular financial contributor to rama by paying for a monthly subscription at [Github Sponsors][ghs-url]. One time contributions are possible as well.

Sponsors help us continue to maintain and improve `rama`, as well as other
Free and Open Source (FOSS) technology. It also helps us to create
educational content such as <https://github.com/plabayo/learn-rust-101>,
and other open source libraries such as <https://github.com/plabayo/tokio-graceful> and <https://venndb.plabayo.tech>.

Next to the many unpaid developer hours we put in a project such as `rama`,
we also have plenty of costs, such as services ranging from hosting to Docker,
but also tooling for developers and automated processing. All these costs money.

Sponsors receive perks and depending on your regular contribution it also
allows you to rely on us for support and consulting.

Finally, you can also support us by shopping Plabayo <3 `ラマ` merchandise 🛍️ at <https://plabayo.threadless.com/>.

[![Plabayo's Store With rama Merchandise](./docs/img/plabayo_mech_store_rama.png)](https://plabayo.threadless.com/)

### rama Sponsors

We would like to extend our thanks to the following sponsors for funding rama (ラマ) development. If you are interested in becoming a sponsor, you can do so by becoming a [sponsor][ghs-url]. One time payments are accepted [at GitHub][ghs-url] as well as at ["Buy me a Coffee"][bmac-url]. One-time and monthly financial contributions are also possible via Paypal, should you feel more at ease with that at ["Paypal Donations"][paypal-url].

Donations can also be paid in the following cryptocurrency:

* Bitcoin: `bc1qk3383nfzcag9lymwv83m7empa6qu2vspqjkpw4`
* Ethereum: `0xc0C5aCdB0E6c560132c93Df721E1Cd220f6fD4aa`

If you wish to financially support us through other means you can best
start a conversation with us by sending an email to [hello@plabayo.tech](mailto:hello@plabayo.tech).

#### Premium Partners

* [fly.io](https://fly.io)
* [BrowserStack](https://browserstack.com)

rama (ラマ) is bundled with Http/Tls emulation data, gathered for all major platforms and browsers using real devices by [BrowserStack](https://browserstack.com). It does this automatically every day by using [our public Fingerprinting service](https://fp.ramaproxy.org) which is hosted together with a database on [fly.io](https://fly.io).

We are grateful to both sponsors for sponsering us these cloud resources.

#### Other Partners

* [SignPath.io](https://about.signpath.io): provides authoritative code signing for the windows rama CLI;

### Professional Services

🤝 Enterprise support, software customisations, integrations, professional support, consultancy and training are available upon request by sending an email to [hello@plabayo.tech](mailto:hello@plabayo.tech). Or get an enterprise subscription via [GitHub Sponsors](https://github.com/sponsors/plabayo/sponsorships?tier_id=300734).

See [For organisations](#for-organisations) for an overview of our support,
consulting and feature development services.

rama is licensed as both [MIT][mit-license] and [Apache 2.0][apache-license]. You are free to use and modify the
code for any purpose, including commercial use. If Rama becomes an important part of your stack,
we invite you to consider supporting the project as a sponsor or partner.

## 🌱 | Alternatives

While there are a handful of proxies written in Rust, there are only two other Rust frameworks
specifically made for proxy purposes. All other proxy codebases are single purpose code bases,
some even just for learning purposes. Or are actually generic http/web libraries/frameworks
that facilitate proxy features as an extra.

[Cloudflare] has been working on a proxy service framework, named [`pingora`], since a couple of years already,
and on the 28th of February of 2024 they also open sourced it.

rama is not for everyone, but we sure hope it is right for you.
If not, consider giving [`pingora`] a try, it might very well be the next best thing for you.

Secondly, [ByteDance] has an open source proxy framework written in Rust to develop forward
and reverse proxies alike, named [`g3proxy`].

[Cloudflare]: https://www.cloudflare.com/
[`pingora`]: https://github.com/cloudflare/pingora
[ByteDance]: https://www.bytedance.com/en/
[`g3proxy`]: https://github.com/bytedance/g3

## ❓| FAQ

Available at <https://ramaproxy.org/book/faq.html>.

## ⭐ | Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=plabayo/rama&type=Date)](https://star-history.com/#plabayo/rama&Date)

[![original (OG) rama logo](./docs/book/src/img/old_logo.png)](https://ramaproxy.org/)

> [!TIP]
>
> 📚 If you like rama, you might also like [the NetstackFM podcast](https://ramaproxy.org/book/netstackfm.html),
> a podcast about networking, Rust, and everything in between.
