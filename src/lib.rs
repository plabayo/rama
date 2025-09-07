//! 🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
//!
//! > The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).
//! >
//! > It might however not be a framework for everyone. In particular, if you are building a typical simple web server
//! > or just need an http client for making standard requests, you might be better served with other crates.
//! > While we at [Plabayo](https://plabayo.tech) do use Rama for most of our web needs, be it clients, servers or proxies,
//! > it is not the easiest framework to use, and does not yet have the big community backing that other crates have.
//! >
//! > - You might want to use [Axum](https://github.com/tokio-rs/axum) if you are building a typical http web server,
//! >   as it comes with a lot of extra community crates to help you with pretty much anything you can think of. Using
//! >   Axum does mean you give up full control over your web stack, meaning as soon as you need something which
//! >   is not typical or standard-enforced, you might get stuck.
//! > - You might want to use [Reqwest](https://docs.rs/reqwest/latest/reqwest/) if all you need is to make typical
//! >   http requests with no need for fine-grained control over your http requests or responses,
//! >   and where TLS is a mere detail only noticeable because you are surfing to an `https` server, with the `s` for secure.
//! >
//! > If you are building proxies and you feel that Rama is not the right approach for you,
//! > then you might also want to check out the alternatives mentioned in this project's README,
//! > easily available at <https://github.com/plabayo/rama?tab=readme-ov-file#--alternatives>.
//! >
//! > Rama is all about empowerment and modularity. It is there to aid you in building your proxies, servers and clients,
//! > without getting in your way and without stopping you in your mission where rama might fall short. A web stack
//! > built with Rama can always be customized to your needs, even if that particular part or layer is custom to your purpose only.
//! >
//! > It goes without saying that Rama is built upon the shoulders of giants.
//! > Please refer to the acknowledgements at <https://github.com/plabayo/rama?tab=readme-ov-file>
//! > for more information about this.
//! >
//! > Where required we had to fork other crates due to an incompatibility in needs or scope.
//! > While this is unfortunate as it leads to more work for us, we gladly do so in cases
//! > where it fits our mission of empowering rama users, including ourselves.
//! > You can find more information about these forks at <https://github.com/plabayo/rama/blob/main/docs/thirdparty/fork/README.md>.
//! > As much as possible we preserve the code layout of forked code modules to be able
//! > to keep in sync with upstream and push patches upstream where applicable.
//!
//! Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
//! Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes.
//!
//! > 💡 If your organization relies on Rama (ラマ) for its operations,
//! > we invite you to consider becoming a sponsor 💖. By supporting our project,
//! > you'll help ensure its continued development and success.
//! > To learn more about sponsorship opportunities, please refer to [the "Sponsors" chapter in rama's online book](https://ramaproxy.org/book/sponsor.html)
//! > or contact us directly at [sponsor@ramaproxy.org](mailto:sponsor@ramaproxy.org).
//!
//! This framework comes with 🔋 batteries included, giving you the full freedome to build the middleware and services you want, without _having_ to repeat the "common":
//!
//! | category | support list |
//! |-|-|
//! | ✅ [transports](crate::net::stream) | ✅ [tcp] ⸱ ✅ [udp] ⸱ ✅ Unix (UDS)] ⸱ ✅ [middleware](crate::net::stream::layer) |
//! | ✅ [http] | ✅ [auto](crate::http::server::service::HttpServer::auto) ⸱ ✅ [http/1.1](crate::http::server::service::HttpServer::http1) ⸱ ✅ [h2](crate::http::server::service::HttpServer::h2) ⸱ 🏗️ h3 <sup>(2)</sup> ⸱ ✅ [middleware](crate::http::layer) |
//! | ✅ web server | ✅ [fs](crate::http::service::fs) ⸱ ✅ [redirect](crate::http::service::redirect::Redirect) ⸱ ✅ [router](crate::http::service::web::Router) ⸱ ✅ [dyn router](crate::http::service::web::WebService) ⸱ ✅ [static router](crate::http::service::web::match_service) ⸱ ✅ [handler extractors](crate::http::service::web::extract) ⸱ ✅ [k8s healthcheck](crate::http::service::web::k8s) |
//! | ✅ [http client](crate::http::client) | ✅ [easy client](crate::http::client::EasyHttpWebClient) ⸱ ✅ [high level API](crate::http::service::client::HttpClientExt) ⸱ ✅ [BoringSSL Connect](crate::tls::boring::client::TlsConnectorLayer) ⸱ ✅ [Rustls Connect](crate::tls::rustls::client::TlsConnectorLayer) ⸱ ✅ [HTTP Proxy Connect](crate::http::client::proxy::layer::HttpProxyConnector) ⸱ ✅ [Socks5 Proxy Connect](crate::proxy::socks5::Socks5ProxyConnectorLayer) ⸱ ❌ [Chromium Http](https://github.com/plabayo/rama/issues/189) <sup>(3)</sup> |
//! | ✅ [tls] | ✅ [Rustls](crate::tls::rustls) ⸱ ✅ [BoringSSL](crate::tls::boring) ⸱ ❌ NSS <sup>(3)</sup> |
//! | ✅ [dns] | ✅ [DNS Resolver][crate::dns::DnsResolver] |
//! | ✅ [proxy] protocols | ✅ [PROXY protocol](crate::proxy::haproxy) ⸱ ✅ [http proxy](https://github.com/plabayo/rama/blob/main/examples/http_connect_proxy.rs) ⸱ ✅ [https proxy](https://github.com/plabayo/rama/blob/main/examples/https_connect_proxy.rs) ⸱ ✅ [socks5(h) proxy](https://github.com/plabayo/rama/blob/main/examples/socks5_connect_proxy.rs) |
//! | ✅ web protocols | ✅ [SSE](crate::http::sse) ⸱ ✅ [WS](crate::http::ws) ⸱ ❌ Web Transport <sup>(3)</sup> ⸱ ❌ gRPC <sup>(2)</sup> |
//! | ✅ [async-method trait](https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html) services | ✅ [Service] ⸱ ✅ [Layer] ⸱ ✅ [context] ⸱ ✅ [dyn dispatch](crate::service::BoxService) ⸱ ✅ [middleware](crate::layer) |
//! | ✅ [telemetry] | ✅ [tracing](https://tracing.rs/tracing/) ⸱ ✅ [opentelemetry][telemetry::opentelemetry] ⸱ ✅ [http metrics](crate::http::layer::opentelemetry) ⸱ ✅ [transport metrics](crate::net::stream::layer::opentelemetry) |
//! | ✅ Diagnostics | ✅ [curl export](crate::http::convert::curl) ⸱ ✅ [HAR](crate::http::layer::har) |
//! | ✅ upstream [proxies](proxy) | ✅ [MemoryProxyDB](crate::proxy::MemoryProxyDB) ⸱ ✅ [Username Config] ⸱ ✅ [Proxy Filters](crate::proxy::ProxyFilter) |
//! | ✅ [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) | ✅ [Http Emulation](crate::ua::profile::HttpProfile) ⸱ ✅ [Tls Emulation](crate::ua::profile::TlsProfile) ⸱ ✅ [UA Parsing](crate::ua::UserAgent) |
//! | ✅ [Fingerprinting](crate::net::fingerprint) | ✅ [Ja3](crate::net::fingerprint::Ja3) ⸱ ✅ [Ja4](crate::net::fingerprint::Ja4) ⸱ ✅ [Ja4H](crate::net::fingerprint::Ja4H) ⸱ 🏗️ [Akamai passive h2](https://github.com/plabayo/rama/issues/517) <sup>(1)</sup> ⸱ ✅ [Peetprint (tls)](crate::net::fingerprint::PeetPrint) |
//! | ✅ utilities | ✅ [error handling](crate::error) ⸱ ✅ [graceful shutdown](crate::graceful) ⸱ ✅ [Connection Pool Trait](crate::net::client::pool::Pool) ✅ [Connection Pooling](crate::net::client::pool) ⸱ ✅ [Tower Adapter](crate::utils::tower)  ⸱ 🏗️ IP2Loc <sup>(1)</sup> |
//! | 🏗️ Graphical Interface | 🏗️ traffic logger <sup>(2)</sup> ⸱ 🏗️ [TUI implementation](https://ratatui.rs/) <sup>(2)</sup> ⸱ ❌ traffic intercept <sup>(3)</sup> ⸱ ❌ traffic replay <sup>(3)</sup> |
//! | ✅ binary | ✅ [prebuilt binaries](https://ramaproxy.org/book/deploy/rama-cli) ⸱ 🏗️ proxy config <sup>(2)</sup> ⸱ ✅ http client ⸱ ❌ WASM Plugins <sup>(3)</sup> |
//! | 🏗️ data scraping | 🏗️ Html Processor <sup>(2)</sup> ⸱ ❌ Json Processor <sup>(3)</sup> |
//! | ❌ browser | ❌ JS Engine <sup>(3)</sup> ⸱ ❌ [Web API](https://developer.mozilla.org/en-US/docs/Web/API) Emulation <sup>(3)</sup> |
//!
//! [Username Config]: https://docs.rs/rama-core/latest/rama_core/username/index.html
//!
//! > 🗒️ _Footnotes_
//! >
//! > * <sup>(1)</sup> Part of [`v0.3.0` milestone (ETA: 2025 Q4)](https://github.com/plabayo/rama/milestone/2)
//! > * <sup>(2)</sup> Part of [`v0.4.0` milestone (ETA: 2025 Q4)](https://github.com/plabayo/rama/milestone/3)
//! > * <sup>(3)</sup> No immediate plans, but on our radar. Please [open an issue](https://github.com/plabayo/rama/issues) to request this feature if you have an immediate need for it. Please add sufficient motivation/reasoning and consider [becoming a sponsor](https://ramaproxy.org/book/sponsor.html) to help accelerate its priority.
//!
//! The primary focus of Rama is to aid you in your development of [proxies](https://ramaproxy.org/book/proxies/intro.html):
//!
//! - 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
//! - 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
//! - 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
//! - 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5);
//! - 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
//! - 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).
//!
//! > 💡 Check out [the "Intro to Proxies" chapters in the Rama book](https://ramaproxy.org/book/proxies/intro.html)
//! > to learn more about the different kind of proxies. It might help in case you are new to developing proxies.
//!
//! The [Distortion proxies](https://ramaproxy.org/book/proxies/distort) support
//! comes with [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) emulation capabilities. The emulations are made possible by patterns
//! and data extracted using [`rama-fp`](https://github.com/plabayo/rama/tree/main/rama-fp/). The service is publicly exposed at
//! <https://fp.ramaproxy.org>, made possible by our sponsor host <https://fly.io/>.
//!
//! > 🔁 <https://echo.ramaproxy.org/> is another service publicly exposed.
//! > In contrast to the Fingerprinting Service it is aimed at developers
//! > and allows you to send any http request you wish in order to get an insight
//! > on the Tls Info and Http Request Info the server receives
//! > from you when making that request.
//! >
//! > ```bash
//! > curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
//! >   -H 'x-magic: 42' --data 'whatever forever'
//! > ```
//! >
//! > Feel free to make use of while crafting distorted http requests,
//! > but please do so with moderation. In case you have ideas on how to improve
//! > the service, please let us know [by opening an issue](https://github.com/plabayo/rama/issues).
//!
//! [BrowserStack](https://browserstack.com) sponsors Rama by providing automated cross-platform browser testing
//! on real devices, which [uses the public fingerprinting service](https://github.com/plabayo/rama/tree/main/rama-fp/browserstack/main.py) to aid in automated fingerprint collection
//! on both the Http and Tls layers. By design we do not consider Tcp and Udp fingerprinting.
//!
//! Next to proxies, Rama can also be used to develop [Web Services](#--web-services) and [Http Clients](#--http-clients).
//!
//! - Learn more by reading the Rama book at <https://ramaproxy.org/book>;
//! - or checkout the framework Rust docs at <https://docs.rs/rama>;
//!     - edge docs (for main branch) can be found at <https://ramaproxy.org/docs/rama>.
//!
//! 📖 Rama's full documentation, references and background material can be found in the form of the "rama book" at <https://ramaproxy.org/book>.
//!
//! 💬 Come join us at [Discord](https://discord.gg/29EetaSYCD) on the `#rama` public channel. To ask questions, discuss ideas and ask how rama may be useful for you.
//!
//! > Rama also has a public channel on the official Discord of the tokio project.
//! > Feel free to join us there instead or as well: <https://discord.com/channels/500028886025895936/1349098858831024209>
//!
//! [![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)](https://ramaproxy.org/)
//!
//! ## 🧪 | Experimental
//!
//! 🦙 Rama (ラマ) is to be considered experimental software for the foreseeable future. In the meanwhile it is already used
//! in production by ourselves and others alike. This is great as it gives us new perspectives and data to further improve
//! and grow the framework. It does mean however that there are still several non-backward compatible releases that will follow `0.2`.
//!
//! In the meanwhile the async ecosystem of Rust is also maturing, and edition 2024 is also to be expected as a 2024 end of year gift.
//! It goes also without saying that we do not nilly-willy change designs or break on purpose. The core design is by now also well defined. But truth has to be said,
//! there is still plenty to be improve and work out. Production use and feedback from you and other users helps a lot with that. As such,
//! if you use Rama do let us know feedback over [Discord][discord-url], [email](mailto:glen@plabayo.tech) or a [GitHub issue](https://github.com/plabayo/rama/issues).
//!
//! 👉 If you are a company or enterprise that makes use of Rama, or even an individual user that makes use of Rama for commcercial purposes.
//! Please consider becoming [a business/enterprise subscriber](https://github.com/sponsors/plabayo/sponsorships?tier_id=300734).
//! It helps make the development cycle to remain sustainable, and is beneficial to you as well.
//! As part of your benefits we are also available to assist you with migrations between breaking releases.
//! For enterprise users we can even make time to develop those PR's in your integration codebases ourselves on your behalf.
//! A win for everybody. 💪
//!
//! [discord-url]: https://discord.gg/29EetaSYCD
//!
//! ## 📣 | Rama Ecosystem
//!
//! For now there are only the rama crates found in this repository, also referred to as "official" rama crates.
//!
//! We welcome however community contributions not only in the form of contributions to this repository,
//! but also have people write their own crates as extensions to the rama ecosystem.
//! E.g. perhaps you wish to support an alternative http/tls backend.
//!
//! In case you have ideas for new features or stacks please let us know first.
//! Perhaps there is room for these within an official rama crate.
//! In case it is considered out of scope you are free to make your own community rama crate.
//! Please prefix all rama community crates with "rama-x", this way the crates are easy to find,
//! and are sufficiently different from "official" rama crates".
//!
//! Once you have such a crate published do let us know it, such that we can list them here.
//!
//! ### 📦 | Rama Crates
//!
//! The `rama` crate can be used as the one and only dependency.
//! However, as you can also read in the "DIY" chapter of the book
//! at <https://ramaproxy.org/book/diy.html#empowering>, you are able
//! to pick and choose not only what specific parts of `rama` you wish to use,
//! but also in fact what specific (sub) crates.
//!
//! Here is a list of all `rama` crates:
//!
//! - [`rama`][crate]: one crate to rule them all
//! - [`rama-error`](https://crates.io/crates/rama-error): error utilities for rama and its users
//! - [`rama-macros`](https://crates.io/crates/rama-macros): contains the procedural macros used by `rama`
//! - [`rama-utils`](https://crates.io/crates/rama-utils): utilities crate for rama
//! - [`rama-ws`](https://crates.io/crates/rama-ws): WebSocket (WS) support for rama
//! - [`rama-core`](https://crates.io/crates/rama-core): core crate containing the service, layer and
//!   context used by all other `rama` code, as well as some other _core_ utilities
//! - [`rama-crypto`](https://crates.io/crates/rama-crytpo): rama crypto primitives and dependencies
//! - [`rama-net`](https://crates.io/crates/rama-net): rama network types and utilities
//! - [`rama-dns`](https://crates.io/crates/rama-dns): DNS support for rama
//! - [`rama-unix`](https://crates.io/crates/rama-unix): Unix (domain) socket support for rama
//! - [`rama-tcp`](https://crates.io/crates/rama-tcp): TCP support for rama
//! - [`rama-udp`](https://crates.io/crates/rama-udp): UDP support for rama
//! - [`rama-tls-acme`](https://crates.io/crates/rama-tls-acme): ACME support for rama
//! - [`rama-tls-boring`](https://crates.io/crates/rama-tls-boring): [Boring](https://github.com/plabayo/rama-boring) tls support for rama
//! - [`rama-tls-rustls`](https://crates.io/crates/rama-tls-rustls): [Rustls](https://github.com/rustls/rustls) support for rama
//! - [`rama-proxy`](https://crates.io/crates/rama-proxy): proxy types and utilities for rama
//! - [`rama-socks5`](https://crates.io/crates/rama-socks5): SOCKS5 support for rama
//! - [`rama-haproxy`](https://crates.io/crates/rama-haproxy): rama HaProxy support
//! - [`rama-ua`](https://crates.io/crates/rama-ua): User-Agent (UA) support for `rama`
//! - [`rama-http-types`](https://crates.io/crates/rama-http-types): http types and utilities
//! - [`rama-http`](https://crates.io/crates/rama-http): rama http services, layers and utilities
//! - [`rama-http-backend`](https://crates.io/crates/rama-http-backend): default http backend for `rama`
//! - [`rama-http-core`](https://crates.io/crates/rama-http-core): http protocol implementation driving `rama-http-backend`
//! - [`rama-tower`](https://crates.io/crates/rama-tower): provide [tower](https://github.com/tower-rs/tower) compatibility for `rama`
//!
//! `rama` crates that live in <https://github.com/plabayo/rama-boring> (forks of `cloudflare/boring`):
//!
//! - [`rama-boring`](https://crates.io/crates/rama-boring): BoringSSL bindings for Rama
//! - [`rama-boring-sys`](https://crates.io/crates/rama-boring-sys): FFI bindings to BoringSSL for Rama
//! - [`rama-boring-tokio`](https://crates.io/crates/rama-boring-tokio): an implementation of SSL streams for Tokio backed by BoringSSL in function of Rama
//!
//! repositories in function of rama that aren't crates:
//!
//! - <https://github.com/plabayo/rama-boringssl>:
//!   Fork of [mirror of BoringSSL](https://github.com/plabayo/rama-boringssl)
//!   in function of [rama-boring](https://github.com/plabayo/rama-boring)
//! - <https://github.com/plabayo/homebrew-rama>: Homebrew formula for the rama Cli tool
//!
//! ## 🏢 | Proxy Examples
//!
//! - [/examples/tls_rustls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_termination.rs):
//!   Spawns a mini handmade http server, as well as a TLS termination proxy (using rustls), forwarding the
//!   plain text stream to the first.
//! - [/examples/tls_rustls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_boring_termination.rs):
//!   Spawns a mini handmade http server, as well as a TLS termination proxy (using boring), forwarding the
//!   plain text stream to the first.
//! - [/examples/mtls_tunnel_and_service.rs](https://github.com/plabayo/rama/blob/main/examples/mtls_tunnel_and_service.rs):
//!   Example of how to do mTls (manual Tls, where the client also needs a certificate) using rama,
//!   as well as how one might use this concept to provide a tunnel service build with these concepts;
//! - [/examples/http_connect_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/http_connect_proxy.rs):
//!   Spawns a minimal http proxy which accepts http/1.1 and h2 connections alike,
//!   and proxies them to the target host.
//!
//! ## 🌐 | Web Services
//!
//! Developing proxies are the primary focus of Rama (ラマ). It can however also be used to develop web services to serve web pages, Http API's and static content. This comes with many of the same benefits that you get when developing proxies using Rama:
//!
//! * Use Async Method Traits;
//! * Reuse modular [Tower](https://github.com/tower-rs/tower)-like middleware using extensions as well as strongly typed state;
//! * Have the ability to be in full control of your web stack from Transport Layer (Tcp, Udp), through Tls and Http;
//! * If all you care about is the Http layer then that is fine to.
//! * Be able to trust that your incoming Application Http data has not been modified (e.g. Http header casing and order is preserved);
//! * Easily develop your service at a Request layer and High level functions alike, choices are yours and can be combined.
//!
//! Examples of the kind of web services you might build with rama in function of your proxy service:
//!
//! - a k8s health service ([/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs));
//! - a metric exposure service;
//! - a minimal api service (e.g. to expose device profiles or certificates);
//! - a graphical interface / control panel;
//!
//! > 📖 Learn more about developing web services in the Rama book: <https://ramaproxy.org/book/web_servers.html>.
//!
//! ## 🌐 | Web Service Examples
//!
//! Here are some low level web service examples without fancy features:
//!
//! - [/examples/http_listener_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_listener_hello.rs): is the most basic example on how to provide
//!   a root service with no needs for endpoints or anything else (e.g. good enough for some use cases related
//!   to health services or metrics exposures);
//!   - [/examples/http_health_check.rs](https://github.com/plabayo/rama/blob/main/examples/http_health_check.rs) is an even more minimal example
//!     of a health check service returning a _200 OK_ for any incoming request.
//! - [/examples/http_service_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs): is an example similar to the previous
//!   example but shows how you can also operate on the underlying transport (TCP) layer, prior to passing it to your
//!   http service;
//!
//! There's also a premade webservice that can be used as the health service for your proxy k8s workloads:
//!
//! - [/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs):
//!   built-in web service that can be used as a k8s health service for proxies deploying as a k8s deployment;
//!
//! The following are examples that use the high level concepts of Request/State extractors and IntoResponse converters,
//! that you'll recognise from `axum`, just as available for `rama` services:
//!
//! - [/examples/http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/http_key_value_store.rs):
//!   a web service example showcasing how one might do a key value store web service using `Rama`;
//! - [/examples/http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_service_dir_and_api.rs):
//!   a web service example showcasing how one can make a web service to serve a website which includes an XHR API;
//! - [/examples/http_web_router.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_router.rs):
//!   a web service example showcasing demonstrating how to create a web router, which is excellent for the typical path-centric routing,
//!   and an approach you'll recognise from most other web frameworks out there.
//!
//! The following examples show how you can integrate ACME into you webservices (ACME support in Rama is currently still under heavy development)
// ! - [/examples/acme_http_challenge.rs](https://github.com/plabayo/rama/tree/main/examples/acme_http_challenge.rs):
// !   Authenticate to an acme server using a http challenge
// ! - [/examples/acme_tls_challenge_using_boring.rs](https://github.com/plabayo/rama/tree/main/examples/acme_tls_challenge_using_boring.rs):
// !   Authenticate to an acme server using a tls challenge backed by boringssl
// ! - [/examples/acme_tls_challenge_using_rustls.rs](https://github.com/plabayo/rama/tree/main/examples/acme_tls_challenge_using_rustls.rs):
// !   Authenticate to an acme server using a tls challenge backed by rustls
//!
//! For a production-like example of a web service you can also read the [`rama-fp` source code](https://github.com/plabayo/rama/tree/main/rama-fp/src).
//! This is the webservice behind the Rama fingerprinting service, which is used by the maintainers of 🦙 Rama (ラマ) to generate
//! the UA emulation data for the Http and TLS layers. It is not meant to fingerprint humans or users. Instead it is meant to help
//! automated processes look like a human.
//!
//! > 💡 This example showcases how you can make use of the [`match_service`](https://docs.rs/rama-http/latest/rama_http/service/web/macro.match_service.html)
//! > macro to create a `Box`-free service router. Another example of this approach can be seen in the
//! > [/examples/http_service_match.rs](https://github.com/plabayo/rama/tree/main/examples/http_service_match.rs) example.
//!
//! ### Datastar
//!
//! > Datastar helps you build reactive web applications with the simplicity of server-side rendering and the power of a full-stack SPA framework.
//! >
//! > — <https://data-star.dev/>
//!
//! Rama has built-in support for [🚀 Datastar](https://data-star.dev).
//! You can see it in action in [Examples](https://github.com/plabayo/rama/tree/main/examples):
//!
//! - [/examples/http_sse_datastar_hello.rs](https://github.com/plabayo/rama/tree/main/examples/http_sse_datastar_hello.rs):
//!   SSE Example, showcasing a very simple datastar example,
//!   which is supported by rama both on the client as well as the server side.
//!
//! Rama rust docs:
//!
//! - SSE support: <https://ramaproxy.org/docs/rama/http/sse/datastar/index.html>
//! - Extractor support (`ReadSignals`): <https://ramaproxy.org/docs/rama/http/service/web/extract/datastar/index.html>
//! - Embedded JS Script: <https://ramaproxy.org/docs/rama/http/service/web/response/struct.DatastarScript.html>
//!
//! ## 🧑‍💻 | Http Clients
//!
//! In [The rama book](https://ramaproxy.org/book) you can read and learn that a big pillar of Rama's architecture is build on top of [the Service concept](https://ramaproxy.org/book/intro/services_all_the_way_down.html). A [`Service`][rama-service] takes as input a user-defined `State` (e.g. containing your database Pool) and a `Request`, and uses it to serve either a `Response` or `Error`. Such a [`Service`][rama-service] can produce the response "directly" (also called ☘️ Leaf services) or instead pass the request and state to an inner [`Service`][rama-service] which it wraps around (so called 🍔 Middlewares).
//!
//! [rama-service]: https://ramaproxy.org/docs/rama/service/trait.Service.html
//!
//! It's a powerful concept, originally introduced to Rust by [the Tower ecosystem](https://github.com/tower-rs/tower) and allows you build complex stacks specialised to your needs in a modular and easy manner. Even cooler is that this works for both clients and servers alike.
//!
//! Rama provides an [`EasyHttpWebClient`](https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html) which sends your _Http_ `Request` over the network and returns the `Response` if it receives and read one or an `Error` otherwise. Combined with [the many Layers (middleware)](https://ramaproxy.org/docs/rama/http/layer/index.html) that `Rama` provides and perhaps also some developed by you it is possible to create a powerful _Http_ client suited to your needs.
//!
//! As a 🍒 cherry on the cake you can import the [`HttpClientExt`](https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html) trait in your Rust module to be able to use your _Http_ Client [`Service`][rama-service] stack using a high level API to build and send requests with ease.
//!
//! ### 🧑‍💻 | Http Client Example
//!
//! > 💡 The full "high level" example can be found at [/examples/http_high_level_client.rs](https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs).
//!
//! ```rust,ignore
//! # #[cfg(feature = "do-not-ever-run")]
//! # {
//! use rama::http::service::client::HttpClientExt;
//!
//! let client = (
//!     TraceLayer::new_for_http(),
//!     DecompressionLayer::new(),
//!     AddAuthorizationLayer::basic("john", "123")
//!         .as_sensitive(true)
//!         .if_not_present(),
//!     RetryLayer::new(
//!         ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
//!     ),
//! ).into_layer(EasyHttpWebClient::default());
//!
//! #[derive(Debug, Deserialize)]
//! struct Info {
//!     name: String,
//!     example: String,
//!     magic: u64,
//! }
//!
//! let info: Info = client
//!     .get("http://example.com/info")
//!     .header("x-magic", "42")
//!     .typed_header(Accept::json())
//!     .send(Context::default())
//!     .await
//!     .unwrap()
//!     .try_into_json()
//!     .await
//!     .unwrap();
//! # }
//! ```

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

#[doc(inline)]
pub use ::rama_core::{
    Context, Layer, Service, bytes, combinators, context, error, futures, graceful, inspect, layer,
    matcher, rt, service, username,
};

#[doc(inline)]
pub use ::rama_crypto as crypto;

#[cfg(all(unix, feature = "net"))]
#[doc(inline)]
pub use ::rama_unix as unix;

#[cfg(feature = "tcp")]
#[doc(inline)]
pub use ::rama_tcp as tcp;

#[cfg(feature = "udp")]
#[doc(inline)]
pub use ::rama_udp as udp;

#[doc(inline)]
pub use ::rama_core::telemetry;

#[cfg(any(feature = "rustls", feature = "boring", feature = "acme"))]
pub mod tls;

#[cfg(feature = "dns")]
#[doc(inline)]
pub use ::rama_dns as dns;

#[cfg(feature = "net")]
#[doc(inline)]
pub use ::rama_net as net;

#[cfg(feature = "http")]
pub mod http;

#[cfg(any(feature = "proxy", feature = "haproxy", feature = "socks5"))]
pub mod proxy {
    //! rama proxy support

    #[cfg(feature = "proxy")]
    #[doc(inline)]
    pub use ::rama_proxy::*;

    #[cfg(feature = "haproxy")]
    #[doc(inline)]
    pub use ::rama_haproxy as haproxy;

    #[cfg(feature = "socks5")]
    #[doc(inline)]
    pub use ::rama_socks5 as socks5;
}

#[cfg(feature = "ua")]
#[doc(inline)]
pub use ::rama_ua as ua;

#[cfg(feature = "cli")]
pub mod cli;

pub mod utils {
    //! utilities for rama

    #[doc(inline)]
    pub use ::rama_utils::*;

    #[cfg(feature = "tower")]
    #[doc(inline)]
    pub use ::rama_tower as tower;
}
