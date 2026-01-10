//! 🦙 **rama** (ラマ) is a modular network service and proxy framework for the 🦀 Rust language.
//!
//! It gives you programmable control over how packets move through your stack so you can build:
//!
//! - production grade reverse and forward proxies
//! - HTTP and TLS termination layers
//! - security inspection and distortion proxies
//! - high volume scraping and data extraction pipelines
//! - custom HTTP clients with deep control over the wire
//!
//! rama is already used in production by companies at scale for use cases such as network
//! security, data extraction, API gateways and routing.
//!
//! rama is async first and uses [`tokio`](https://tokio.rs) as its only async runtime.
//!
//! ---
//!
//! ## Who is rama for
//!
//! - **Developers and teams** who want fine grained control over transport, TLS and HTTP
//!   while staying in safe Rust.
//! - **Organisations** that need a partner to:
//!   - maintain and evolve a proxy or network platform
//!   - build custom features on top of rama
//!   - get support and training for internal teams
//!
//! ---
//!
//! ## Getting started
//!
//! 1. Read the ["Why rama" chapter](https://ramaproxy.org/book/why_rama) for background.
//! 2. Run one of the examples in
//!    <https://github.com/plabayo/rama/tree/main/examples>.
//! 3. Use the rama book at <https://ramaproxy.org/book> and the Rust docs at
//!    <https://docs.rs/rama> or <https://ramaproxy.org/docs/rama> as references
//!    while building your own stack.
//!
//! You can also use the `rama` binary if you want to use some of the rama features from the command line
//! without writing your own Rust code. See <https://ramaproxy.org/book/deploy/rama-cli.html>.
//!
//! ---
//!
//! ## Experimental status
//!
//! rama is considered experimental software for the foreseeable future. At the same time
//! it is already used in production by the maintainers and by other organisations.
//!
//! Real world use helps shape the design and priorities. If you run rama in production,
//! feedback via GitHub issues, email or Discord is very welcome.
//!
//! ---
//!
//! ## For organisations
//!
//! If your organisation relies on rama or plans to, the maintainers offer:
//!
//! - support and maintenance contracts
//! - feature development with higher priority or extended scope
//! - consulting and integration work around proxies, scraping and security
//! - training and mentoring for your internal teams
//!
//! To discuss options, contact `hello@plabayo.tech`.
//!
//! Enterprise sponsorships are available via GitHub Sponsors and help fund development,
//! maintenance and ecosystem work.
//!
//! ---
//!
//! ## Batteries included
//!
//! rama ships with batteries included for transports, HTTP, TLS, DNS, proxy protocols,
//! telemetry, fingerprinting and more. Some highlights:
//!
//! - transports: TCP, UDP, Unix domain sockets, connection pooling and middleware
//! - HTTP: HTTP 1 and 2 servers and clients, layers and middleware, metrics, tracing
//! - TLS: Rustls and BoringSSL support
//! - proxy protocols: HTTP connect, HTTPS connect, SOCKS5, HAProxy PROXY protocol
//! - fingerprinting and user agent emulation for distortion and anti bot use cases
//! - telemetry: tracing integration and OpenTelemetry metrics for HTTP and transport layers
//!
//! For a detailed and up to date overview see the feature table in the README and the
//! relevant chapters in the rama book.
//!
//! ---
//!
//! ## Proxies and proxy focused use cases
//!
//! The primary focus of rama is to help you build proxies and proxy like services:
//!
//! - reverse proxies
//! - TLS termination proxies
//! - HTTP and HTTPS proxies
//! - SOCKS5 proxies
//! - SNI based routing proxies
//! - MITM proxies
//! - distortion proxies with UA emulation and fingerprinting
//!
//! The proxy chapters in the book start at
//! <https://ramaproxy.org/book/proxies/intro.html>.
//!
//! Distortion support includes User Agent emulation for HTTP and TLS built on top of data
//! collected by [`rama-fp`](https://github.com/plabayo/rama/tree/main/rama-fp) and exposed
//! via <https://fp.ramaproxy.org>.
//!
//! ---
//!
//! ## Web services
//!
//! Even though proxies are the main focus, rama can also be used to build general purpose
//! web services. Typical use cases:
//!
//! - dynamic HTTP endpoints
//! - serving static files
//! - websockets and Server Sent Events (SSE)
//! - health and readiness endpoints for Kubernetes
//! - metrics and control plane services
//!
//! rama gives you:
//!
//! - async method trait based services and layers
//! - modular middleware to reuse across services and clients
//! - full control from transport through TLS to HTTP and web protocols
//!
//! Learn more in the web servers chapter of the book:
//! <https://ramaproxy.org/book/web_servers.html>.
//!
//! ### Datastar integration
//!
//! rama has built in support for [Datastar](https://data-star.dev) for reactive web
//! applications using SSE. See the examples at
//! <https://github.com/plabayo/rama/tree/main/examples> and the docs at:
//!
//! - <https://ramaproxy.org/docs/rama/http/sse/datastar/index.html>
//! - <https://ramaproxy.org/docs/rama/http/service/web/extract/datastar/index.html>
//! - <https://ramaproxy.org/docs/rama/http/service/web/response/struct.DatastarScript.html>
//!
//! ---
//!
//! ## Web clients
//!
//! A large part of rama is built on top of a service concept. A `Service` takes a `Request`
//! and produces a `Response` or `Error`. Services can be leaf services or middlewares that
//! wrap inner services.
//!
//! rama provides:
//!
//! - an `EasyHttpWebClient` for HTTP requests
//! - many HTTP layers to tune timeouts, retries, telemetry and more
//! - a high level `HttpClientExt` trait to build and send requests with a fluent API
//!
//! See the client example at
//! <https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs> and the
//! docs at:
//!
//! - <https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html>
//! - <https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html>
//!
//! ---
//!
//! ## Ecosystem
//!
//! The `rama` crate can be used as the one and only dependency.
//! However, as you can also read in the "DIY" chapter of the book
//! at <https://ramaproxy.org/book/diy.html#empowering>, you are able
//! to pick and choose not only what specific parts of `rama` you wish to use,
//! but also in fact what specific (sub) crates.
//!
//! Here is a list of all `rama` crates:
//!
//! - [`rama`](https://crates.io/crates/rama): one crate to rule them all
//! - [`rama-error`](https://crates.io/crates/rama-error): error utilities for rama and its users
//! - [`rama-macros`](https://crates.io/crates/rama-macros): contains the procedural macros used by `rama`
//! - [`rama-utils`](https://crates.io/crates/rama-utils): utilities crate for rama
//! - [`rama-ws`](https://crates.io/crates/rama-ws): WebSocket (WS) support for rama
//! - [`rama-core`](https://crates.io/crates/rama-core): core crate containing the service and layer traits
//!   used by all other `rama` code, as well as some other _core_ utilities
//! - [`rama-crypto`](https://crates.io/crates/rama-crypto): rama crypto primitives and dependencies
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
//! - [`rama-haproxy`](https://crates.io/crates/rama-haproxy): rama HAProxy support
//! - [`rama-ua`](https://crates.io/crates/rama-ua): User-Agent (UA) support for `rama`
//! - [`rama-http-types`](https://crates.io/crates/rama-http-types): http types and utilities
//! - [`rama-http-headers`](https://crates.io/crates/rama-http-headers): typed http headers
//! - [`rama-grpc`](https://crates.io/crates/rama-grpc): Grpc support for rama
//! - [`rama-grpc-codegen`](https://crates.io/crates/rama-grpc-codegen): Grpc codegen support for rama
//! - [`rama-http`](https://crates.io/crates/rama-http): rama http services, layers and utilities
//! - [`rama-http-backend`](https://crates.io/crates/rama-http-backend): default http backend for `rama`
//! - [`rama-http-core`](https://crates.io/crates/rama-http-core): http protocol implementation driving `rama-http-backend`
//! - [`rama-tower`](https://crates.io/crates/rama-tower): provide [tower](https://github.com/tower-rs/tower) compatibility for `rama`
//!
//! `rama` crates that live in <https://github.com/plabayo/rama-boring> (forks of `cloudflare/boring`):
//!
//! - [`rama-boring`](https://crates.io/crates/rama-boring): BoringSSL bindings for rama
//! - [`rama-boring-sys`](https://crates.io/crates/rama-boring-sys): FFI bindings to BoringSSL for rama
//! - [`rama-boring-tokio`](https://crates.io/crates/rama-boring-tokio): an implementation of SSL streams for Tokio backed by BoringSSL in function of rama
//!
//! repositories in function of rama that aren't crates:
//!
//! - <https://github.com/plabayo/rama-boringssl>:
//!   Fork of [mirror of BoringSSL](https://github.com/plabayo/rama-boringssl)
//!   in function of [rama-boring](https://github.com/plabayo/rama-boring)
//! - <https://github.com/plabayo/homebrew-rama>: Homebrew formula for the rama Cli tool
//!
//! Repositories that we maintain and are re exported by the root `rama` crate:
//!
//! - <https://github.com/plabayo/tokio-graceful>: Graceful shutdown util for Rust projects using the Tokio Async runtime.
//!
//! Community crates that extend the ecosystem are encouraged. If you publish a community
//! crate, please prefix it with `rama-x` so it is easy to discover and clearly distinct
//! from the official crates in this repository.
//!
//! ---
//!
//! ## Safety and compatibility
//!
//! - rama crates avoid `unsafe` Rust as much as possible and use it only where necessary.
//! - Supply chain auditing is done with [`cargo vet`](https://github.com/mozilla/cargo-vet).
//! - Tier 1 platforms include macOS, Linux and Windows on modern architectures.
//! - The minimum supported Rust version (MSRV) is `1.91`.
//!
//! For details see the compatibility section in the README and the CI configuration in
//! the repository.
//!
//! ---
//!
//! ## License
//!
//! rama is free and open source software, dual licensed under MIT and Apache 2.0.
//!
//! You can use rama for commercial and non commercial purposes. If rama becomes an
//! important part of your stack, please consider supporting the project as a sponsor
//! or partner.
//!
//! ---
//!
//! ## Community and links
//!
//! - Official website: <https://ramaproxy.org>
//! - Rama Book index: <https://ramaproxy.org/book>
//! - Rust docs: <https://docs.rs/rama> (latest release) and <https://ramaproxy.org/docs/rama> (edge)
//! - Repository and issues: <https://github.com/plabayo/rama>
//! - Discord: <https://discord.gg/29EetaSYCD>
//! - FAQ: <https://ramaproxy.org/book/faq.html>
//! - Netstack FM podcast: <https://netstack.fm> (podcast about networking and Rust)
//!
//! If you are not sure where to start, read "Why rama" in the book, run a proxy example and then
//! iterate from there with the book and docs at hand.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[doc(inline)]
pub use ::rama_core::{
    Layer, Service, ServiceInput, bytes, combinators, conversion, error, extensions, futures,
    graceful, layer, matcher, rt, service, stream, username,
};

#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
#[doc(inline)]
pub use ::rama_crypto as crypto;

#[cfg(all(target_family = "unix", feature = "net"))]
#[cfg_attr(docsrs, doc(cfg(all(target_family = "unix", feature = "net"))))]
#[doc(inline)]
pub use ::rama_unix as unix;

#[cfg(feature = "tcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcp")))]
#[doc(inline)]
pub use ::rama_tcp as tcp;

#[cfg(feature = "udp")]
#[cfg_attr(docsrs, doc(cfg(feature = "udp")))]
#[doc(inline)]
pub use ::rama_udp as udp;

pub mod telemetry;

#[cfg(any(feature = "rustls", feature = "boring", feature = "acme"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "rustls", feature = "boring", feature = "acme")))
)]
pub mod tls;

#[cfg(feature = "dns")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns")))]
#[doc(inline)]
pub use ::rama_dns as dns;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
#[doc(inline)]
pub use ::rama_net as net;

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod http;

#[cfg(any(feature = "proxy", feature = "haproxy", feature = "socks5"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "proxy", feature = "haproxy", feature = "socks5")))
)]
pub mod proxy {
    //! rama proxy support

    #[cfg(feature = "proxy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "proxy")))]
    #[doc(inline)]
    pub use ::rama_proxy::*;

    #[cfg(feature = "haproxy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "haproxy")))]
    #[doc(inline)]
    pub use ::rama_haproxy as haproxy;

    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    #[doc(inline)]
    pub use ::rama_socks5 as socks5;
}

#[cfg(feature = "ua")]
#[cfg_attr(docsrs, doc(cfg(feature = "ua")))]
#[doc(inline)]
pub use ::rama_ua as ua;

#[cfg(feature = "cli")]
#[cfg_attr(docsrs, doc(cfg(feature = "cli")))]
pub mod cli;

pub mod utils {
    //! utilities for rama

    #[doc(inline)]
    pub use ::rama_utils::*;

    #[cfg(feature = "tower")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
    #[doc(inline)]
    pub use ::rama_tower as tower;
}
