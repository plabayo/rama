#![cfg_attr(nightly_error_messages, feature(diagnostic_namespace))]
//! # rama
//!
//! 🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
//! The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).
//!
//! Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
//! Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes.
//!
//! The primary focus of Rama is to aid you in your development of proxies:
//!
//! - 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
//! - 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
//! - 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
//! - 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5) (will be implemented in `v0.3`);
//! - 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
//! - 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).
//!
//! The [Distortion proxies](https://ramaproxy.org/book/proxies/distort) support
//! comes with User-Agent (UA) emulation capabilities. The emulations are made possible by patterns
//! and data extracted using [`rama-fp`](https://github.com/plabayo/rama/tree/main/rama-fp/). The service is publicly exposed at
//! <https://fp.ramaproxy.org>, made possible by our sponsor host <https://fly.io/>.
//!
//! [BrowserStack](https://browserstack.com) sponsors Rama by providing automated cross-platform browser testing
//! on real devices, which [uses the public fingerprinting service](./rama-fp/browserstack/main.py) to aid in automated fingerprint collection
//! on both the Http and Tls layers. By design we do not consider Tcp and Udp fingerprinting.
//!
//! Next to proxies, Rama can also be used to develop [Web Services](#--web-services) and [Http Clients](#--http-clients).
//!
//! - Learn more by reading the Rama book at <https://ramaproxy.org/book>;
//! - or checkout the framework Rust docs at <https://docs.rs/rama>;
//!     - edge docs (for main branch) can be found at <https://ramaproxy.org/docs/rama>.
//!
//! There is no [crates.io](https://crates.io) release of rama yet.
//! If you already want to start using rama you can do so by referring to it in your `Cargo.toml` as follows:
//!
//! ```toml
//! rama = { git = "https://github.com/plabayo/rama" }
//! ```
//!
//! 📖 Rama's full documentation, references and background material can be found in the form of the "rama book" at <https://ramaproxy.org/book>.
//!
//! 💬 Come join us at [Discord][discord-url] on the `#rama` public channel. To ask questions, discuss ideas and ask how rama may be useful for you.
//! 
//! [![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)](https://ramaproxy.org/)
//!
//! ### 🏢 | Proxy Examples
//!
//! - [/examples/tls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_termination.rs):
//!   Spawns a mini handmade http server, as well as a TLS termination proxy, forwarding the
//!   plain text stream to the first.
//! - [/examples/tls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_termination.rs):
//!   Spawns a mini handmade http server, as well as a TLS termination proxy, forwarding the
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
//!
//! For a production-like example of a web service you can also read the [`rama-fp` source code](https://github.com/plabayo/rama/tree/main/rama-fp/src).
//! This is the webservice behind the Rama fingerprinting service, which is used by the maintainers of 🦙 Rama (ラマ) to generate
//! the UA emulation data for the Http and TLS layers. It is not meant to fingerprint humans or users. Instead it is meant to help
//! automated processes look like a human.
//!
//! > This example showcases how you can make use of the [`match_service`](https://ramaproxy.org/docs/rama/http/service/web/macro.match_service.html)
//! > macro to create a `Box`-free service router. Another example of this approach can be seen in the
//! > [http_service_match.rs](https://github.com/plabayo/rama/tree/main/examples/http_service_match.rs) example.
//!
//! ## 🧑‍💻 | Http Clients
//!
//! In [The rama book](https://ramaproxy.org/book) you can read and learn that a big pilar of Rama's architecture is build on top of [the Service concept](https://ramaproxy.org/book/intro/services_all_the_way_down.html). A [`Service`][rama-service] takes as input a user-defined `State` (e.g. containing your database Pool) and a `Request`, and uses it to serve either a `Response` or `Error`. Such a [`Service`][rama-service] can produce the response "directly" (also called ☘️ Leaf services) or instead pass the request and state to an inner [`Service`][rama-service] which it wraps around (so called 🍔 Middlewares).
//!
//! [rama-service]: https://ramaproxy.org/docs/rama/service/trait.Service.html
//!
//! It's a powerful concept, originally introduced to Rust by [the Tower ecosystem](https://github.com/tower-rs/tower) and allows you build complex stacks specialised to your needs in a modular and easy manner. Even cooler is that this works for both clients and servers alike.
//!
//! Rama provides an [`HttpClient`](https://ramaproxy.org/docs/rama/http/client/struct.HttpClient.html) which sends your _Http_ `Request` over the network and returns the `Response` if it receives and read one or an `Error` otherwise. Combined with [the many Layers (middleware)](https://ramaproxy.org/docs/rama/http/layer/index.html) that `Rama` provides and perhaps also some developed by you it is possible to create a powerful _Http_ client suited to your needs.
//!
//! As a 🍒 cherry on the cake you can import the [`HttpClientExt`](https://ramaproxy.org/docs/rama/http/client/trait.HttpClientExt.html) trait in your Rust module to be able to use your _Http_ Client [`Service`][rama-service] stack using a high level API to build and send requests with ease.
//!
//! ### 🧑‍💻 | Http Client Example
//!
//! > The full example can be found at [/examples/http_high_level_client.rs](https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs).
//!
//! ```rust,ignore
//! use rama::http::client::HttpClientExt;
//!
//! let client = ServiceBuilder::new()
//!     .layer(TraceLayer::new_for_http())
//!     .layer(DecompressionLayer::new())
//!     .layer(
//!         AddAuthorizationLayer::basic("john", "123")
//!             .as_sensitive(true)
//!             .if_not_present(),
//!     )
//!     .layer(RetryLayer::new(
//!         ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
//!     ))
//!     .service(HttpClient::new());
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
//! ```

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![warn(
    clippy::all,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

#[macro_use]
pub(crate) mod macros;

#[cfg(test)]
mod test_helpers;

pub mod graceful;
pub mod latency;

pub(crate) mod future;

pub mod rt;

pub mod error;
pub mod service;

pub mod stream;

pub mod tcp;

pub mod dns;
pub mod tls;
pub mod uri;

pub mod http;

pub mod proxy;
pub mod ua;
