#![cfg_attr(nightly_error_messages, feature(diagnostic_namespace))]
//! # rama
//!
//! 🦙 Rama (ラマ) is a modular proxy framework for the 🦀 Rust language to move and transform your network packets. You can use it to develop:
//!
//! - 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
//! - 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
//! - 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
//! - 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5) (will be implemented in `v0.3`);
//! - 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
//! - 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).
//!
//! Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
//! Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes.
//!
//! ![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)
//!
//! Rama aims to offer a flexible and modular framework that empowers you to
//! effortlessly create your own proxy. Unlike prebuilt tools that can be configured
//! to suit your needs, Rama allows you to build proxies using code.
//! The framework is designed to be both user-friendly and robust,
//! offering a powerful and adaptable solution. Although using code may not be as intuitive
//! as configuring files, it grants you greater freedom and control over the final product.
//! This way, you can create a proxy that precisely fits your requirements and nothing more.
//!
//! Learn more by reading the Rama book at <https://ramaproxy.org/book> or continue to read the framework Rust docs here,
//! to [get started](#getting-started).
//!
//! # High-level features
//!
//! - Rama offers a macro-free API, ensuring a clean and streamlined development experience.
//! - The framework utilizes a tower-like service abstraction, which is poised for
//!   stable Async Rust and future growth.
//! - You can easily compose layers, services, and state from the Transport Layer
//!   to the Application Layer, allowing for a highly customizable solution.
//! - With Rama, you have the freedom to build your own proxy using
//!   the provided building blocks and your own custom logic, resulting in a
//!   tailored and efficient solution.
//!
//! # Edge documentation
//!
//! In case you are using `rama` as a _git_ dependency directly from the `main` branch or
//! a (feature) derivative of you can still consult the rust docs of `rama` online. You can find
//! the "edge" rust docs for the latest `main` _git_ commit of `rama` at:
//!
//! > <https://ramaproxy.org/docs/rama/index.html>
//!
//! # Getting started
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rama = "0.2"
//! ```
//!
//! or add it using: `cargo add rama`.
//!
//! See [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes. Or check the [Rama book](https://ramaproxy.org/book)
//! for more in-depth information.
//!

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
