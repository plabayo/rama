#![cfg_attr(nightly_error_messages, feature(diagnostic_namespace))]
//! # rama
//!
//! 🦙 Rama is a modular proxy framework for the 🦀 Rust language to move and transform your network packets. You can use it to develop:
//!
//! - 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
//! - 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
//! - 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
//! - 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5);
//! - 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
//! - 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).
//!
//! Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
//! Please refer to [the examples found in the `./examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes.
//!
//! ![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)
//!
//! - Learn more by reading the Rama book at <https://ramaproxy.org/book>
//! - or continue to read the framework Rust docs here.
//!
//! # High-level features
//!
//! - Macro-free API.
//! - Use a tower-like service abstraction, ready for stable Async Rust, with an eye on the future.
//! - Compose layers, services and state from the Transport Layer all the way to the Application Layer.
//! - Compose your own proxy with the provided building blocks and your own custom logic intertwined.
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
//! See [the examples found in the `./examples` dir](https://github.com/plabayo/rama/tree/main/examples)
//! to get inspired on how you can use it for your purposes. Or check the [Rama book](https://ramaproxy.org/book)
//! for more in-depth information.
//!

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

pub mod tls;

pub mod http;
