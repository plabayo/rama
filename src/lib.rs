#![cfg_attr(nightly_error_messages, feature(diagnostic_namespace))]
//! 🦙 Rama is a modular proxy framework for the 🦀 Rust language to move and transform your network packets.
//! You can use it to develop 🚦 reverse proxies, 🔓 TLS termination proxies, 🌐 HTTP(S) proxies, 🧦 SOCKS5 proxies
//! and 🕵️‍♀️ distortion proxies.
//!
//! # High-level features
//!
//! - Macro-free API.
//! - Use a tower-like service abstraction, ready for stable Async Rust, with an eye on the future.
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
// TODO: delete these allows after refactor is finished
#![allow(unused_macros)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
pub(crate) mod macros;

#[cfg(test)]
mod test_helpers;

pub mod graceful;

pub mod error;
pub mod service;

pub mod stream;

pub mod tcp;

pub mod tls;

pub mod http;
