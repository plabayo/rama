//! `async fn serve(&self, Context<S>, Request) -> Result<Response, Error>`
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # rama service
//!
//! Heavily inspired by [tower-service](https://docs.rs/tower-service/0.3.0/tower_service/trait.Service.html)
//! and the vast [Tokio](https://docs.rs/tokio/latest/tokio/) ecosystem which makes use of it.
//!
//! Initially the goal was to rely on `tower-service` directly, but it turned out to be
//! too restrictive and difficult to work with, for the use cases we have in Rama.
//! See <https://ramaproxy.org/book/faq.html> for more information regarding this and more.

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

pub mod context;
pub use context::Context;

pub use ::rama_error as error;

pub mod dns;
pub mod graceful;
pub mod rt;

pub mod service;
pub use service::Service;

pub mod layer;
pub use layer::Layer;

pub mod combinators;
pub mod matcher;

#[cfg(feature = "telemetry")]
pub mod telemetry;

#[macro_use]
pub mod utils;
