//! User Agent (UA) parser and types.
//!
//! This module provides a parser ([`UserAgent::new`]) for User Agents
//! as well as a classifier (`UserAgentClassifierLayer` in `rama_http`) that can be used to
//! classify incoming requests based on their User Agent (header).
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # Remarks
//!
//! We classify only the majority User Agents, and we do not classify all User Agents:
//!
//! - All _Chromium_ User Agents are classified as [`UserAgentKind::Chromium`] (including _Google Chrome_);
//! - All _Firefox_ User Agents are classified as [`UserAgentKind::Firefox`];
//! - All _Safari_ User Agents are classified as [`UserAgentKind::Safari`];
//!
//! The only [`Platform`](PlatformKind)s recognised are [`Windows`](PlatformKind::Windows),
//! [`MacOS`](PlatformKind::MacOS), [`Linux`](PlatformKind::Linux),
//! [`Android`](PlatformKind::Android), and [`iOS`](PlatformKind::IOS).
//!
//! User Agent versions are parsed only their most significant version number (e.g. `124` for `Chrome/124.0.0`
//! and `1704` for `Safari Version/17.4`). We do not parse the version for platforms as
//! these are no longer advertised in contemporary User Agents.
//!
//! For UA Classification one can overwrite the [`HttpAgent`] and [`TlsAgent`] advertised by the [`UserAgent`],
//! using the [`UserAgent::with_http_agent`] and [`UserAgent::with_tls_agent`] methods.
//!
//! UA Emulators are advised to interpret the [`UserAgent`] in the following order:
//!
//! 1. first try to find an emulation match using [`UserAgent::header_str`];
//! 2. otherwise try to find an emulation match using [`UserAgent::info`]: where the [`UserAgentKind`] and [`PlatformKind`] should be matched,
//!    and the version should be as close as possible to the version of the [`UserAgent`].
//! 3. otherwise match the [`DeviceKind`] using [`UserAgent::device`].
//! 4. final fallback is to find emulation data for [`DeviceKind::Desktop`].
//!
//! Please open an [issue](https://github.com/plabayo/rama/issues) in case you need support for more User Agents,
//! and have a good case to make for it. For example we might also support the default user agents used by mobile
//! application SDKs. This makes however only sense if we can provide Http and Tls emulation for it.

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

use serde::{Deserialize, Serialize};

mod info;
pub use info::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
};

mod parse;
use parse::parse_http_user_agent_header;

/// Information that can be used to overwrite the [`UserAgent`] of an http request.
///
/// Used by the `UserAgentClassifier` (see `rama-http`) to overwrite the specified
/// information duing the classification of the [`UserAgent`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAgentOverwrites {
    /// Overwrite the [`UserAgent`] of the http `Request` with a custom value.
    ///
    /// This value will be used instead of
    /// the 'User-Agent' http (header) value.
    ///
    /// This is useful in case you cannot set the User-Agent header in your request.
    pub ua: Option<String>,
    /// Overwrite the [`HttpAgent`] of the http `Request` with a custom value.
    pub http: Option<HttpAgent>,
    /// Overwrite the [`TlsAgent`] of the http `Request` with a custom value.
    pub tls: Option<TlsAgent>,
    /// Preserve the original [`UserAgent`] header of the http `Request`.
    pub preserve_ua: Option<bool>,
}

#[cfg(test)]
mod parse_tests;
