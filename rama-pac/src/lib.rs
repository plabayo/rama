//! Proxy Auto-Configuration (PAC) support for Rama.
//!
//! A PAC script is a javascript configuration file exposing
//! `FindProxyForURL(url, host)`, which returns the proxies to use for a
//! given request — the mechanism browsers and system proxy settings have
//! used since Netscape. This crate parses what such a script returns
//! ([`PacDirectives`]), evaluates scripts ([`PacResolver`]) and
//! generates them ([`PacGenerator`]).
//!
//! Scripts are evaluated on a [`JsWorker`][rama_js::JsWorker]: compiled
//! once, called per request. Only run scripts you trust at least as much
//! as your configuration files — see the
//! [rama-js docs][rama_js#limits-are-guardrails-not-a-sandbox] on the
//! reach of its limits.
//!
//! # What one evaluation may spend
//!
//! The execution time limit bounds bytecode, not the native work a host
//! function does, so the host functions carry budgets of their own, reset
//! per evaluation and configurable on [`PacEnv`]:
//!
//! - distinct hosts resolved ([`PacEnv::DEFAULT_MAX_LOOKUPS_PER_EVALUATION`])
//!   — without it, a script looping over `dnsResolve` turns one request into
//!   as many queries as its time limit allows. Repeats within an evaluation
//!   are served from its own cache and cost nothing, as they do in browsers;
//! - `shExpMatch` work ([`PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION`])
//!   — building and running a matcher is native work no deadline reaches;
//! - wall clock spent blocking ([`PacEnv::DEFAULT_MAX_BLOCKING_PER_EVALUATION`])
//!   — a lookup blocks the worker where the execution time limit cannot reach;
//! - `alert` calls ([`PacEnv::DEFAULT_MAX_ALERTS_PER_EVALUATION`]) — a log is
//!   not a channel for a script to fill an operator's disk through.
//!
//! Microsoft's ipv6-aware extensions — `dnsResolveEx` and friends — are
//! defined by default. Chromium defines that set except for
//! `getClientVersion`, while Firefox defines none of it; rama supports the
//! full Microsoft surface and WinHTTP's `FindProxyForURLEx` preference. The
//! extensions can be left out with
//! [`PacEnv::set_ipv6_extensions`][PacEnv::set_ipv6_extensions].
//!
//! Exhausting any of the first three fails the evaluation rather than
//! answering `false`: a client must not be able to spend a budget until a
//! rule stops matching. Alerts past the cap are simply dropped, since losing
//! a diagnostic line is not a routing decision. `myIpAddress` results are
//! cached for the evaluation, and the addresses it may disclose are bounded
//! by [`PacLocalAddresses`].

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod directive;
mod env;
mod generate;
#[cfg(feature = "http")]
mod layer;
mod provider;
#[cfg(feature = "http")]
mod provider_http;
mod resolver;

pub use directive::{PacDirective, PacDirectives};
pub use env::{
    DEFAULT_LOCAL_IP_SCOPES, PacBudgetHandle, PacClock, PacEnv, PacLocalAddresses,
    PacRuntimeBuilder, PacShExpMatch,
};
pub use generate::PacGenerator;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use layer::{
    DEFAULT_PAC_MAX_ROUTES, PacFailurePolicy, PacProxyRoutesLayer, PacProxyRoutesService,
};
pub use provider::{PacScript, PacScriptCache, PacScriptCacheLayer, StaticPacScript};
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use provider_http::FetchPacScript;
pub use resolver::{PacResolver, PacResolverBuilder, PacUrlSanitize};
