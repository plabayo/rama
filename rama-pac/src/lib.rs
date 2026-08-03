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
mod provider;
#[cfg(feature = "http")]
mod provider_http;
mod resolver;

pub use directive::{PacDirective, PacDirectives, PacSocks5Dns};
pub use env::{PacClock, PacEnv};
pub use generate::PacGenerator;
pub use provider::{PacScript, PacScriptCache, PacScriptCacheLayer, StaticPacScript};
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use provider_http::FetchPacScript;
pub use resolver::{PacResolver, PacResolverBuilder, PacUrlSanitize};
