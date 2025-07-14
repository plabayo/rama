//! Rama network types and utilities.
//!
//! Protocols such as tcp, http, tls, etc are not explicitly implemented here,
//! see the relevant `rama` crates for this.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub mod address;
pub mod asn;
pub mod client;
pub mod conn;
pub mod forwarded;
pub mod mode;
pub mod proxy;
pub mod stream;
pub mod test_utils;
pub mod user;

pub(crate) mod proto;
#[doc(inline)]
pub use proto::Protocol;

#[cfg(feature = "http")]
pub mod transport;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(any(feature = "tls", feature = "http"))]
pub mod fingerprint;

#[cfg(all(feature = "tls", feature = "http"))]
pub mod https;

pub mod socket;
