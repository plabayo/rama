//! Rama http protocol implementation and low level utilities.
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
//! ## rama-http-core
//!
//! ### Features
//!
//! - HTTP/1 and HTTP/2
//! - Asynchronous design
//! - Leading in performance
//! - Tested and **correct**
//! - Extensive production use
//! - [Client](client/index.html) and [Server](server/index.html) APIs

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![allow(unreachable_pub)]
#![expect(
    clippy::panic,
    clippy::unreachable,
    reason = "vendored from upstream `hyper`/`h2`: matches upstream invariant-violation panicking style and macro-internal `#[allow]` attrs"
)]

pub mod body;

mod common;

mod error;
pub use self::error::{Error, Result};

pub mod h2;

pub mod service;

mod headers;

pub(crate) mod proto;

pub mod client;
pub mod server;
