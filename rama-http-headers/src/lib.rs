//! # Typed HTTP Headers
//!
//! rama has the opinion that headers should be strongly-typed, because that's
//! why we're using Rust in the first place. To set or get any header, an object
//! must implement the `Header` trait from this module. Several common headers
//! are already provided, such as `Host`, `ContentType`, `UserAgent`, and others.
//!
//! # Why Typed?
//!
//! Or, why not stringly-typed? Types give the following advantages:
//!
//! - More difficult to typo, since typos in types should be caught by the compiler
//! - Parsing to a proper type by default
//!
//! # Defining Custom Headers
//!
//! ## Implementing the `Header` trait
//!
//! Consider a Do Not Track header. It can be true or false, but it represents
//! that via the numerals `1` and `0`.
//!
//! ```
//! use rama_http_types::{HeaderName, HeaderValue};
//! use rama_http_headers::Header;
//!
//! struct Dnt(bool);
//!
//! impl Header for Dnt {
//!     fn name() -> &'static HeaderName {
//!          &rama_http_types::header::DNT
//!     }
//!
//!     fn decode<'i, I>(values: &mut I) -> Result<Self, rama_http_headers::Error>
//!     where
//!         I: Iterator<Item = &'i HeaderValue>,
//!     {
//!         let value = values
//!             .next()
//!             .ok_or_else(rama_http_headers::Error::invalid)?;
//!
//!         if value == "0" {
//!             Ok(Dnt(false))
//!         } else if value == "1" {
//!             Ok(Dnt(true))
//!         } else {
//!             Err(rama_http_headers::Error::invalid())
//!         }
//!     }
//!
//!     fn encode<E>(&self, values: &mut E)
//!     where
//!         E: Extend<HeaderValue>,
//!     {
//!         let s = if self.0 {
//!             "1"
//!         } else {
//!             "0"
//!         };
//!
//!         let value = HeaderValue::from_static(s);
//!
//!         values.extend(std::iter::once(value));
//!     }
//! }
//! ```
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
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

mod header;
#[doc(inline)]
pub use header::{Error, Header};

pub use mime::Mime;

#[macro_use]
pub mod util;

mod common;
mod map_ext;
mod req_builder_ext;
mod resp_builder_ext;

pub mod specifier;

pub use self::common::*;
pub use self::map_ext::HeaderMapExt;
pub use self::req_builder_ext::HttpRequestBuilderExt;
pub use self::resp_builder_ext::HttpResponseBuilderExt;

pub mod encoding;
pub mod forwarded;

mod client_hints;
pub use client_hints::{
    ClientHint, all_client_hint_header_name_strings, all_client_hint_header_names, all_client_hints,
};

pub mod dep {
    //! dependencies rama-http-headers

    pub use mime;
}
