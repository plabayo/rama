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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod header;
#[doc(inline)]
pub use header::{Error, HeaderDecode, HeaderEncode, TypedHeader};

#[macro_use]
pub mod util;

mod common;
mod map_ext;
mod req_builder_ext;
mod resp_builder_ext;

pub mod privacy;

pub mod x_robots_tag;
pub use x_robots_tag::XRobotsTag;

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
