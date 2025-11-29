//! rama http services, layers and utilities
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
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[doc(inline)]
pub use ::rama_http_types::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, Error as HttpError, HeaderMap, HeaderName,
    HeaderValue, InfiniteReader, Method, Request, Response, Result as HttpResult, Scheme,
    StatusCode, StreamingBody, Uri, Version, conn, header, method, mime, opentelemetry, proto,
    request, response, sse, status, uri, version,
};

pub use ::rama_http_headers as headers;

pub mod body;

pub mod convert;

pub mod matcher;

pub mod layer;
pub mod service;

pub mod io;

pub mod utils;

#[doc(hidden)]
pub mod __macro_dep {
    #[doc(hidden)]
    pub use rama_core as __core;
}
