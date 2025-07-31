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
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

#[doc(inline)]
pub use ::rama_http_types::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, HeaderMap, HeaderName, HeaderValue,
    InfiniteReader, Method, Request, Response, Scheme, StatusCode, Uri, Version, conn, header,
    opentelemetry, proto, sse,
};

pub mod body;

pub use ::rama_http_headers as headers;

pub mod matcher;

pub mod layer;
pub mod service;

pub mod io;

pub mod utils;

pub mod dep {
    //! Dependencies for rama http modules.
    //!
    //! Exported for your convenience.

    pub use rama_core as core;

    #[doc(inline)]
    pub use ::rama_http_types::dep::{http, http_body, http_body_util, mime, mime_guess};
}
