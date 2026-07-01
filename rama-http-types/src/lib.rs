//! rama http types and minimal utilities
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

pub mod body;
use rama_core::extensions::Extension;

pub use body::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, InfiniteReader, StreamingBody, sse,
};

pub mod request;
pub mod response;

#[macro_use]
mod convert;
pub mod method;
pub mod status;

mod error;
#[doc(inline)]
pub use crate::header::{HeaderMap, HeaderName, HeaderValue, IntoOrderedIter, OrderedIter};
#[doc(inline)]
pub use crate::method::Method;
#[doc(inline)]
pub use crate::request::{HttpRequestParts, HttpRequestPartsMut, Request};
#[doc(inline)]
pub use crate::response::Response;
#[doc(inline)]
pub use crate::status::StatusCode;
#[doc(inline)]
pub use error::{Error, Result};
#[doc(inline)]
pub use rama_net::http::Version;

pub mod version {
    //! HTTP version type, owned by `rama-net`.

    #[doc(inline)]
    pub use rama_net::http::{InvalidVersion, Version};
}

/// Hosts the per-concern `*InputExt` accessor impls for http `Request`/`Parts`.
mod input_ext;

pub mod fingerprint;

mod body_limit_layer;
#[doc(inline)]
pub use body_limit_layer::{BodyLimitLayer, BodyLimitService};

pub mod stream {
    //! Stream-oriented utilities layered on top of the HTTP request type.

    pub mod matcher;
}

pub mod client {
    //! Client-oriented utilities layered on top of the HTTP request type.

    pub mod pool;
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
/// Extension type that can be inserted in case a Uri is modified as part of nested routers
pub struct OriginalRouterUri(pub Uri);

pub mod uri;
#[doc(inline)]
pub use uri::{Uri, try_to_strip_path_prefix_from_uri};

pub mod proto;

pub mod opentelemetry;

pub mod conn;

pub mod proxy;

pub mod header;

pub mod mime {
    //! Re-export of the [`mime`] crate.
    //!
    //! Support MIME (Media Types) as strong types in Rust.
    //!
    //! [`mime`]: https://docs.rs/mime

    #[doc(inline)]
    pub use mime::*;

    #[doc(inline)]
    pub use mime_guess as guess;
}
