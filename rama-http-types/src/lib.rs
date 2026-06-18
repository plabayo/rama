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
use std::sync::Arc;

pub use body::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, InfiniteReader, StreamingBody, sse,
};

pub mod request;
pub mod response;

#[macro_use]
mod convert;
mod byte_str;
mod hyperium_bridge;
// TEMPORARY (Phase 3): hyperium `http::HeaderMap` trailer-boundary bridges,
// used by rama-http/grpc/http-core until `http-body` is forked. Relocates to
// `rama-http-hyperium`.
#[doc(hidden)]
pub use hyperium_bridge::{headers_from_hyperium, headers_to_hyperium};
pub mod method;
pub mod status;

mod error;
#[doc(inline)]
pub use crate::header::{HeaderMap, HeaderName, HeaderValue};
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
    pub use rama_net::http::Version;
}

pub mod request_context;
#[doc(inline)]
pub use request_context::{RequestContext, try_request_ctx_from_http_parts};

pub mod proxy_target_from_req;
#[doc(inline)]
pub use proxy_target_from_req::{
    ProxyTargetFromRequestContext, ProxyTargetFromRequestContextLayer,
};

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
pub struct OriginalRouterUri(pub Arc<Uri>);

pub mod uri;
#[doc(inline)]
pub use uri::{Scheme, Uri, try_to_strip_path_prefix_from_uri};

// TODO: move URI to rama-net :) Somehow...

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

pub mod dep {
    //! Dependencies for rama http modules.
    //!
    //! Exported for your convenience.

    pub(crate) mod hyperium {
        pub(crate) mod http {
            //! Re-export of the [`http`] crate incase we need to convert.
            //!
            //! A general purpose library of common HTTP types.
            //!
            //! [`http`]: https://docs.rs/http

            #[doc(inline)]
            pub(crate) use http::*;
        }

        pub(crate) mod http_body {
            //! Re-export of the [`http-body`] crate incase we need to convert.
            //!
            //! Asynchronous HTTP request or response body
            //!
            //! [`http-body`]: https://docs.rs/http-body

            #[doc(inline)]
            pub use http_body::*;
        }

        pub(crate) mod http_body_util {
            //! Re-export of the [`http-body-util`] crate incase we need to convert.
            //!
            //! Utilities for working with [`http-body`] types.
            //!
            //! [`http-body`]: https://docs.rs/http-body
            //! [`http-body-util`]: https://docs.rs/http-body-util

            #[doc(inline)]
            pub use http_body_util::*;
        }
    }
}
