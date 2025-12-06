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
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

pub mod body;
use std::sync::Arc;

pub use body::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, InfiniteReader, StreamingBody, sse,
};

pub mod request;
pub mod response;
pub use crate::dep::hyperium::http::method;
pub use crate::dep::hyperium::http::status;
pub use crate::dep::hyperium::http::version;

#[doc(inline)]
pub use crate::dep::hyperium::http::{Error, Result};
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
pub use crate::version::Version;

#[derive(Debug, Clone)]
/// Extension type that can be inserted in case a Uri is modified as part of nested routers
pub struct OriginalRouterUri(pub Arc<Uri>);

pub mod uri;
#[doc(inline)]
pub use uri::{Scheme, Uri, try_to_strip_path_prefix_from_uri};

// TODO: move URI to rama-net :) Somehow...

pub mod proto;

pub mod opentelemetry;

pub mod conn;

pub mod header {
    //! HTTP header types

    #[doc(inline)]
    pub use crate::dep::hyperium::http::header::*;

    macro_rules! static_header {
        ($($name_bytes:literal),+ $(,)?) => {
            $(
                rama_macros::paste! {
                    #[doc = concat!("header name constant for `", $name_bytes, "`.")]
                    pub static [<$name_bytes:snake:upper>]: super::HeaderName = super::HeaderName::from_static($name_bytes);
                }
            )+
        };
    }

    // non-std conventional
    static_header![
        "x-forwarded-host",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-robots-tag",
        "x-clacks-overhead",
    ];

    // new standard sec-headers
    static_header!["sec-gpc"];

    // standard
    static_header!["keep-alive", "proxy-connection", "last-event-id"];

    // non-std client ip forward headers
    static_header![
        "cf-connecting-ip",
        "true-client-ip",
        "client-ip",
        "x-client-ip",
        "x-real-ip",
    ];

    // extra access control headers
    static_header![
        "access-control-allow-private-network",
        "access-control-request-private-network",
    ];

    /// Static Header Value that is can be used as `User-Agent` or `Server` header.
    pub static RAMA_ID_HEADER_VALUE: HeaderValue = HeaderValue::from_static(
        const_format::formatcp!("{}/{}", rama_utils::info::NAME, rama_utils::info::VERSION),
    );
}

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
            pub use http::*;
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
