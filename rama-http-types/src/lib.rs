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
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub(crate) mod body;
pub use body::{Body, BodyDataStream, BodyExtractExt, BodyLimit, sse};

mod request;
pub use request::{HttpRequestParts, HttpRequestPartsMut, Request};

/// Type alias for [`http::Response`] whose body type defaults to [`Body`], the most common body
/// type used with rama.
pub type Response<T = Body> = http::Response<T>;

pub mod proto;

pub mod opentelemetry;

pub mod conn;

pub mod dep {
    //! Dependencies for rama http modules.
    //!
    //! Exported for your convenience.

    pub mod http {
        //! Re-export of the [`http`] crate.
        //!
        //! A general purpose library of common HTTP types.
        //!
        //! [`http`]: https://docs.rs/http

        #[doc(inline)]
        pub use http::*;
    }

    pub mod http_body {
        //! Re-export of the [`http-body`] crate.
        //!
        //! Asynchronous HTTP request or response body.
        //!
        //! [`http-body`]: https://docs.rs/http-body

        #[doc(inline)]
        pub use http_body::*;
    }

    pub mod http_body_util {
        //! Re-export of the [`http-body-util`] crate.
        //!
        //! Utilities for working with [`http-body`] types.
        //!
        //! [`http-body`]: https://docs.rs/http-body
        //! [`http-body-util`]: https://docs.rs/http-body-util

        #[doc(inline)]
        pub use http_body_util::*;
    }

    pub mod mime {
        //! Re-export of the [`mime`] crate.
        //!
        //! Support MIME (Media Types) as strong types in Rust.
        //!
        //! [`mime`]: https://docs.rs/mime

        #[doc(inline)]
        pub use mime::*;
    }

    pub mod mime_guess {
        //! Re-export of the [`mime_guess`] crate.
        //!
        //! Guessing of MIME types by file extension.
        //!
        //! [`mime_guess`]: https://docs.rs/mime_guess

        #[doc(inline)]
        pub use mime_guess::*;
    }
}

pub mod header {
    //! HTTP header types

    #[doc(inline)]
    pub use crate::dep::http::header::*;

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
    static_header!["x-forwarded-host", "x-forwarded-for", "x-forwarded-proto",];

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

    /// Static Header Value that is can be used as `User-Agent` or `Server` header.
    pub static RAMA_ID_HEADER_VALUE: HeaderValue = HeaderValue::from_static(
        const_format::formatcp!("{}/{}", rama_utils::info::NAME, rama_utils::info::VERSION),
    );
}

#[doc(inline)]
pub use self::dep::http::header::{HeaderMap, HeaderName, HeaderValue};
#[doc(inline)]
pub use self::dep::http::method::Method;
#[doc(inline)]
pub use self::dep::http::status::StatusCode;
#[doc(inline)]
pub use self::dep::http::uri::{Scheme, Uri};
#[doc(inline)]
pub use self::dep::http::version::Version;
