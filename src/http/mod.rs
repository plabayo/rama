//! Rama http modules.

pub(crate) mod body;
#[doc(inline)]
pub use body::{Body, BodyDataStream};

mod body_limit;
#[doc(inline)]
pub use body_limit::BodyLimit;

mod body_ext;
#[doc(inline)]
pub use body_ext::BodyExtractExt;

mod request_context;
#[doc(inline)]
pub use request_context::{get_request_context, RequestContext};

pub mod utils;

pub mod headers;

/// Type alias for [`http::Request`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Request<T = Body> = http::Request<T>;

pub mod response;
pub use response::{IntoResponse, Response};

pub mod matcher;

pub mod layer;
pub mod service;

pub mod server;

pub mod client;

pub mod io;

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

        pub use http::*;
    }

    pub mod http_body {
        //! Re-export of the [`http-body`] crate.
        //!
        //! Asynchronous HTTP request or response body.
        //!
        //! [`http-body`]: https://docs.rs/http-body

        pub use http_body::*;
    }

    pub mod http_body_util {
        //! Re-export of the [`http-body-util`] crate.
        //!
        //! Utilities for working with [`http-body`] types.
        //!
        //! [`http-body`]: https://docs.rs/http-body
        //! [`http-body-util`]: https://docs.rs/http-body-util

        pub use http_body_util::*;
    }

    pub mod mime {
        //! Re-export of the [`mime`] crate.
        //!
        //! Support MIME (Media Types) as strong types in Rust.
        //!
        //! [`mime`]: https://docs.rs/mime

        pub use mime::*;
    }

    pub mod mime_guess {
        //! Re-export of the [`mime_guess`] crate.
        //!
        //! Guessing of MIME types by file extension.
        //!
        //! [`mime_guess`]: https://docs.rs/mime_guess

        pub use mime_guess::*;
    }
}

pub mod header {
    //! HTTP header types

    pub use crate::http::dep::http::header::*;

    macro_rules! static_header {
        ($($name_bytes:literal),+ $(,)?) => {
            $(
                paste::paste! {
                    #[doc = concat!("header name constant for `", $name_bytes, "`.")]
                    pub static [<$name_bytes:snake:upper>]: super::HeaderName = super::HeaderName::from_static($name_bytes);
                }
            )+
        };
    }

    // non-std conventional
    static_header!["x-forwarded-host", "x-forwarded-for", "x-forwarded-proto",];

    // standard
    static_header!["keep-alive", "proxy-connection", "via",];

    // non-std client ip forward headers
    static_header![
        "cf-connecting-ip",
        "true-client-ip",
        "client-ip",
        "x-client-ip",
        "x-real-ip",
    ];

    /// Static Header Value that is can be used as `User-Agent` or `Server` header.
    pub static RAMA_ID_HEADER_VALUE: HeaderValue =
        HeaderValue::from_static(const_format::formatcp!(
            "{}/{}",
            crate::utils::info::NAME,
            crate::utils::info::VERSION,
        ));
}

pub use self::dep::http::header::HeaderMap;
pub use self::dep::http::header::HeaderName;
pub use self::dep::http::header::HeaderValue;
pub use self::dep::http::method::Method;
pub use self::dep::http::status::StatusCode;
pub use self::dep::http::uri::{Scheme, Uri};
pub use self::dep::http::version::Version;
