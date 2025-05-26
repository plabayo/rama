//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

#[doc(inline)]
pub use ::rama_http::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, HeaderMap, HeaderName, HeaderValue, Method,
    Request, Response, Scheme, StatusCode, Uri, Version, conn, dep, header, headers, io, matcher,
    proto, service,
};

#[cfg(feature = "http-full")]
#[doc(inline)]
pub use ::rama_http_core as core;

pub mod layer {
    //! Http [`Layer`][crate::Layer]s provided by Rama.
    //!
    //! mostly contains re-exports from
    //! `rama-http` and `rama-http-backend`.

    #[doc(inline)]
    pub use ::rama_http::layer::*;

    #[cfg(feature = "http-full")]
    #[doc(inline)]
    pub use ::rama_http_backend::server::layer::*;
}

#[cfg(feature = "http-full")]
#[doc(inline)]
pub use ::rama_http_backend::{client, server};
