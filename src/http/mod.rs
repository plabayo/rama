//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

#[doc(inline)]
pub use ::rama_http::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, HeaderMap, HeaderName, HeaderValue, HttpError,
    HttpResult, InfiniteReader, Method, Request, Response, Scheme, StatusCode, StreamingBody, Uri,
    Version, body, conn, convert, header, headers, io, matcher, mime, opentelemetry, proto,
    request, response, service, sse, uri, utils,
};

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
    #[doc(inline)]
    pub use ::rama_http_backend::server::layer::*;
}

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
pub mod client;

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
#[doc(inline)]
pub use ::rama_http_backend::server;

#[cfg(feature = "ws")]
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
#[doc(inline)]
pub use ::rama_ws as ws;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub mod tls;
