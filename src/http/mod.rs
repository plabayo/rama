//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

#[doc(inline)]
pub use ::rama_http::{
    Body, BodyDataStream, BodyExtractExt, BodyLimit, BodyLimitLayer, BodyLimitService, HeaderMap,
    HeaderName, HeaderValue, HttpError, HttpResult, InfiniteReader, Method, Request,
    RequestContext, Response, Scheme, StatusCode, StreamingBody, Uri, Version, body, conn, convert,
    fingerprint, header, headers, io, layer, matcher, mime, opentelemetry, proto, protocols,
    request, request_context, response, service, sse, try_request_ctx_from_http_parts, uri, utils,
};

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
#[doc(inline)]
pub use ::rama_http_core as core;

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
pub mod client;

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
#[doc(inline)]
pub use ::rama_http_backend::server;

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
#[doc(inline)]
pub use ::rama_http_backend::proxy;

#[cfg(feature = "ws")]
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
#[doc(inline)]
pub use ::rama_ws as ws;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub mod tls;

#[cfg(feature = "grpc")]
#[cfg_attr(docsrs, doc(cfg(feature = "grpc")))]
#[doc(inline)]
pub use ::rama_grpc as grpc;
