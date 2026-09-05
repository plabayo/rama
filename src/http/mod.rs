//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

#[doc(inline)]
pub use ::rama_http::{
    Body, BodyCaptureEvent, BodyCaptureSink, BodyDataStream, BodyExtractExt, BodyLimit,
    BodyLimitLayer, BodyLimitService, BufferedBodyCapture, CaptureBody, CaptureCanceled,
    CaptureHandle, CaptureLimit, CaptureOutcome, CapturedBody, HeaderMap, HeaderName, HeaderValue,
    HttpError, HttpResult, InfiniteReader, Method, Request, Response, StatusCode, StreamingBody,
    Version, body, conn, convert, fingerprint, header, headers, io, layer, matcher, mime,
    opentelemetry, proto, protocols, request, response, service, sse, utils,
};

/// HTTP proxy types, request utilities, and MITM support.
pub mod proxy {
    #[doc(inline)]
    pub use ::rama_http::proxy::*;

    #[cfg(feature = "http-full")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
    #[doc(inline)]
    pub use ::rama_http_backend::proxy::*;
}

#[cfg(feature = "http-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-backend")))]
#[doc(inline)]
pub use ::rama_http_core as core;

// `EasyHttpWebClient` and its connector builder additionally need `dns` + `tcp`
// on top of `http-backend` (default dns/transport connectors, proxy tunneling, ...).
#[cfg(all(feature = "http-backend", feature = "dns", feature = "tcp"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "http-backend", feature = "dns", feature = "tcp")))
)]
pub mod client;

#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
#[doc(inline)]
pub use ::rama_http_backend::server;

#[cfg(feature = "ws")]
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
#[doc(inline)]
pub use ::rama_ws as ws;

// `CertIssuerHttpClient` builds on `EasyHttpWebClient`, hence the same gates as `http::client`.
#[cfg(all(
    feature = "tls",
    feature = "http-backend",
    feature = "dns",
    feature = "tcp"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "tls",
        feature = "http-backend",
        feature = "dns",
        feature = "tcp"
    )))
)]
pub mod tls;

#[cfg(feature = "grpc")]
#[cfg_attr(docsrs, doc(cfg(feature = "grpc")))]
#[doc(inline)]
pub use ::rama_grpc as grpc;
