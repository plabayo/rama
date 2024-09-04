//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

pub use ::rama_http::{
    dep, header, headers, io, matcher,
    response::{self, IntoResponse, Response},
    service, Body, BodyDataStream, BodyExtractExt, BodyLimit, HeaderMap, HeaderName, HeaderValue,
    Method, Request, Scheme, StatusCode, Uri, Version,
};

pub mod layer {
    //! Http [`Layer`][crate::Layer]s provided by Rama.
    //!
    //! mostly contains re-exports from
    //! `rama-http` and `rama-http-backend`.

    pub use ::rama_http::layer::*;
    pub use ::rama_http_backend::server::layer::*;
}

pub use ::rama_http_backend::{client, server};
