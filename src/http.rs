//! rama http support
//!
//! mostly contains re-exports from
//! `rama-http` and `rama-http-backend`.

pub use ::rama_http::{
    header,
    response::{self, IntoResponse, Response},
    Body, BodyDataStream, BodyExtractExt, BodyLimit, HeaderMap, HeaderName, HeaderValue, Method,
    Request, Scheme, StatusCode, Uri, Version,
    headers, matcher, service, io, dep, RequestContext,
};

pub mod layer {
    //! Http [`Layer`]s provided by Rama.
    //!
    //! mostly contains re-exports from
    //! `rama-http` and `rama-http-backend`.

    pub use ::rama_http::layer::*;
    pub use ::rama_http_backend::layer::*;
}

pub use ::rama_http_backend::{
    server, client,
};
