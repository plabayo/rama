pub use tower_async_http::BoxError;

pub use tower_async_http::LatencyUnit;

pub use tower_async_http::ServiceBuilderExt;

pub mod auth {
    //! Authorization related middleware.

    pub use tower_async_http::auth::{
        AddAuthorization, AddAuthorizationLayer, AsyncAuthorizeRequest, AsyncRequireAuthorization,
        AsyncRequireAuthorizationLayer,
    };
}

pub mod set_header {
    //! Middleware for setting headers on requests and responses.

    pub use tower_async_http::set_header::{
        MakeHeaderValue, SetRequestHeader, SetRequestHeaderLayer, SetResponseHeader,
        SetResponseHeaderLayer,
    };
}

pub mod propagate_header {
    //! Propagate a header from the request to the response.

    pub use tower_async_http::propagate_header::{PropagateHeader, PropagateHeaderLayer};
}

pub mod compression {
    //! Middleware that compresses response bodies.

    pub mod predicate {
        //! Predicates for disabling compression of responses.

        pub use tower_async_http::compression::predicate::{
            And, DefaultPredicate, NotForContentType, Predicate, SizeAbove,
        };
    }
    pub use tower_async_http::compression::{
        Compression, CompressionBody, CompressionLayer, DefaultPredicate, Predicate,
    };
    pub use tower_async_http::CompressionLevel;
}

pub mod add_extension {
    //! Middleware that clones a value into each request's [extensions].
    //!
    //! [extensions]: https://docs.rs/http/latest/http/struct.Extensions.html

    pub use tower_async_http::add_extension::{AddExtension, AddExtensionLayer};
}

pub mod sensitive_headers {
    //! Middlewares that mark headers as [sensitive].
    //!
    //! [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive

    pub use tower_async_http::sensitive_headers::{
        SetSensitiveHeadersLayer, SetSensitiveRequestHeaders, SetSensitiveRequestHeadersLayer,
        SetSensitiveResponseHeaders, SetSensitiveResponseHeadersLayer,
    };
}

pub mod decompression {
    //! Middleware that decompresses request and response bodies.

    pub use tower_async_http::decompression::{
        Decompression, DecompressionBody, DecompressionLayer, RequestDecompression,
        RequestDecompressionLayer,
    };
}

pub use tower_async_http::CompressionLevel;

pub mod map_response_body {
    //! Apply a transformation to the response body.

    pub use tower_async_http::map_response_body::{MapResponseBody, MapResponseBodyLayer};
}

pub mod map_request_body {
    //! Apply a transformation to the request body.

    pub use tower_async_http::map_request_body::{MapRequestBody, MapRequestBodyLayer};
}

pub mod trace {
    //! Middleware that adds high level [tracing] to a [`Service`].
    //!
    //! [tracing]: https://crates.io/crates/tracing
    //! [`Service`]: crate::service::Service
    pub use tower_async_http::trace::{
        DefaultMakeSpan, DefaultOnBodyChunk, DefaultOnEos, DefaultOnFailure, DefaultOnRequest,
        DefaultOnResponse, MakeSpan, OnBodyChunk, OnEos, OnFailure, OnRequest, OnResponse,
        ResponseBody, Trace, TraceLayer,
    };
}

pub mod follow_redirect {
    //! Middleware for following redirections.

    pub use tower_async_http::follow_redirect::{FollowRedirect, FollowRedirectLayer, RequestUri};

    pub mod policy {
        //! Tools for customizing the behavior of a [`FollowRedirect`][super::FollowRedirect] middleware.

        pub use tower_async_http::follow_redirect::policy::{
            clone_body_fn, redirect_fn, Action, And, Attempt, CloneBodyFn, FilterCredentials,
            Limited, Or, Policy, PolicyExt, RedirectFn, SameOrigin, Standard,
        };
    }
}

pub mod limit {
    //! Middleware for limiting request bodies.
    //!
    //! This layer will also intercept requests with a `Content-Length` header
    //! larger than the allowable limit and return an immediate error response
    //! before reading any of the body.
    //!
    //! Note that payload length errors can be used by adversaries in an attempt
    //! to smuggle requests. When an incoming stream is dropped due to an
    //! over-sized payload, servers should close the connection or resynchronize
    //! by optimistically consuming some data in an attempt to reach the end of
    //! the current HTTP frame. If the incoming stream cannot be resynchronized,
    //! then the connection should be closed. If you're using [hyper] this is
    //! automatically handled for you.

    pub use tower_async_http::limit::{RequestBodyLimit, RequestBodyLimitLayer, ResponseBody};
}

pub mod cors {
    //! Middleware which adds headers for [CORS][mdn].
    //!
    //! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

    pub use tower_async_http::cors::{
        preflight_request_headers, AllowCredentials, AllowHeaders, AllowMethods, AllowOrigin,
        AllowPrivateNetwork, Any, Cors, CorsLayer, ExposeHeaders, MaxAge, Vary,
    };
}

pub mod request_id {
    //! Set and propagate request ids.

    pub use tower_async_http::request_id::{
        MakeRequestId, MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestId,
        SetRequestIdLayer,
    };
}

pub mod catch_panic {
    //! Convert panics into responses.
    //!
    //! Note that using panics for error handling is _not_ recommended. Prefer instead to use `Result`
    //! whenever possible.

    pub use tower_async_http::catch_panic::{
        CatchPanic, CatchPanicLayer, DefaultResponseForPanic, ResponseForPanic,
    };
}

pub mod set_status {
    //! Middleware to override status codes.

    pub use tower_async_http::set_status::{SetStatus, SetStatusLayer};
}

pub mod timeout {
    //! Middleware that applies a timeout to requests.
    //!
    //! If the request does not complete within the specified timeout it will be aborted and a `408
    //! Request Timeout` response will be sent.
    //!
    //! # Differences from [`crate::service::timeout`]
    //!
    //! [`crate::service::timeout::Timeout`] middleware uses an error to signal timeout, i.e.
    //! it changes the error type to [`crate::service::BoxError`]`. For HTTP services that is rarely
    //! what you want as returning errors will terminate the connection without sending a response.
    //!
    //! This middleware won't change the error type and instead return a `408 Request Timeout`
    //! response. That means if your service's error type is [`Infallible`] it will still be
    //! [`Infallible`] after applying this middleware.
    //!
    //! [`Infallible`]: std::convert::Infallible
    pub use tower_async_http::timeout::{Timeout, TimeoutLayer};
}

pub mod normalize_path {
    //! Middleware that normalizes paths.
    //!
    //! Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
    //! will be changed to `/foo` before reaching the inner service.

    pub use tower_async_http::normalize_path::{NormalizePath, NormalizePathLayer};
}

pub mod classify {
    //! Tools for classifying responses as either success or failure.

    pub use tower_async_http::classify::{
        ClassifiedResponse, ClassifyEos, ClassifyResponse, MakeClassifier, MapFailureClass,
        NeverClassifyEos, ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier,
        StatusInRangeAsFailures, StatusInRangeFailureClass,
    };
}

pub mod services {
    //! [`Service`]s that return responses without wrapping other [`Service`]s.
    //!
    //! These kinds of services are also referred to as "leaf services" since they sit at the leaves of
    //! a [tree] of services.
    //!
    //! [`Service`]: https://docs.rs/tower-async/latest/tower-async/trait.Service.html
    //! [tree]: https://en.wikipedia.org/wiki/Tree_(data_structure)

    pub use tower_async_http::services::Redirect;

    pub mod redirect {
        //! Service that redirects all requests.
        //!
        //! See the [`module docs`] for more details.
        //!
        //! [`module docs`]: https://docs.rs/tower-async-http/latest/tower_async_http/services/index.html
        pub use tower_async_http::services::redirect::Redirect;
    }

    pub use tower_async_http::services::{ServeDir, ServeFile};

    pub mod fs {
        //! File system related services.

        pub use tower_async_http::services::fs::{
            DefaultServeDirFallback, ServeDir, ServeFile, ServeFileSystemResponseBody,
        };
    }
}

pub mod validate_request {
    //! Middleware that validates requests.

    pub use tower_async_http::validate_request::{
        AcceptHeader, ValidateRequest, ValidateRequestHeader, ValidateRequestHeaderLayer,
    };
}
