//! Convert panics into responses.
//!
//! Note that using panics for error handling is _not_ recommended. Prefer instead to use `Result`
//! whenever possible.
//!
//! # Example
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use rama_http::{Request, Response, Body, header::HeaderName};
//! use rama_http::layer::catch_panic::CatchPanicLayer;
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     panic!("something went wrong...")
//! }
//!
//! let mut svc = (
//!     // Catch panics and convert them into responses.
//!     CatchPanicLayer::new(),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let request = Request::new(Body::default());
//!
//! let response = svc.serve(request).await?;
//!
//! assert_eq!(response.status(), 500);
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Using a custom panic handler:
//!
//! ```rust
//! use std::{any::Any, convert::Infallible};
//!
//! use rama_http::{Body, Request, StatusCode, Response, header::{self, HeaderName}};
//! use rama_http::layer::catch_panic::CatchPanicLayer;
//! use rama_core::service::{Service, service_fn};
//! use rama_core::Layer;
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     panic!("something went wrong...")
//! }
//!
//! fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response {
//!     let details = if let Some(s) = err.downcast_ref::<String>() {
//!         s.clone()
//!     } else if let Some(s) = err.downcast_ref::<&str>() {
//!         s.to_string()
//!     } else {
//!         "Unknown panic message".to_string()
//!     };
//!
//!     let body = serde_json::json!({
//!         "error": {
//!             "kind": "panic",
//!             "details": details,
//!         }
//!     });
//!     let body = serde_json::to_string(&body).unwrap();
//!
//!     Response::builder()
//!         .status(StatusCode::INTERNAL_SERVER_ERROR)
//!         .header(header::CONTENT_TYPE, "application/json")
//!         .body(Body::from(body))
//!         .unwrap()
//! }
//!
//! let svc = (
//!     // Use `handle_panic` to create the response.
//!     CatchPanicLayer::custom(handle_panic),
//! ).into_layer(service_fn(handle));
//! #
//! # Ok(())
//! # }
//! ```

use crate::{Body, HeaderValue, Request, Response, StatusCode};
use rama_core::futures::FutureExt;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::{any::Any, panic::AssertUnwindSafe};

/// Layer that applies the [`CatchPanic`] middleware that catches panics and converts them into
/// `500 Internal Server` responses.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone)]
pub struct CatchPanicLayer<T> {
    panic_handler: T,
}

impl Default for CatchPanicLayer<DefaultResponseForPanic> {
    fn default() -> Self {
        Self::new()
    }
}

impl CatchPanicLayer<DefaultResponseForPanic> {
    /// Create a new `CatchPanicLayer` with the [`Default`]] panic handler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            panic_handler: DefaultResponseForPanic,
        }
    }
}

impl<T> CatchPanicLayer<T> {
    /// Create a new `CatchPanicLayer` with a custom panic handler.
    pub fn custom(panic_handler: T) -> Self
    where
        T: ResponseForPanic,
    {
        Self { panic_handler }
    }
}

impl<T, S> Layer<S> for CatchPanicLayer<T>
where
    T: Clone,
{
    type Service = CatchPanic<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        CatchPanic {
            inner,
            panic_handler: self.panic_handler.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        CatchPanic {
            inner,
            panic_handler: self.panic_handler,
        }
    }
}

/// Middleware that catches panics and converts them into `500 Internal Server` responses.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone)]
pub struct CatchPanic<S, T> {
    inner: S,
    panic_handler: T,
}

impl<S> CatchPanic<S, DefaultResponseForPanic> {
    /// Create a new `CatchPanic` with the default panic handler.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            panic_handler: DefaultResponseForPanic,
        }
    }
}

impl<S, T> CatchPanic<S, T> {
    define_inner_service_accessors!();

    /// Create a new `CatchPanic` with a custom panic handler.
    pub const fn custom(inner: S, panic_handler: T) -> Self
    where
        T: ResponseForPanic,
    {
        Self {
            inner,
            panic_handler,
        }
    }
}

impl<S, T, ReqBody, ResBody> Service<Request<ReqBody>> for CatchPanic<S, T>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ResBody: Into<Body> + Send + 'static,
    T: ResponseForPanic + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let future = match std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.serve(req))) {
            Ok(future) => future,
            Err(panic_err) => return Ok(self.panic_handler.response_for_panic(panic_err)),
        };
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(res) => match res {
                Ok(res) => Ok(res.map(Into::into)),
                Err(err) => Err(err),
            },
            Err(panic_err) => Ok(self.panic_handler.response_for_panic(panic_err)),
        }
    }
}

/// Trait for creating responses from panics.
pub trait ResponseForPanic: Clone {
    /// Create a response from the panic error.
    fn response_for_panic(&self, err: Box<dyn Any + Send + 'static>) -> Response<Body>;
}

impl<F> ResponseForPanic for F
where
    F: Fn(Box<dyn Any + Send + 'static>) -> Response + Clone,
{
    fn response_for_panic(&self, err: Box<dyn Any + Send + 'static>) -> Response {
        self(err)
    }
}

/// The default `ResponseForPanic` used by `CatchPanic`.
///
/// It will log the panic message and return a `500 Internal Server` error response with an empty
/// body.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct DefaultResponseForPanic;

impl ResponseForPanic for DefaultResponseForPanic {
    fn response_for_panic(&self, err: Box<dyn Any + Send + 'static>) -> Response {
        if let Some(s) = err.downcast_ref::<String>() {
            tracing::error!("Service panicked: {}", s);
        } else if let Some(s) = err.downcast_ref::<&str>() {
            tracing::error!("Service panicked: {}", s);
        } else {
            tracing::error!(
                "Service panicked but `CatchPanic` was unable to downcast the panic info"
            );
        };

        let mut res = Response::new(Body::from("Service panicked"));
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

        #[allow(clippy::declare_interior_mutable_const)]
        const TEXT_PLAIN: HeaderValue = HeaderValue::from_static("text/plain; charset=utf-8");
        res.headers_mut()
            .insert(rama_http_types::header::CONTENT_TYPE, TEXT_PLAIN);

        res
    }
}

#[cfg(test)]
mod tests {
    #![allow(unreachable_code)]

    use super::*;

    use crate::{Body, Response, body::util::BodyExt};
    use rama_core::Service;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn panic_before_returning_future() {
        let svc = CatchPanicLayer::new().into_layer(service_fn(|_: Request| {
            panic!("service panic");
            async { Ok::<_, Infallible>(Response::new(Body::empty())) }
        }));

        let req = Request::new(Body::empty());

        let res = svc.serve(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Service panicked");
    }

    #[tokio::test]
    async fn panic_in_future() {
        let svc = CatchPanicLayer::new().into_layer(service_fn(async |_: Request<Body>| {
            panic!("future panic");
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));

        let req = Request::new(Body::empty());

        let res = svc.serve(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Service panicked");
    }
}
