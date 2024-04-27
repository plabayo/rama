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
//! use rama::http::{Request, Response, Body, header::HeaderName};
//! use rama::http::layer::catch_panic::CatchPanicLayer;
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     panic!("something went wrong...")
//! }
//!
//! let mut svc = ServiceBuilder::new()
//!     // Catch panics and convert them into responses.
//!     .layer(CatchPanicLayer::new())
//!     .service_fn(handle);
//!
//! // Call the service.
//! let request = Request::new(Body::default());
//!
//! let response = svc.serve(Context::default(), request).await?;
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
//! use rama::http::{Body, Request, StatusCode, Response, header::{self, HeaderName}};
//! use rama::http::layer::catch_panic::CatchPanicLayer;
//! use rama::service::{Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
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
//! let svc = ServiceBuilder::new()
//!     // Use `handle_panic` to create the response.
//!     .layer(CatchPanicLayer::custom(handle_panic))
//!     .service_fn(handle);
//! #
//! # Ok(())
//! # }
//! ```

use futures_lite::future::FutureExt;
use std::{any::Any, panic::AssertUnwindSafe};

use crate::http::{Body, HeaderValue, Request, Response, StatusCode};
use crate::service::{Context, Layer, Service};

/// Layer that applies the [`CatchPanic`] middleware that catches panics and converts them into
/// `500 Internal Server` responses.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone, Copy, Default)]
pub struct CatchPanicLayer<T> {
    panic_handler: T,
}

impl CatchPanicLayer<DefaultResponseForPanic> {
    /// Create a new `CatchPanicLayer` with the default panic handler.
    pub fn new() -> Self {
        CatchPanicLayer {
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
}

/// Middleware that catches panics and converts them into `500 Internal Server` responses.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone, Copy)]
pub struct CatchPanic<S, T> {
    inner: S,
    panic_handler: T,
}

impl<S> CatchPanic<S, DefaultResponseForPanic> {
    /// Create a new `CatchPanic` with the default panic handler.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            panic_handler: DefaultResponseForPanic,
        }
    }
}

impl<S, T> CatchPanic<S, T> {
    define_inner_service_accessors!();

    /// Create a new `CatchPanic` with a custom panic handler.
    pub fn custom(inner: S, panic_handler: T) -> Self
    where
        T: ResponseForPanic,
    {
        Self {
            inner,
            panic_handler,
        }
    }
}

impl<State, S, T, ReqBody, ResBody> Service<State, Request<ReqBody>> for CatchPanic<S, T>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Into<Body> + Send + 'static,
    T: ResponseForPanic + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let future = match std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.serve(ctx, req)))
        {
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
#[derive(Debug, Default, Clone, Copy)]
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
            .insert(http::header::CONTENT_TYPE, TEXT_PLAIN);

        res
    }
}

#[cfg(test)]
mod tests {
    #![allow(unreachable_code)]

    use super::*;

    use hyper::Response;
    use std::convert::Infallible;

    use crate::http::dep::http_body_util::BodyExt;
    use crate::service::ServiceBuilder;

    #[tokio::test]
    async fn panic_before_returning_future() {
        let svc = ServiceBuilder::new()
            .layer(CatchPanicLayer::new())
            .service_fn(|_: Request| {
                panic!("service panic");
                async { Ok::<_, Infallible>(Response::new(Body::empty())) }
            });

        let req = Request::new(Body::empty());

        let res = svc.serve(Context::default(), req).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Service panicked");
    }

    #[tokio::test]
    async fn panic_in_future() {
        let svc = ServiceBuilder::new()
            .layer(CatchPanicLayer::new())
            .service_fn(|_: Request<Body>| async {
                panic!("future panic");
                Ok::<_, Infallible>(Response::new(Body::empty()))
            });

        let req = Request::new(Body::empty());

        let res = svc.serve(Context::default(), req).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Service panicked");
    }
}
