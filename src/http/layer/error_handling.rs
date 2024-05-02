//! Middleware to turn [`Service`] errors into [`Response`]s.
//!
//! # Example
//!
//! ```
//! use rama::{
//!     http::{
//!         client::HttpClientExt,
//!         layer::{error_handling::ErrorHandlerLayer, timeout::TimeoutLayer},
//!         service::web::WebService,
//!         Body, IntoResponse, Request, Response, StatusCode,
//!     },
//!     service::{Context, Service, ServiceBuilder},
//! };
//! use std::time::Duration;
//!
//! # async fn some_expensive_io_operation() -> Result<(), std::io::Error> {
//! #     Ok(())
//! # }
//!
//! async fn handler<S>(_ctx: Context<S>, _req: Request) -> Result<Response, std::io::Error> {
//!     some_expensive_io_operation().await?;
//!     Ok(StatusCode::OK.into_response())
//! }
//!
//! # #[tokio::main]
//! # async fn main() {
//!     let home_handler = ServiceBuilder::new()
//!         .layer(ErrorHandlerLayer::new().error_mapper(|err| {
//!             tracing::error!("Error: {:?}", err);
//!             StatusCode::INTERNAL_SERVER_ERROR.into_response()
//!         }))
//!         .layer(TimeoutLayer::new(Duration::from_secs(5)))
//!         .service_fn(handler);
//!
//!     let service = WebService::default().get("/", home_handler);
//!
//!     let _ = service.serve(Context::default(), Request::builder()
//!         .method("GET")
//!         .uri("/")
//!         .body(Body::empty())
//!         .unwrap()).await;
//! # }
//! ```

use crate::{
    http::{IntoResponse, Request, Response},
    service::{Context, Layer, Service},
};
use std::{convert::Infallible, fmt};

/// A [`Layer`] that wraps a [`Service`] and converts errors into [`Response`]s.
pub struct ErrorHandlerLayer<F = ()> {
    error_mapper: F,
}

impl Default for ErrorHandlerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: fmt::Debug> fmt::Debug for ErrorHandlerLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ErrorHandlerLayer")
            .field("error_mapper", &self.error_mapper)
            .finish()
    }
}

impl<F: Clone> Clone for ErrorHandlerLayer<F> {
    fn clone(&self) -> Self {
        Self {
            error_mapper: self.error_mapper.clone(),
        }
    }
}

impl ErrorHandlerLayer {
    /// Create a new [`ErrorHandlerLayer`].
    pub fn new() -> Self {
        Self { error_mapper: () }
    }

    /// Set the error mapper function (not set by default).
    ///
    /// The error mapper function is called with the error,
    /// and should return an [`IntoResponse`] implementation.
    pub fn error_mapper<F>(self, error_mapper: F) -> ErrorHandlerLayer<F> {
        ErrorHandlerLayer { error_mapper }
    }
}

impl<S, F: Clone> Layer<S> for ErrorHandlerLayer<F> {
    type Service = ErrorHandler<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorHandler::new(inner).error_mapper(self.error_mapper.clone())
    }
}

/// A [`Service`] adapter that handles errors by converting them into [`Response`]s.
pub struct ErrorHandler<S, F = ()> {
    inner: S,
    error_mapper: F,
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for ErrorHandler<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ErrorHandler")
            .field("inner", &self.inner)
            .field("error_mapper", &self.error_mapper)
            .finish()
    }
}

impl<S: Clone, F: Clone> Clone for ErrorHandler<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            error_mapper: self.error_mapper.clone(),
        }
    }
}

impl<S> ErrorHandler<S> {
    /// Create a new [`ErrorHandler`] wrapping the given service.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            error_mapper: (),
        }
    }

    /// Set the error mapper function (not set by default).
    ///
    /// The error mapper function is called with the error,
    /// and should return an [`IntoResponse`] implementation.
    pub fn error_mapper<F>(self, error_mapper: F) -> ErrorHandler<S, F> {
        ErrorHandler {
            inner: self.inner,
            error_mapper,
        }
    }
}

impl<S, State, Body> Service<State, Request<Body>> for ErrorHandler<S, ()>
where
    S: Service<State, Request<Body>>,
    S::Response: IntoResponse,
    S::Error: IntoResponse,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok(error.into_response()),
        }
    }
}

impl<S, F, R, State, Body> Service<State, Request<Body>> for ErrorHandler<S, F>
where
    S: Service<State, Request<Body>>,
    S::Response: IntoResponse,
    F: Fn(S::Error) -> R + Clone + Send + Sync + 'static,
    R: IntoResponse + 'static,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(ctx, req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok((self.error_mapper)(error).into_response()),
        }
    }
}
