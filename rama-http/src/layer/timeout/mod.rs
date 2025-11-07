//! Middleware that applies a timeout to requests.
//!
//! If the request does not complete within the specified timeout, it will be aborted and a
//! response with an empty body and a custom status code will be returned.
//!
//! # Differences from `rama_core::service::layer::Timeout`
//!
//! The generic [`Timeout`] middleware uses an error to signal timeout, i.e.
//! it changes the error type to [`BoxError`](rama_core::error::BoxError). For HTTP services that is rarely
//! what you want as returning errors will terminate the connection without sending a response.
//!
//! This middleware won't change the error type and instead returns a response with an empty body
//! and the specified status code. That means if your service's error type is [`Infallible`], it will
//! still be [`Infallible`] after applying this middleware.
//!
//! # Example
//!
//! ```
//! use std::{convert::Infallible, time::Duration};
//!
//! use rama_core::Layer;
//! use rama_core::service::service_fn;
//! use rama_http::{Body, Request, Response, StatusCode};
//! use rama_http::layer::timeout::TimeoutLayer;
//! use rama_core::error::BoxError;
//!
//! async fn handle(_: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let svc = (
//!     // Timeout requests after 30 seconds with the specified status code
//!     TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)),
//! ).into_layer(service_fn(handle));
//! # Ok(())
//! # }
//! ```
//!
//! [`Infallible`]: std::convert::Infallible

mod body;
mod service;

pub use body::{TimeoutBody, TimeoutError};
pub use service::{
    RequestBodyTimeout, RequestBodyTimeoutLayer, ResponseBodyTimeout, ResponseBodyTimeoutLayer,
    Timeout, TimeoutLayer,
};
