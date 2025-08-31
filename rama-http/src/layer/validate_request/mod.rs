//! Middleware that validates requests.
//!
//! # Example
//!
//! ```
//! use rama_http::layer::validate_request::ValidateRequestHeaderLayer;
//! use rama_http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = (
//!     // Require the `Accept` header to be `application/json`, `*/*` or `application/*`
//!     ValidateRequestHeaderLayer::accept("application/json"),
//! ).into_layer(service_fn(handle));
//!
//! // Requests with the correct value are allowed through
//! let request = Request::builder()
//!     .header(ACCEPT, "application/json")
//!     .body(Body::empty())
//!     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(StatusCode::OK, response.status());
//!
//! // Requests with an invalid value get a `406 Not Acceptable` response
//! let request = Request::builder()
//!     .header(ACCEPT, "text/strings")
//!     .body(Body::empty())
//!     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(StatusCode::NOT_ACCEPTABLE, response.status());
//! # Ok(())
//! # }
//! ```
//!
//! Custom validation can be made by implementing [`ValidateRequest`]:
//!
//! ```
//! use rama_http::layer::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};
//! use rama_http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! #[derive(Clone, Copy)]
//! pub struct MyHeader { /* ...  */ }
//!
//! impl<B> ValidateRequest<B> for MyHeader
//!     where
//!         B: Send + 'static,
//! {
//!     type ResponseBody = Body;
//!
//!     async fn validate(
//!         &self,
//!         ctx: Context,
//!         req: Request<B>,
//!     ) -> Result<(Context, Request<B>), Response<Self::ResponseBody>> {
//!         // validate the request...
//!         # Ok::<_, Response>((ctx, req))
//!     }
//! }
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     # Ok(Response::builder().body(Body::empty()).unwrap())
//!     // ...
//! }
//!
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let service = (
//!     // Validate requests using `MyHeader`
//!     ValidateRequestHeaderLayer::custom(MyHeader { /* ... */ }),
//! ).into_layer(service_fn(handle));
//!
//! # let request = Request::builder()
//! #     .body(Body::empty())
//! #     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! Or using a closure:
//!
//! ```
//! use rama_core::bytes::Bytes;
//! use rama_http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama_http::layer::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     # Ok(Response::builder().body(Body::empty()).unwrap())
//!     // ...
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let service = (
//!     ValidateRequestHeaderLayer::custom_fn(async |request: Request| {
//!         // Validate the request
//!         # Ok::<_, Response>(request)
//!     }),
//! ).into_layer(service_fn(handle));
//!
//! # let request = Request::builder()
//! #     .body(Body::empty())
//! #     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```

mod accept_header;
mod validate;
mod validate_fn;
mod validate_request_header;

#[doc(inline)]
pub use accept_header::AcceptHeader;
#[doc(inline)]
pub use validate::ValidateRequest;
#[doc(inline)]
pub use validate_fn::{BoxValidateRequestFn, ValidateRequestFn};
#[doc(inline)]
pub use validate_request_header::{ValidateRequestHeader, ValidateRequestHeaderLayer};
