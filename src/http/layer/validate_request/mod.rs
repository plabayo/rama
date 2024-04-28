//! Middleware that validates requests.
//!
//! # Example
//!
//! ```
//! use rama::http::layer::validate_request::ValidateRequestHeaderLayer;
//! use rama::http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = ServiceBuilder::new()
//!     // Require the `Accept` header to be `application/json`, `*/*` or `application/*`
//!     .layer(ValidateRequestHeaderLayer::accept("application/json"))
//!     .service_fn(handle);
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
//! use rama::http::layer::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};
//! use rama::http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! #[derive(Clone, Copy)]
//! pub struct MyHeader { /* ...  */ }
//!
//! impl<S, B> ValidateRequest<S, B> for MyHeader
//!     where
//!         S: Send + Sync + 'static,
//!         B: Send + 'static,
//! {
//!     type ResponseBody = Body;
//!
//!     async fn validate(
//!         &self,
//!         ctx: Context<S>,
//!         req: Request<B>,
//!     ) -> Result<(Context<S>, Request<B>), Response<Self::ResponseBody>> {
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
//! let service = ServiceBuilder::new()
//!     // Validate requests using `MyHeader`
//!     .layer(ValidateRequestHeaderLayer::custom(MyHeader { /* ... */ }))
//!     .service_fn(handle);
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
//! use bytes::Bytes;
//! use rama::http::{Body, Request, Response, StatusCode, header::ACCEPT};
//! use rama::http::layer::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     # Ok(Response::builder().body(Body::empty()).unwrap())
//!     // ...
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let service = ServiceBuilder::new()
//!     .layer(ValidateRequestHeaderLayer::custom_fn(|request: Request| async move {
//!         // Validate the request
//!         # Ok::<_, Response>(request)
//!     }))
//!     .service_fn(handle);
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
