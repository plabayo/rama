//! Types and traits for generating responses.
//!
//! See [`crate::response`] for more details.

use crate::Response;

mod append_headers;
mod headers;
mod into_response;
mod into_response_parts;

#[doc(inline)]
pub use self::{
    append_headers::AppendHeaders,
    headers::Headers,
    into_response::{IntoResponse, StaticResponseFactory},
    into_response_parts::{IntoResponseParts, ResponseParts, TryIntoHeaderError},
};

mod html;
#[doc(inline)]
pub use html::Html;

mod script;
#[doc(inline)]
pub use script::Script;

mod datastar;
#[doc(inline)]
pub use datastar::DatastarScript;

mod css;
#[doc(inline)]
pub use css::Css;

mod json;
#[doc(inline)]
pub use json::Json;

mod csv;
#[doc(inline)]
pub use csv::Csv;

mod form;
#[doc(inline)]
pub use form::Form;

mod octet_stream;
#[doc(inline)]
pub use octet_stream::OctetStream;

pub mod redirect;
#[doc(inline)]
pub use redirect::Redirect;

pub mod sse;
pub use sse::Sse;

/// An [`IntoResponse`]-based result type that uses [`ErrorResponse`] as the error type.
///
/// All types which implement [`IntoResponse`] can be converted to an [`ErrorResponse`]. This makes
/// it useful as a general purpose error type for functions which combine multiple distinct error
/// types that all implement [`IntoResponse`].
///
/// # Example
///
/// ```
/// use rama_http_types::{StatusCode, Response};
/// use rama_http::service::web::response::IntoResponse;
///
/// // two fallible functions with different error types
/// fn try_something() -> Result<(), ErrorA> {
///     // ...
///     # unimplemented!()
/// }
///
/// fn try_something_else() -> Result<(), ErrorB> {
///     // ...
///     # unimplemented!()
/// }
///
/// // each error type implements `IntoResponse`
/// struct ErrorA;
///
/// impl IntoResponse for ErrorA {
///     fn into_response(self) -> Response {
///         // ...
///         # unimplemented!()
///     }
/// }
///
/// enum ErrorB {
///     SomethingWentWrong,
/// }
///
/// impl IntoResponse for ErrorB {
///     fn into_response(self) -> Response {
///         // ...
///         # unimplemented!()
///     }
/// }
///
/// // we can combine them using `rama_http::response::Result` and still use `?`
/// async fn handler() -> rama_http::service::web::response::Result<&'static str> {
///     // the errors are automatically converted to `ErrorResponse`
///     try_something()?;
///     try_something_else()?;
///
///     Ok("it worked!")
/// }
/// ```
///
/// # As a replacement for `std::result::Result`
///
/// Since `rama_http::response::Result` has a default error type you only have to specify the `Ok` type:
///
/// ```
/// use rama_http_types::{Response, StatusCode};
/// use rama_http::service::web::response::{IntoResponse, Result};
///
/// // `Result<T>` automatically uses `ErrorResponse` as the error type.
/// async fn handler() -> Result<&'static str> {
///     try_something()?;
///
///     Ok("it worked!")
/// }
///
/// // You can still specify the error even if you've imported `rama_http::response::Result`
/// fn try_something() -> Result<(), StatusCode> {
///     // ...
///     # unimplemented!()
/// }
/// ```
pub type Result<T, E = ErrorResponse> = std::result::Result<T, E>;

impl<T> IntoResponse for Result<T>
where
    T: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Ok(ok) => ok.into_response(),
            Err(err) => err.0,
        }
    }
}

/// An [`IntoResponse`]-based error type
///
/// See [`Result`] for more details.
#[derive(Debug)]
pub struct ErrorResponse(Response);

impl<T> From<T> for ErrorResponse
where
    T: IntoResponse,
{
    fn from(value: T) -> Self {
        Self(value.into_response())
    }
}
