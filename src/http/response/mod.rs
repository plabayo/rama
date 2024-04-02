//! Types and traits for generating responses.
//!
//! See [`crate::http::response`] for more details.

use crate::http::Body;

mod append_headers;
mod into_response;
mod into_response_parts;

#[doc(inline)]
pub use self::{
    append_headers::AppendHeaders,
    into_response::IntoResponse,
    into_response_parts::{IntoResponseParts, ResponseParts, TryIntoHeaderError},
};

mod html;
#[doc(inline)]
pub use html::Html;

mod json;
#[doc(inline)]
pub use json::Json;

mod form;
#[doc(inline)]
pub use form::Form;

mod redirect;
#[doc(inline)]
pub use redirect::Redirect;

/// Type alias for [`http::Response`] whose body type defaults to [`Body`], the most common body
/// type used with rama.
pub type Response<T = Body> = http::Response<T>;

/// An [`IntoResponse`]-based result type that uses [`ErrorResponse`] as the error type.
///
/// All types which implement [`IntoResponse`] can be converted to an [`ErrorResponse`]. This makes
/// it useful as a general purpose error type for functions which combine multiple distinct error
/// types that all implement [`IntoResponse`].
///
/// # Example
///
/// ```
/// use rama::{
///     http::response::{IntoResponse, Response},
///     http::StatusCode,
/// };
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
/// // we can combine them using `rama::http::response::Result` and still use `?`
/// async fn handler() -> rama::http::response::Result<&'static str> {
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
/// Since `rama::http::response::Result` has a default error type you only have to specify the `Ok` type:
///
/// ```
/// use rama::{
///     http::response::{IntoResponse, Response, Result},
///     http::StatusCode,
/// };
///
/// // `Result<T>` automatically uses `ErrorResponse` as the error type.
/// async fn handler() -> Result<&'static str> {
///     try_something()?;
///
///     Ok("it worked!")
/// }
///
/// // You can still specify the error even if you've imported `rama::http::response::Result`
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
