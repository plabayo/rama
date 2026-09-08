//! Types and traits for generating responses.
//!
//! See [`crate::response`] for more details.

use std::convert::Infallible;

use rama_core::extensions::Extension;

use crate::{Response, StatusCode};

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

/// Marks a response produced because converting a response value failed.
///
/// Tuple response implementations use this marker to avoid replacing an inner
/// error status with an outer status code. Custom fallible response types can
/// add it as a response part for the same behavior.
#[derive(Copy, Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct IntoResponseFailed;

impl IntoResponseParts for IntoResponseFailed {
    type Error = Infallible;

    fn into_response_parts(self, res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.extensions().insert(self);
        Ok(res)
    }
}

/// Forces an outer status code even if converting the inner response failed.
#[derive(Debug, Copy, Clone, Default)]
#[must_use = "a forced status code has no effect unless returned or converted into a response"]
pub struct ForceStatusCode(pub StatusCode);

impl IntoResponse for ForceStatusCode {
    fn into_response(self) -> Response {
        let mut res = ().into_response();
        *res.status_mut() = self.0;
        res
    }
}

impl<R> IntoResponse for (ForceStatusCode, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let (ForceStatusCode(status), res) = self;
        let mut res = res.into_response();
        *res.status_mut() = status;
        res
    }
}

mod html;
#[doc(inline)]
pub use html::Html;

mod script;
#[doc(inline)]
pub use script::Script;

mod datastar;
#[doc(inline)]
pub use datastar::{DatastarScript, DatastarSourceMap};

mod svg;
#[doc(inline)]
pub use svg::Svg;

mod css;
#[doc(inline)]
pub use css::Css;

mod json;
#[doc(inline)]
pub use json::Json;

#[doc(inline)]
pub use crate::protocols::json_ld::JsonLd;

mod csv;
mod json_lines;
#[doc(inline)]
pub use csv::Csv;

mod form;
#[doc(inline)]
pub use form::Form;

pub mod robots_txt;

mod octet_stream;
#[doc(inline)]
pub use octet_stream::OctetStream;

pub mod redirect;
#[doc(inline)]
pub use redirect::Redirect;

pub mod sse;
pub use sse::Sse;

#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
pub mod partial_updates;
#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
pub use partial_updates::PartialUpdates;

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

/// An [`IntoResponse`]-based error type
///
/// See [`Result`] for more details.
#[derive(Debug)]
#[must_use]
pub struct ErrorResponse(Response);

impl<T> From<T> for ErrorResponse
where
    T: IntoResponse,
{
    fn from(value: T) -> Self {
        Self(value.into_response())
    }
}

impl ErrorResponse {
    #[must_use]
    pub fn into_response(self) -> Response {
        self.0
    }
}
