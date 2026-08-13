//! Extract utilities to develop endpoint services effortlessly.
//!
//! [`HeaderMap`] implements [`FromOwnedRequestParts`], allowing handlers to take ownership of all
//! request headers without cloning them. Owned-parts extractors are placed immediately before a
//! trailing [`FromRequestBody`] extractor.

use super::IntoResponse;
use crate::{HeaderMap, header, mime, request::Parts};

pub mod host;
#[doc(inline)]
pub use host::Host;

pub mod authority;
#[doc(inline)]
pub use authority::Authority;

pub mod path;
#[doc(inline)]
pub use path::Path;

pub mod query;
#[doc(inline)]
pub use query::Query;

mod uri;

mod header_map;
mod method;
mod request;

mod state;
pub use state::State;

mod extensions;

pub mod typed_header;
#[doc(inline)]
pub use typed_header::TypedHeader;

pub mod body;
#[doc(inline)]
pub use body::{Body, Bytes, Csv, Form, Json, OctetStream, Text};

#[cfg(feature = "multipart")]
#[doc(inline)]
pub use body::multipart;
#[cfg(feature = "multipart")]
#[doc(inline)]
pub use body::multipart::Multipart;

pub mod datastar;

mod option;
#[doc(inline)]
pub use option::{OptionalFromPartsStateRefPair, OptionalFromRequest, OptionalFromRequestBody};

/// Types that can be created from request parts.
///
/// Extractors that implement [`FromPartsStateRefPair`] cannot consume the request body and can thus
/// be run in any order for handlers.
///
/// If your extractor needs to consume the request body then you should implement [`FromRequest`]
/// and not [`FromPartsStateRefPair`].
#[diagnostic::on_unimplemented(
    note = "Function argument is not a valid web endpoint extractor. \nSee `https://ramaproxy.org/docs/rama/http/service/web/extract/index.html` for details"
)]
pub trait FromPartsStateRefPair<State>: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection;

    /// Perform the extraction.
    fn from_parts_state_ref_pair(
        parts: &Parts,
        state: &State,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// Types that can be created by consuming the request parts.
///
/// Exactly one owned-parts extractor can be used, either as the final handler argument or
/// immediately before a trailing [`FromRequestBody`] extractor. Implementors automatically
/// implement [`FromRequest`] for the terminal case. Unlike [`FromPartsStateRefPair`], this trait
/// can move fields out of [`Parts`] without cloning them. When followed by a body extractor, the
/// body extractor first prepares an owned future from borrowed parts, the owned-parts extractor
/// runs, and only then is the body future awaited. This preserves argument-order rejection
/// precedence without retaining or cloning the parts.
///
/// `HeaderMap`, [`Parts`], [`Extensions`](rama_core::extensions::Extensions), and
/// [`Uri`](rama_net::uri::Uri) implement this trait.
///
/// # Example
///
/// ```
/// use rama_http::{HeaderMap, StatusCode};
/// use rama_http::service::web::{WebService, extract::Text};
///
/// let _service = WebService::default().with_post(
///     "/",
///     async |_headers: HeaderMap, Text(_payload): Text| StatusCode::OK,
/// );
/// ```
#[diagnostic::on_unimplemented(
    note = "Owned request-parts extractors must be the final argument, or immediately precede a body extractor that implements `FromRequestBody`."
)]
pub trait FromOwnedRequestParts: Sized + Send + 'static {
    /// If the extractor fails it'll use this rejection type.
    type Rejection;

    /// Perform the extraction by consuming the request parts.
    fn from_owned_request_parts(
        parts: Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static;
}

/// Types that own the request body while only borrowing the other request parts.
///
/// This is the body-only counterpart to [`FromRequest`]. It enables an immediately preceding
/// [`FromOwnedRequestParts`] extractor to take ownership of the request parts after the body
/// extractor has finished inspecting them. Types implementing this trait also implement
/// [`FromRequest`] so they remain usable as ordinary terminal extractors.
#[diagnostic::on_unimplemented(
    note = "The final argument after an owned request-parts extractor must implement `FromRequestBody`."
)]
pub trait FromRequestBody: FromRequest {
    /// Prepare extraction using borrowed request parts and an owned request body.
    ///
    /// The returned future cannot borrow `parts`, allowing the request parts to be dropped or
    /// moved before body processing is awaited.
    fn from_request_body(
        parts: &Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static;
}

/// Types that can be created from requests.
///
/// Extractors that implement `FromRequest` can consume the request body and can thus only be run
/// once for handlers.
///
/// If your extractor owns only the request body and merely borrows the request parts, also
/// implement [`FromRequestBody`] to compose with a preceding [`FromOwnedRequestParts`] extractor.
/// If it doesn't need to consume the request body at all, implement [`FromPartsStateRefPair`]
/// instead.
#[diagnostic::on_unimplemented(
    note = "Function argument is not a valid web endpoint extractor. \nSee `https://ramaproxy.org/docs/rama/http/service/web/extract/index.html` for details"
)]
pub trait FromRequest: Sized + Send + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection;

    /// Perform the extraction.
    fn from_request(
        req: crate::Request,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

impl<T> FromRequest for T
where
    T: FromOwnedRequestParts,
{
    type Rejection = T::Rejection;

    async fn from_request(req: crate::Request) -> Result<Self, Self::Rejection> {
        Self::from_owned_request_parts(req.into_parts().0).await
    }
}

fn has_any_content_type(headers: &HeaderMap, expected_content_types: &[&mime::Mime]) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };

    let Ok(content_type) = content_type.to_str() else {
        return false;
    };

    expected_content_types
        .iter()
        .any(|ct| content_type.starts_with(ct.as_ref()))
}
