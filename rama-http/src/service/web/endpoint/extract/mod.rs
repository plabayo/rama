//! Extract utilities to develop endpoint services efortless.

use super::IntoResponse;
use crate::{HeaderMap, dep::http::request::Parts, dep::mime, header};
use rama_core::Context;

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

mod method;
mod request;

pub mod typed_header;
#[doc(inline)]
pub use typed_header::TypedHeader;

pub mod body;
#[doc(inline)]
pub use body::{Body, Bytes, Csv, Form, Json, Text};

mod option;
#[doc(inline)]
pub use option::{OptionalFromRequest, OptionalFromRequestContextRefPair};

/// Types that can be created from request parts.
///
/// Extractors that implement `FromRequestParts` cannot consume the request body and can thus be
/// run in any order for handlers.
///
/// If your extractor needs to consume the request body then you should implement [`FromRequest`]
/// and not [`FromRequestParts`].
pub trait FromRequestContextRefPair<S>: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request_context_ref_pair(
        ctx: &Context<S>,
        parts: &Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// Types that can be created from requests.
///
/// Extractors that implement `FromRequest` can consume the request body and can thus only be run
/// once for handlers.
///
/// If your extractor doesn't need to consume the request body then you should implement
/// [`FromRequestParts`] and not [`FromRequest`].
pub trait FromRequest: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request(
        req: crate::Request,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

fn has_any_content_type(headers: &HeaderMap, expected_content_types: &[&mime::Mime]) -> bool {
    let content_type = if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        content_type
    } else {
        return false;
    };

    let content_type = if let Ok(content_type) = content_type.to_str() {
        content_type
    } else {
        return false;
    };

    expected_content_types
        .iter()
        .any(|ct| content_type.starts_with(ct.as_ref()))
}
