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

pub mod datastar;

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
#[diagnostic::on_unimplemented(
    note = "Function argument is not a valid web endpoint extractor. \nSee `https://ramaproxy.org/docs/rama/http/service/web/extract/index.html` for details"
)]
pub trait FromRequestContextRefPair: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request_context_ref_pair(
        ctx: &Context,
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
#[diagnostic::on_unimplemented(
    note = "Function argument is not a valid web endpoint extractor. \nSee `https://ramaproxy.org/docs/rama/http/service/web/extract/index.html` for details"
)]
pub trait FromRequest: Sized + Send + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request(
        req: crate::Request,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
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
