//! Extract utilities to develop endpoint services efortless.

use crate::http::{self, dep::http::request::Parts, IntoResponse};
use crate::service::Context;
use std::future::Future;

mod extension;
#[doc(inline)]
pub use extension::Extension;

mod host;
#[doc(inline)]
pub use host::Host;

mod path;
#[doc(inline)]
pub use path::Path;

mod query;
#[doc(inline)]
pub use query::Query;

mod context;
mod method;
mod request;

mod state;
#[doc(inline)]
pub use state::State;

mod typed_header;
#[doc(inline)]
pub use typed_header::TypedHeader;

mod body;
pub use body::{Body, Bytes, Json, Text};

mod private {
    #[derive(Debug, Clone, Copy)]
    pub enum ViaParts {}

    #[derive(Debug, Clone, Copy)]
    pub enum ViaRequest {}
}

/// Types that can be created from request parts.
///
/// Extractors that implement `FromRequestParts` cannot consume the request body and can thus be
/// run in any order for handlers.
///
/// If your extractor needs to consume the request body then you should implement [`FromRequest`]
/// and not [`FromRequestParts`].
pub trait FromRequestParts<S>: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request_parts(
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
pub trait FromRequest<S, M = private::ViaRequest>: Sized + Send + Sync + 'static {
    /// If the extractor fails it'll use this "rejection" type. A rejection is
    /// a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request(
        ctx: Context<S>,
        req: http::Request,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

impl<S, T> FromRequest<S, private::ViaParts> for T
where
    S: Send + Sync + 'static,
    T: FromRequestParts<S>,
{
    type Rejection = <Self as FromRequestParts<S>>::Rejection;

    async fn from_request(ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        let (parts, _) = req.into_parts();
        Self::from_request_parts(&ctx, &parts).await
    }
}
