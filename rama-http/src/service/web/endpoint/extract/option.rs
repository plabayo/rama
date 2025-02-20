use std::future::Future;

use rama_core::Context;

use crate::response::IntoResponse;
use crate::{Request, dep::http::request::Parts};

use super::{FromRequest, FromRequestContextRefPair};

/// Customize the behavior of `Option<Self>` as a [`FromRequestContextRefPair`]
/// extractor.
pub trait OptionalFromRequestContextRefPair<S>: Sized + Send + Sync + 'static {
    /// If the extractor fails, it will use this "rejection" type.
    ///
    /// A rejection is a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request_context_ref_pair(
        ctx: &Context<S>,
        parts: &Parts,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send;
}

/// Customize the behavior of `Option<Self>` as a [`FromRequest`] extractor.
pub trait OptionalFromRequest: Sized + Send + Sync + 'static {
    /// If the extractor fails, it will use this "rejection" type.
    ///
    /// A rejection is a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request(
        req: Request,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send;
}

impl<S, T> FromRequestContextRefPair<S> for Option<T>
where
    T: OptionalFromRequestContextRefPair<S>,
    S: Send + Sync,
{
    type Rejection = T::Rejection;

    fn from_request_context_ref_pair(
        ctx: &Context<S>,
        parts: &Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        T::from_request_context_ref_pair(ctx, parts)
    }
}

impl<T> FromRequest for Option<T>
where
    T: OptionalFromRequest,
{
    type Rejection = T::Rejection;

    async fn from_request(req: Request) -> Result<Option<T>, Self::Rejection> {
        T::from_request(req).await
    }
}
