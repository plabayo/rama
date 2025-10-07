use crate::service::web::endpoint::IntoResponse;
use crate::{Request, request::Parts};

use super::{FromRequest, FromRequestContextRefPair};

/// Customize the behavior of `Option<Self>` as a [`FromRequestContextRefPair`]
/// extractor.
pub trait OptionalFromRequestContextRefPair: Sized + Send + Sync + 'static {
    /// If the extractor fails, it will use this "rejection" type.
    ///
    /// A rejection is a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_request_context_ref_pair(
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

impl<T> FromRequestContextRefPair for Option<T>
where
    T: OptionalFromRequestContextRefPair,
{
    type Rejection = T::Rejection;

    fn from_request_context_ref_pair(
        parts: &Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        T::from_request_context_ref_pair(parts)
    }
}

impl<T> FromRequest for Option<T>
where
    T: OptionalFromRequest,
{
    type Rejection = T::Rejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        T::from_request(req).await
    }
}
