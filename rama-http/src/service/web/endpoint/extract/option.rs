use crate::service::web::endpoint::IntoResponse;
use crate::{Request, request::Parts};

use super::{FromPartsStateRefPair, FromRequest, FromRequestBody};

/// Customize the behavior of `Option<Self>` as a [`FromPartsStateRefPair`]
/// extractor.
pub trait OptionalFromPartsStateRefPair<State>: Sized + Send + Sync + 'static {
    /// If the extractor fails, it will use this "rejection" type.
    ///
    /// A rejection is a kind of error that can be converted into a response.
    type Rejection: IntoResponse;

    /// Perform the extraction.
    fn from_parts_state_ref_pair(
        parts: &Parts,
        state: &State,
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

/// Customize the behavior of `Option<Self>` as a [`FromRequestBody`] extractor.
pub trait OptionalFromRequestBody: OptionalFromRequest {
    /// Perform extraction using borrowed request parts and an owned request body.
    fn from_optional_request_body(
        parts: &Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send + 'static;
}

impl<T, State> FromPartsStateRefPair<State> for Option<T>
where
    T: OptionalFromPartsStateRefPair<State>,
{
    type Rejection = T::Rejection;

    fn from_parts_state_ref_pair(
        parts: &Parts,
        state: &State,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        T::from_parts_state_ref_pair(parts, state)
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

impl<T> FromRequestBody for Option<T>
where
    T: OptionalFromRequestBody,
{
    fn from_request_body(
        parts: &Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        T::from_optional_request_body(parts, body)
    }
}
