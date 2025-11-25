use super::FromRequestContextRefPair;
use crate::request::Parts;
use crate::service::web::extract::OptionalFromRequestContextRefPair;
use crate::utils::macros::define_http_rejection;
use rama_utils::macros::impl_deref;
use std::convert::Infallible;

#[derive(Debug, Clone)]
/// Extractor that extracts an extension from the request extensions
pub struct Extension<T>(pub T);

impl_deref!(Extension<T>: T);

define_http_rejection! {
    #[status = INTERNAL_SERVER_ERROR]
    #[body = "Internal server error"]
    /// Rejection type used in case the extension is missing
    pub struct MissingExtension;
}

impl<State, T> FromRequestContextRefPair<State> for Extension<T>
where
    State: Send + Sync,
    T: Send + Sync + Clone + 'static,
{
    type Rejection = MissingExtension;

    async fn from_request_context_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<T>() {
            Some(ext) => Ok(Extension(ext.clone())),
            None => Err(MissingExtension),
        }
    }
}

impl<State, T> OptionalFromRequestContextRefPair<State> for Extension<T>
where
    State: Send + Sync,
    T: Send + Sync + Clone + 'static,
{
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<T>()
            .map(|ext| Extension(ext.clone())))
    }
}
