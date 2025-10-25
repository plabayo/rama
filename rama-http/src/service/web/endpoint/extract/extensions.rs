use super::FromRequestContextRefPair;
use crate::request::Parts;
use rama_core::extensions::Extensions;
use std::convert::Infallible;

impl<State> FromRequestContextRefPair<State> for Extensions
where
    State: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.clone())
    }
}
