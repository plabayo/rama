use super::FromRequestContextRefPair;
use crate::{Method, request::Parts};
use std::convert::Infallible;

impl<State> FromRequestContextRefPair<State> for Method
where
    State: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}
