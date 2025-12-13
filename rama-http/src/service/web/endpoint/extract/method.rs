use super::FromPartsStateRefPair;
use crate::{Method, request::Parts};
use std::convert::Infallible;

impl<State> FromPartsStateRefPair<State> for Method
where
    State: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}
