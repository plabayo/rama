use super::FromRequestContextRefPair;
use crate::{dep::http::request::Parts, Method};
use rama_core::Context;
use std::convert::Infallible;

impl<S> FromRequestContextRefPair<S> for Method
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(
        _ctx: &Context<S>,
        parts: &Parts,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}
