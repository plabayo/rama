use super::FromRequestContextRefPair;
use crate::{Method, request::Parts};
use rama_core::Context;
use std::convert::Infallible;

impl FromRequestContextRefPair for Method {
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(
        _ctx: &Context,
        parts: &Parts,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}
