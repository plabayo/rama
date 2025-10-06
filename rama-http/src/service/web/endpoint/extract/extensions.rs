use super::FromRequestContextRefPair;
use crate::request::Parts;
use rama_core::extensions::Extensions;
use std::convert::Infallible;

impl FromRequestContextRefPair for Extensions {
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(parts: &Parts) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.clone())
    }
}
