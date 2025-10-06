use super::FromRequestContextRefPair;
use crate::{Method, request::Parts};
use std::convert::Infallible;

impl FromRequestContextRefPair for Method {
    type Rejection = Infallible;

    async fn from_request_context_ref_pair(parts: &Parts) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}
