use super::FromRequest;
use crate::http;
use crate::service::Context;
use std::convert::Infallible;
use std::ops::{Deref, DerefMut};

/// Extractor to get the request by value.
#[derive(Debug)]
pub struct Request(pub http::Request);

impl<S> FromRequest<S> for Request
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        Ok(Self(req))
    }
}

impl Deref for Request {
    type Target = http::Request;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Request {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
