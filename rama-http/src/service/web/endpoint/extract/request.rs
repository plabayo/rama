use super::FromRequest;
use crate::Request;
use rama_core::Context;
use std::convert::Infallible;

impl<S> FromRequest<S> for Request
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(_ctx: Context<S>, req: Request) -> Result<Self, Self::Rejection> {
        Ok(req)
    }
}
