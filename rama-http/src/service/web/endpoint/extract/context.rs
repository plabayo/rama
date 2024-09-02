use super::FromRequest;
use crate::http::Request;
use crate::Context;
use std::convert::Infallible;

impl<S> FromRequest<S> for Context<S>
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(ctx: Context<S>, _req: Request) -> Result<Self, Self::Rejection> {
        Ok(ctx)
    }
}
