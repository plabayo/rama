use super::{Context, Service};
use std::convert::Infallible;

/// Identity service, which simply returns the given request.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct IdentityService;

impl<S, Request> Service<S, Request> for IdentityService
where
    S: Send + 'static,
    Request: Send + 'static,
{
    type Response = Request;
    type Error = Infallible;

    async fn serve(&self, _ctx: Context<S>, req: Request) -> Result<Self::Response, Self::Error> {
        Ok(req)
    }
}
