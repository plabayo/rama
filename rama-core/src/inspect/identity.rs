use std::convert::Infallible;

use crate::{Context, Service};

impl<Request> Service<Request> for ()
where
    Request: Send + 'static,
{
    type Error = Infallible;
    type Response = (Context, Request);

    async fn serve(&self, ctx: Context, req: Request) -> Result<(Context, Request), Self::Error> {
        Ok((ctx, req))
    }
}
