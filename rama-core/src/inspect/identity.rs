use std::convert::Infallible;

use crate::{Context, Service};

impl<State, Request> Service<State, Request> for ()
where
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Error = Infallible;
    type Response = (Context<State>, Request);

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<(Context<State>, Request), Self::Error> {
        Ok((ctx, req))
    }
}
