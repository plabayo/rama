use crate::{Context, Service};

impl<I, StateIn, StateOut, RequestIn, RequestOut> Service<StateIn, RequestIn> for Option<I>
where
    I: Service<StateIn, RequestIn, Response = (Context<StateOut>, RequestOut)>,
    StateIn: Into<StateOut> + Clone + Send + Sync + 'static,
    StateOut: Clone + Send + Sync + 'static,
    RequestIn: Into<RequestOut> + Send + 'static,
    RequestOut: Send + 'static,
{
    type Error = I::Error;
    type Response = I::Response;

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        match self {
            Some(inspector) => inspector.serve(ctx, req).await,
            None => Ok((ctx.map_state(Into::into), req.into())),
        }
    }
}
