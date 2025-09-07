use crate::{Context, Service};

impl<I, RequestIn, RequestOut> Service<RequestIn> for Option<I>
where
    I: Service<RequestIn, Response = (Context, RequestOut)>,
    RequestIn: Into<RequestOut> + Send + 'static,
    RequestOut: Send + 'static,
{
    type Error = I::Error;
    type Response = I::Response;

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        match self {
            Some(inspector) => inspector.serve(ctx, req).await,
            None => Ok((ctx, req.into())),
        }
    }
}
