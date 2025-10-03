use crate::Service;

impl<I, RequestIn, RequestOut> Service<RequestIn> for Option<I>
where
    I: Service<RequestIn, Response = RequestOut>,
    RequestIn: Into<RequestOut> + Send + 'static,
    RequestOut: Send + 'static,
{
    type Error = I::Error;
    type Response = I::Response;

    async fn serve(&self, req: RequestIn) -> Result<Self::Response, Self::Error> {
        match self {
            Some(inspector) => inspector.serve(req).await,
            None => Ok(req.into()),
        }
    }
}
