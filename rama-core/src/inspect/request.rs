use crate::{Context, Service};

/// A special kind of [`Service`] which has access only to the Request,
/// but not to the Response.
///
/// Useful in case you want to explicitly
/// restrict this acccess or because the Response would
/// anyway not yet be produced at the point this inspector would be layered.
pub trait RequestInspector<RequestIn>: Send + Sync + 'static {
    /// The type of error returned by the service.
    type Error: Send + 'static;
    type RequestOut: Send + 'static;

    /// Inspect the request, modify it if needed or desired, and return it.
    fn inspect_request(
        &self,
        ctx: Context,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context, Self::RequestOut), Self::Error>> + Send + '_;
}

impl<S, RequestIn, RequestOut> RequestInspector<RequestIn> for S
where
    S: Service<RequestIn, Response = (Context, RequestOut)>,
    RequestIn: Send + 'static,
    RequestOut: Send + 'static,
{
    type Error = S::Error;
    type RequestOut = RequestOut;

    fn inspect_request(
        &self,
        ctx: Context,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context, Self::RequestOut), Self::Error>> + Send + '_ {
        self.serve(ctx, req)
    }
}
