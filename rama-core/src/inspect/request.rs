use crate::{Context, Service};

/// A special kind of [`Service`] which has access only to the Request,
/// but not to the Response.
///
/// Useful in case you want to explicitly
/// restrict this acccess or because the Response would
/// anyway not yet be produced at the point this inspector would be layered.
pub trait RequestInspector<StateIn, RequestIn>: Send + Sync + 'static {
    /// The type of error returned by the service.
    type Error: Send + Sync + 'static;
    type RequestOut: Send + 'static;
    type StateOut: Clone + Send + Sync + 'static;

    /// Inspect the request, modify it if needed or desired, and return it.
    fn inspect_request(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context<Self::StateOut>, Self::RequestOut), Self::Error>> + Send + '_;
}

impl<S, StateIn, StateOut, RequestIn, RequestOut> RequestInspector<StateIn, RequestIn> for S
where
    S: Service<StateIn, RequestIn, Response = (Context<StateOut>, RequestOut)>,
    RequestIn: Send + 'static,
    RequestOut: Send + 'static,
    StateIn: Clone + Send + Sync + 'static,
    StateOut: Clone + Send + Sync + 'static,
{
    type Error = S::Error;
    type RequestOut = RequestOut;
    type StateOut = StateOut;

    fn inspect_request(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context<Self::StateOut>, Self::RequestOut), Self::Error>> + Send + '_
    {
        self.serve(ctx, req)
    }
}
