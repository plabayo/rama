use rama_core::{error::BoxError, Context, Service};
use rama_http_types::{dep::http_body::Body, Request, Response};
use std::future::Future;

pub trait HttpService<State, ReqBody>: sealed::Sealed<State, ReqBody> {
    /// The `Body` body of the `http::Response`.
    type ResBody: Body + Send + 'static;

    /// The error type that can occur within this `Service`.
    ///
    /// Note: Returning an `Error` to a hyper server will cause the connection
    /// to be abruptly aborted. In most cases, it is better to return a `Response`
    /// with a 4xx or 5xx status code.
    type Error: Into<BoxError>;

    #[doc(hidden)]
    fn serve_http(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response<Self::ResBody>, Self::Error>> + Send + 'static;
}

impl<S, State, ReqBody, ResBody> HttpService<State, ReqBody> for S
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>
        + Clone,
    State: Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Body + Send + 'static,
{
    type ResBody = ResBody;
    type Error = S::Error;

    fn serve_http(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response<Self::ResBody>, Self::Error>> + Send + 'static {
        let service = self.clone();
        async move { service.serve(ctx, req).await }
    }
}

mod sealed {
    use super::*;

    pub trait Sealed<State, T>: Send + Sync + 'static {}

    impl<S, State, ReqBody, ResBody> Sealed<State, ReqBody> for S
    where
        S: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>
            + Clone,
        State: Send + Sync + 'static,
        ReqBody: Send + 'static,
        ResBody: Body + Send + 'static,
    {
    }
}
