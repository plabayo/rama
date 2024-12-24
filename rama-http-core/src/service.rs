use rama_core::{error::BoxError, Context, Service};
use rama_http_types::{dep::http_body::Body, Request, Response};
use std::{fmt, future::Future};

pub trait HttpService<ReqBody>: sealed::Sealed<ReqBody> {
    /// The `Body` body of the `http::Response`.
    type ResBody: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin;

    /// The error type that can occur within this `Service`.
    ///
    /// Note: Returning an `Error` to a rama_http_core server will cause the connection
    /// to be abruptly aborted. In most cases, it is better to return a `Response`
    /// with a 4xx or 5xx status code.
    type Error: Into<BoxError>;

    #[doc(hidden)]
    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response<Self::ResBody>, Self::Error>> + Send + 'static;
}

struct RamaHttpService<S, State> {
    svc: S,
    ctx: Context<State>,
}

impl<S, State> fmt::Debug for RamaHttpService<S, State>
where
    S: fmt::Debug,
    State: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamaHttpService")
            .field("svc", &self.svc)
            .field("ctx", &self.ctx)
            .finish()
    }
}

impl<S, State> Clone for RamaHttpService<S, State>
where
    S: Clone,
    State: Clone,
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<S, State, ReqBody, ResBody> HttpService<ReqBody> for RamaHttpService<S, State>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>
        + Clone,
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    type ResBody = ResBody;
    type Error = S::Error;

    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl std::future::Future<Output = Result<Response<Self::ResBody>, Self::Error>> + Send + 'static
    {
        let RamaHttpService { svc, ctx } = self.clone();
        async move { svc.serve(ctx, req).await }
    }
}

mod sealed {
    use super::*;

    pub trait Sealed<T>: Send + Sync + 'static {}

    impl<S, State, ReqBody, ResBody> Sealed<ReqBody> for RamaHttpService<S, State>
    where
        S: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>,
        State: Clone + Send + Sync + 'static,
        ReqBody: Send + 'static,
        ResBody: Body + Send + 'static,
    {
    }
}
