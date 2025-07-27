use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing::{Instrument, trace_root_span};
use rama_core::{Context, Service, error::BoxError};
use rama_http::opentelemetry::version_as_protocol_version;
use rama_http::service::web::response::IntoResponse;
use rama_http_types::{Request, Response};
use std::{convert::Infallible, fmt};

pub trait HttpService<ReqBody>: sealed::Sealed<ReqBody> {
    #[doc(hidden)]
    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static;
}

pub struct RamaHttpService<S, State> {
    svc: S,
    ctx: Context<State>,
}

impl<S, State> RamaHttpService<S, State> {
    pub fn new(ctx: Context<State>, svc: S) -> Self {
        Self { svc, ctx }
    }
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

impl<S, State, ReqBody, R> HttpService<ReqBody> for RamaHttpService<S, State>
where
    S: Service<State, Request, Response = R, Error = Infallible> + Clone,
    State: Clone + Send + Sync + 'static,
    ReqBody: rama_http_types::dep::http_body::Body<Data = Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
    R: IntoResponse + Send + 'static,
{
    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        let Self { svc, ctx } = self.clone();
        async move {
            let req = req.map(rama_http_types::Body::new);

            let span = trace_root_span!(
                "http::serve",
                otel.kind = "server",
                http.request.method = %req.method().as_str(),
                url.full = %req.uri(),
                url.path = %req.uri().path(),
                url.query = req.uri().query().unwrap_or_default(),
                url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(req.version()),
            );

            Ok(svc.serve(ctx, req).instrument(span).await?.into_response())
        }
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct VoidHttpService;

impl<ReqBody> HttpService<ReqBody> for VoidHttpService
where
    ReqBody: rama_http_types::dep::http_body::Body<Data = Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    #[allow(clippy::manual_async_fn)]
    fn serve_http(
        &self,
        _req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        async move { Ok(Response::new(rama_http_types::Body::empty())) }
    }
}

mod sealed {
    use super::*;

    pub trait Sealed<T>: Send + Sync + 'static {}

    impl<S, State, ReqBody, R> Sealed<ReqBody> for RamaHttpService<S, State>
    where
        S: Service<State, Request, Response = R, Error = Infallible> + Clone,
        State: Clone + Send + Sync + 'static,
        ReqBody: rama_http_types::dep::http_body::Body<Data = Bytes, Error: Into<BoxError>>
            + Send
            + Sync
            + 'static,
        R: IntoResponse + Send + 'static,
    {
    }

    impl<ReqBody> Sealed<ReqBody> for VoidHttpService where
        ReqBody: rama_http_types::dep::http_body::Body<Data = Bytes, Error: Into<BoxError>>
            + Send
            + Sync
            + 'static
    {
    }
}
