use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing::{Instrument, trace_root_span};
use rama_core::{Service, error::BoxError};
use rama_http::StreamingBody;
use rama_http::opentelemetry::version_as_protocol_version;
use rama_http::service::web::response::IntoResponse;
use rama_http_types::{Request, Response};
use std::{convert::Infallible, fmt};

#[derive(Clone, fmt::Debug)]
pub struct RamaHttpService<S> {
    svc: S,
}

impl<S> RamaHttpService<S> {
    pub fn new(svc: S) -> Self {
        Self { svc }
    }
}

impl<S, ReqBody, R> Service<Request<ReqBody>> for RamaHttpService<S>
where
    S: Service<Request, Output = R, Error = Infallible>,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    R: IntoResponse + Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Response, Infallible> {
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

        Ok(self.svc.serve(req).instrument(span).await?.into_response())
    }
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct VoidHttpService;

#[cfg(test)]
impl<ReqBody> Service<Request<ReqBody>> for VoidHttpService
where
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = Infallible;

    #[allow(clippy::manual_async_fn)]
    fn serve(
        &self,
        _req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + '_ {
        async move { Ok(Response::new(rama_http_types::Body::empty())) }
    }
}
