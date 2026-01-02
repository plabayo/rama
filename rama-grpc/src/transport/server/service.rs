use std::{convert::Infallible, pin::pin, sync::Arc};

use rama_core::{
    Service, bytes,
    error::BoxError,
    extensions::ExtensionsMut,
    futures::FutureExt,
    rt::Executor,
    stream::Stream,
    telemetry::tracing::{self, Instrument, trace_root_span},
};
use rama_http::{Body, Response, StreamingBody};
use rama_http_core::server::conn::http2::Builder as H2ConnBuilder;
use rama_http_types::Request;

use tokio::select;

use crate::Status;

/// grpc server service
#[derive(Debug, Clone)]
pub struct GrpcService<S> {
    builder: Arc<H2ConnBuilder>,
    service: Arc<S>,
}

impl<S> GrpcService<S> {
    pub(super) fn new(builder: H2ConnBuilder, service: S) -> Self {
        Self {
            builder: Arc::new(builder),
            service: Arc::new(service),
        }
    }
}

impl<S, IO> Service<IO> for GrpcService<S>
where
    S: Service<Request, Output = rama_http_types::Response, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    // TODO, what should output be?
    IO: Stream + ExtensionsMut + Unpin + Send + 'static,
{
    type Output = ();
    type Error = Status;

    async fn serve(&self, io: IO) -> Result<Self::Output, Self::Error> {
        let guard = io
            .extensions()
            .get::<Executor>()
            .and_then(|exec| exec.guard())
            .cloned();

        let conn_svc = GrpcConnectionSerice(self.service.clone());
        let mut conn = pin!(self.builder.serve_connection(io, conn_svc));

        if let Some(guard) = guard {
            let mut cancelled_fut = pin!(guard.cancelled().fuse());

            select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("gRPC: signal received, initiating graceful shutdown");
                    conn.as_mut().graceful_shutdown();
                }
                result = conn.as_mut() => {
                    return result.map_err(Status::from_error_generic);
                }
            }
            // Wait for the shutdown to complete after the signal
            conn.await.map_err(Status::from_error_generic)
        } else {
            conn.await.map_err(Status::from_error_generic)
        }
    }
}

// TODO: adapt to actual Grpc usage

#[derive(Clone, Debug)]
struct GrpcConnectionSerice<S>(S);

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for GrpcConnectionSerice<S>
where
    S: Service<Request, Output = Response<ResBody>, Error = Infallible>,
    ReqBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Response, Infallible> {
        let req = req.map(rama_http_types::Body::new);

        let span = trace_root_span!(
            "grpc::serve",
            otel.kind = "server",
            url.full = %req.uri(),
            url.path = %req.uri().path(),
            url.query = req.uri().query().unwrap_or_default(),
            url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
            network.protocol.name = "grpc",
            network.protocol.version = 1,
        );

        Ok(self.0.serve(req).instrument(span).await?.map(Body::new))
    }
}
