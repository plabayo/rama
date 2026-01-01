//! Rama gRPC server module.

use std::{convert::Infallible, pin::pin, sync::Arc};

use rama_core::{
    Service, bytes,
    error::BoxError,
    extensions::ExtensionsMut,
    futures::FutureExt,
    graceful::ShutdownGuard,
    rt::Executor,
    stream::Stream,
    telemetry::tracing::{self, Instrument, trace_root_span},
};
use rama_http::{Body, Response, StreamingBody};
use rama_http_core::server::conn::http2::Builder as H2ConnBuilder;
use rama_http_types::Request;
use rama_net::socket::Interface;
use rama_tcp::server::TcpListener;

use tokio::select;

use crate::Status;

/// A specialized result for gRPC server operations.
pub type GrpcServeResult = Result<(), BoxError>;

/// A builder for configuring and listening over gRPC (HTTP/2).
#[derive(Debug, Clone)]
pub struct GrpcServer {
    builder: H2ConnBuilder,
    guard: Option<ShutdownGuard>,
}

impl GrpcServer {
    /// Create a new gRPC server builder with default H2 settings.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        let guard = exec.guard().cloned();
        Self {
            builder: H2ConnBuilder::new(exec),
            guard,
        }
    }

    /// Access the underlying H2 configuration (e.g., window sizes, keepalives).
    pub fn h2_mut(&mut self) -> &mut H2ConnBuilder {
        &mut self.builder
    }

    /// Create a Rama [`Service`] that serves IO Byte streams as gRPC.
    pub fn service<S>(self, service: S) -> GrpcService<S> {
        GrpcService::new(self.builder, service)
    }

    /// Listen for connections on the given interface and serve gRPC.
    pub async fn listen<S, I>(self, interface: I, service: S) -> GrpcServeResult
    where
        S: Service<Request, Output = rama_http_types::Response, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        // TODO: what should output be?
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface).await?;
        let service = GrpcService::new(self.builder, service);

        match self.guard {
            Some(guard) => tcp.serve_graceful(guard, service).await,
            None => tcp.serve(service).await,
        };
        Ok(())
    }
}

/// The service that drives the H2 connection loop.
#[derive(Debug, Clone)]
pub struct GrpcService<S> {
    builder: Arc<H2ConnBuilder>,
    service: Arc<S>,
}

impl<S> GrpcService<S> {
    fn new(builder: H2ConnBuilder, service: S) -> Self {
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
