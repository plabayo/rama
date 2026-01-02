use std::marker::PhantomData;

use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{
    Service,
    error::{BoxError, OpaqueError},
    extensions::ExtensionsRef,
    rt::Executor,
    stream::Stream,
};
use rama_http::{
    Request, StreamingBody, Version,
    conn::H2ClientContextParams,
    header::{HOST, USER_AGENT},
    proto::h2::PseudoHeaderOrder,
};
use rama_http_core::h2::ext::Protocol;
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    http::RequestContext,
};
use rama_utils::macros::define_inner_service_accessors;

use super::GrpcClientService;

#[derive(Debug, Clone)]
/// A [`Service`] which establishes a Grpc Connection.
pub struct GrpcConnector<S, Body> {
    inner: S,
    // Body type this connector will be able to send, this is not
    // necessarily the same one that was used in the request that
    // created this connection
    _phantom: PhantomData<fn() -> Body>,
}

impl<S, Body> GrpcConnector<S, Body> {
    /// Create a new [`GrpcConnector`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<S, BodyIn, BodyConnection> Service<Request<BodyIn>> for GrpcConnector<S, BodyConnection>
where
    S: ConnectorService<Request<BodyIn>, Connection: Stream + Unpin>,
    BodyIn: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<GrpcClientService<BodyConnection>, Request<BodyIn>>;
    type Error = BoxError;

    async fn serve(&self, req: Request<BodyIn>) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input: req, conn } =
            self.inner.connect(req).await.map_err(Into::into)?;

        let extensions = conn.extensions().clone();

        let server_address = req
            .extensions()
            .get::<RequestContext>()
            .map(|ctx| ctx.authority.host.to_str())
            .or_else(|| req.uri().host().map(Into::into))
            .or_else(|| {
                req.headers()
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(Into::into)
            })
            .unwrap_or_default();

        let io = Box::pin(conn);

        let executor = req
            .extensions()
            .get::<Executor>()
            .cloned()
            .unwrap_or_default();

        match req.version() {
            Version::HTTP_2 => {
                tracing::trace!(url.full = %req.uri(), "create h2 client executor");

                let mut builder =
                    rama_http_core::client::conn::http2::Builder::new(executor.clone());

                if req.extensions().get::<Protocol>().is_some() {
                    // e.g. used for h2 bootstrap support for WebSocket
                    builder.set_enable_connect_protocol(1);
                }

                if let Some(params) = req
                    .extensions()
                    .get::<H2ClientContextParams>()
                    .or_else(|| req.extensions().get())
                {
                    if let Some(order) = params.headers_pseudo_order.clone() {
                        builder.set_headers_pseudo_order(order);
                    }
                    if let Some(ref frames) = params.early_frames {
                        let v = frames.as_slice().to_vec();
                        builder.set_early_frames(v);
                    }
                } else if let Some(pseudo_order) =
                    req.extensions().get::<PseudoHeaderOrder>().cloned()
                {
                    builder.set_headers_pseudo_order(pseudo_order);
                }

                let (sender, conn) = builder.handshake(io).await?;

                let conn_span = tracing::trace_root_span!(
                    "grpc::conn::serve",
                    otel.kind = "client",
                    url.full = %req.uri(),
                    url.path = %req.uri().path(),
                    url.query = req.uri().query().unwrap_or_default(),
                    url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                    network.protocol.name = "grpc",
                    network.protocol.version = 1,
                    user_agent.original = %req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default(),
                    server.address = %server_address,
                    server.service.name = %server_address,
                );

                executor.spawn_task(
                    async move {
                        if let Err(err) = conn.await {
                            tracing::debug!("connection failed: {err:?}");
                        }
                    }
                    .instrument(conn_span),
                );

                let svc = GrpcClientService { sender, extensions };

                Ok(EstablishedClientConnection {
                    input: req,
                    conn: svc,
                })
            }
            version => Err(OpaqueError::from_display(format!(
                "unsupported Http version: {version:?}",
            ))
            .into()),
        }
    }
}
