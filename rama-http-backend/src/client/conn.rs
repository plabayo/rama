use super::{HttpClientService, svc::SendRequest};
use rama_core::{
    Layer, Service,
    error::{BoxError, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    rt::Executor,
    stream::Stream,
};
use rama_http::{
    StreamingBody,
    header::{HOST, USER_AGENT},
    opentelemetry::version_as_protocol_version,
};
use rama_http_core::h2::ext::Protocol;
use rama_http_types::{
    Request, Version,
    conn::{H2ClientContextParams, Http1ClientContextParams},
    proto::h2::PseudoHeaderOrder,
};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    conn::ConnectionHealth,
    http::RequestContext,
};
use tokio::sync::Mutex;

use rama_core::telemetry::tracing::{self, Instrument};
use rama_utils::macros::define_inner_service_accessors;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
/// A [`Service`] which establishes an HTTP Connection.
pub struct HttpConnector<S, Body> {
    inner: S,
    exec: Executor,
    // Body type this connector will be able to send, this is not
    // necessarily the same one that was used in the request that
    // created this connection
    _phantom: PhantomData<fn() -> Body>,
}

impl<S, Body> HttpConnector<S, Body> {
    /// Create a new [`HttpConnector`].
    pub fn new(inner: S, exec: Executor) -> Self {
        Self {
            inner,
            exec,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<S, BodyIn, BodyConnection> Service<Request<BodyIn>> for HttpConnector<S, BodyConnection>
where
    S: ConnectorService<Request<BodyIn>, Connection: Stream + Unpin>,
    BodyIn: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<HttpClientService<BodyConnection>, Request<BodyIn>>;
    type Error = BoxError;

    async fn serve(&self, req: Request<BodyIn>) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection {
            input: req,
            mut conn,
        } = self.inner.connect(req).await.map_err(Into::into)?;

        // TODO this is way to tricky, this needs to be here on the io extensions
        // Not the ones we clone, ideally the exentions should all just use the same store
        // We can solve this by making them clonable
        conn.extensions_mut()
            .get_or_insert(ConnectionHealth::default);

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

        match req.version() {
            Version::HTTP_2 => {
                tracing::trace!(url.full = %req.uri(), "create h2 client executor");

                let mut builder =
                    rama_http_core::client::conn::http2::Builder::new(self.exec.clone());

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
                    if let Some(sz) = params.init_stream_window_size {
                        builder.set_initial_stream_window_size(sz);
                    }
                    if let Some(sz) = params.init_connection_window_size {
                        builder.set_initial_connection_window_size(sz);
                    }
                    if let Some(d) = params.keep_alive_interval {
                        builder.set_keep_alive_interval(d);
                    }
                    if let Some(d) = params.keep_alive_timeout {
                        builder.set_keep_alive_timeout(d);
                    }
                    if let Some(keep_alive) = params.keep_alive_while_idle {
                        builder.set_keep_alive_while_idle(keep_alive);
                    }
                    if let Some(sz) = params.max_header_list_size {
                        builder.set_max_header_list_size(sz);
                    }
                    if let Some(adaptive_window) = params.adaptive_window {
                        builder.set_adaptive_window(adaptive_window);
                    }
                } else if let Some(pseudo_order) =
                    req.extensions().get::<PseudoHeaderOrder>().cloned()
                {
                    builder.set_headers_pseudo_order(pseudo_order);
                }

                let (sender, conn) = builder.handshake(io).await?;

                let conn_span = tracing::trace_root_span!(
                    "h2::conn::serve",
                    otel.kind = "client",
                    http.request.method = %req.method().as_str(),
                    url.full = %req.uri(),
                    url.path = %req.uri().path(),
                    url.query = req.uri().query().unwrap_or_default(),
                    url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                    network.protocol.name = "http",
                    network.protocol.version = version_as_protocol_version(req.version()),
                    user_agent.original = %req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default(),
                    server.address = %server_address,
                    server.service.name = %server_address,
                );

                self.exec.spawn_task(
                    async move {
                        if let Err(err) = conn.await {
                            tracing::debug!("connection failed: {err:?}");
                        }
                    }
                    .instrument(conn_span),
                );

                let svc = HttpClientService {
                    sender: SendRequest::Http2(sender),
                    extensions,
                };

                Ok(EstablishedClientConnection {
                    input: req,
                    conn: svc,
                })
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                tracing::trace!(url.full = %req.uri(), "create ~h1 client executor");
                let mut builder = rama_http_core::client::conn::http1::Builder::new();
                if let Some(params) = req.extensions().get::<Http1ClientContextParams>() {
                    builder.set_title_case_headers(params.title_header_case);
                }
                let (sender, conn) = builder.handshake(io).await?;
                let conn = conn.with_upgrades();

                let conn_span = tracing::trace_root_span!(
                    "h1::conn::serve",
                    otel.kind = "client",
                    http.request.method = %req.method().as_str(),
                    url.full = %req.uri(),
                    url.path = %req.uri().path(),
                    url.query = req.uri().query().unwrap_or_default(),
                    url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                    network.protocol.name = "http",
                    network.protocol.version = version_as_protocol_version(req.version()),
                    user_agent.original = %req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default(),
                    server.address = %server_address,
                    server.service.name = %server_address,
                );

                self.exec.spawn_task(
                    async move {
                        if let Err(err) = conn.await {
                            tracing::debug!("connection failed: {err:?}");
                        }
                    }
                    .instrument(conn_span),
                );

                let svc = HttpClientService {
                    sender: SendRequest::Http1(Mutex::new(sender)),
                    extensions,
                };

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

#[derive(Clone, Debug)]
/// A [`Layer`] that produces an [`HttpConnector`].
pub struct HttpConnectorLayer<Body> {
    exec: Executor,
    _phantom: PhantomData<Body>,
}

impl<Body> HttpConnectorLayer<Body> {
    /// Create a new [`HttpConnectorLayer`].
    #[must_use]
    pub const fn new(exec: Executor) -> Self {
        Self {
            exec,
            _phantom: PhantomData,
        }
    }
}

impl<Body> Default for HttpConnectorLayer<Body> {
    fn default() -> Self {
        Self::new(Executor::default())
    }
}

impl<S, Body> Layer<S> for HttpConnectorLayer<Body> {
    type Service = HttpConnector<S, Body>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            exec: self.exec.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            exec: self.exec,
            _phantom: PhantomData,
        }
    }
}
