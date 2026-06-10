use super::{HttpClientService, svc::SendRequest};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt as _, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
    rt::Executor,
};
use rama_http::{
    StreamingBody,
    header::{HOST, USER_AGENT},
    opentelemetry::version_as_protocol_version,
};
use rama_http_core::client::conn::http2::H2PeerSettingsHandle;
use rama_http_core::h2::ext::Protocol;
use rama_http_types::{
    Request, Version,
    conn::{H2ClientContextParams, Http1ClientContextParams},
    proto::h2::PseudoHeaderOrder,
};
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::conn::is_connection_error;
use tokio::sync::Mutex;

use rama_core::telemetry::tracing::{self, Instrument};
use rama_utils::macros::define_inner_service_accessors;
use std::{borrow::Cow, error::Error as StdError, marker::PhantomData};

fn is_expected_http_connection_termination(err: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if let Some(http_err) = err.downcast_ref::<rama_http_core::Error>()
            && (http_err.is_canceled() || http_err.is_closed() || http_err.is_body_write_aborted())
        {
            return true;
        }

        if let Some(h2_err) = err.downcast_ref::<rama_http_core::h2::Error>() {
            if h2_err.is_go_away() {
                return true;
            }
            if let Some(io_err) = h2_err.get_io()
                && is_connection_error(io_err)
            {
                return true;
            }
        }

        if let Some(io_err) = err.downcast_ref::<std::io::Error>()
            && is_connection_error(io_err)
        {
            return true;
        }

        current = err.source();
    }

    false
}

fn log_connection_termination(err: &rama_http_core::Error) {
    if is_expected_http_connection_termination(err) {
        tracing::trace!(error = ?err, "connection closed by peer / transport");
    } else {
        tracing::debug!(error = ?err, "connection failed");
    }
}

/// Apply h2 builder knobs from `extensions` (looks up
/// `H2ClientContextParams`, falls back to a bare `PseudoHeaderOrder`).
/// Shared between the lazy [`http_connect`] path (passes
/// `req.extensions()`) and the eager [`http2_eager_handshake`] path
/// (passes egress IO's `extensions()`). The eager path doesn't see
/// request-scoped extensions — stamp on the egress IO instead.
fn apply_h2_client_extensions_to_builder(
    builder: &mut rama_http_core::client::conn::http2::Builder,
    extensions: &Extensions,
    enable_connect_protocol: bool,
) {
    if enable_connect_protocol {
        // e.g. used for h2 bootstrap support for WebSocket — only ever
        // requested on a per-request basis by the lazy path.
        builder.set_enable_connect_protocol(1);
    }

    if let Some(params) = extensions
        .get_ref::<H2ClientContextParams>()
        .or_else(|| extensions.get_ref())
    {
        if let Some(order) = params.headers_pseudo_order.clone() {
            builder.set_headers_pseudo_order(order);
        } else if let Some(pseudo_order) = extensions.get_ref::<PseudoHeaderOrder>().cloned() {
            builder.set_headers_pseudo_order(pseudo_order);
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
    } else if let Some(pseudo_order) = extensions.get_ref::<PseudoHeaderOrder>().cloned() {
        builder.set_headers_pseudo_order(pseudo_order);
    }
}

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

/// Establish an HTTP connection on the pre-established IO (bytes) stream
/// with the given http request as context for the initial setup.
pub async fn http_connect<IO, BodyIn, BodyConnection>(
    io: IO,
    req: Request<BodyIn>,
    exec: Executor,
) -> Result<
    EstablishedClientConnection<HttpClientService<BodyConnection>, Request<BodyIn>>,
    OpaqueError,
>
where
    IO: Io + Unpin + ExtensionsRef,
    BodyIn: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    let extensions = io.extensions().clone();

    let server_address: Cow<'_, str> = req
        .uri()
        .host()
        .map(Into::into)
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(Into::into)
        })
        .unwrap_or_default();

    match req.version() {
        Version::HTTP_2 => {
            tracing::trace!(url.full = %req.uri(), "create h2 client executor");

            let mut builder = rama_http_core::client::conn::http2::Builder::new(exec.clone());

            let enable_connect_protocol = req.extensions().get_ref::<Protocol>().is_some();
            apply_h2_client_extensions_to_builder(
                &mut builder,
                req.extensions(),
                enable_connect_protocol,
            );

            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;

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

            exec.into_spawn_task(
                async move {
                    if let Err(err) = conn.await {
                        log_connection_termination(&err);
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
            if let Some(params) = req.extensions().get_ref::<Http1ClientContextParams>() {
                builder.set_title_case_headers(params.title_header_case);
            }
            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
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

            exec.into_spawn_task(
                async move {
                    if let Err(err) = conn.await {
                        log_connection_termination(&err);
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
        version => Err(BoxError::from_static_str("unsupported Http version")
            .context_debug_field("version", version)
            .into_opaque_error()),
    }
}

/// Establish an HTTP/2 connection on the pre-established IO (bytes)
/// stream *without* a triggering request, and return both the
/// [`HttpClientService`] and a [`H2PeerSettingsHandle`] that resolves
/// to the peer's initial SETTINGS frame once received.
///
/// Used by MITM relays that need to observe upstream h2 SETTINGS before
/// the ingress server's initial SETTINGS frame is written to the
/// downstream client. Like the h2 arm of [`http_connect`], request-
/// scoped builder knobs ([`H2ClientContextParams`], [`PseudoHeaderOrder`])
/// are read from the egress IO's extensions and applied — letting
/// UA-emulation profiles flow through the eager path as well. The
/// per-request `Protocol` extension is intentionally NOT honored here:
/// there is no request yet at eager-handshake time.
pub async fn http2_eager_handshake<IO, BodyConnection>(
    io: IO,
    exec: Executor,
) -> Result<(HttpClientService<BodyConnection>, H2PeerSettingsHandle), OpaqueError>
where
    IO: Io + Unpin + ExtensionsRef,
    BodyConnection:
        StreamingBody<Data: Send + Sync + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    let extensions = io.extensions().clone();

    tracing::trace!("eager h2 client handshake");
    let mut builder = rama_http_core::client::conn::http2::Builder::new(exec.clone());
    apply_h2_client_extensions_to_builder(&mut builder, &extensions, false);
    let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
    let peer_handle = conn.peer_settings_handle();

    let conn_span = tracing::trace_root_span!(
        "h2::conn::serve",
        otel.kind = "client",
        network.protocol.name = "http",
        network.protocol.version = version_as_protocol_version(Version::HTTP_2),
    );

    exec.into_spawn_task(
        async move {
            if let Err(err) = conn.await {
                log_connection_termination(&err);
            }
        }
        .instrument(conn_span),
    );

    let svc = HttpClientService {
        sender: SendRequest::Http2(sender),
        extensions,
    };
    Ok((svc, peer_handle))
}

impl<S, BodyIn, BodyConnection> Service<Request<BodyIn>> for HttpConnector<S, BodyConnection>
where
    S: ConnectorService<Request<BodyIn>, Connection: Io + Unpin>,
    BodyIn: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<HttpClientService<BodyConnection>, Request<BodyIn>>;
    type Error = OpaqueError;

    #[inline]
    async fn serve(&self, req: Request<BodyIn>) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input: req, conn } = self
            .inner
            .connect(req)
            .await
            .map_err(Into::into)
            .into_opaque_error()?;
        http_connect(conn, req, self.exec.clone()).await
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
