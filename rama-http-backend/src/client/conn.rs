use super::{HttpClientService, svc::SendRequest};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt as _, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
    rt::Executor,
};
use rama_http::{StreamingBody, opentelemetry::version_as_protocol_version};
use rama_http_core::client::conn::http2::H2PeerSettingsHandle;
use rama_http_core::h2::ext::Protocol;
use rama_http_types::{
    Version,
    conn::{
        FallbackHttpVersion, H2ClientContextParams, Http1ClientContextParams, TargetHttpVersion,
    },
    proto::h2::PseudoHeaderOrder,
};
use rama_net::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
};
use rama_net::conn::is_connection_error;
use rama_net::{AuthorityInputExt, HttpVersionInputExt, TargetHttpVersionInputExt};
use tokio::sync::Mutex;

use rama_core::telemetry::tracing::{self, Instrument};
use rama_utils::macros::define_inner_service_accessors;
use std::{error::Error as StdError, marker::PhantomData};

pub(super) fn resolve_input_target_http_version<Input>(input: &Input) -> Option<Version>
where
    Input: ExtensionsRef + HttpVersionInputExt + TargetHttpVersionInputExt,
{
    let fallback = input
        .extensions()
        .get_ref::<FallbackHttpVersion>()
        .map(|fallback| fallback.0);
    input
        .target_http_version_with_fallback(fallback)
        .or_else(|| input.http_version())
}

fn resolve_target_http_version<IO, Input>(io: &IO, input: &Input) -> Option<Version>
where
    IO: ExtensionsRef,
    Input: ExtensionsRef + HttpVersionInputExt + TargetHttpVersionInputExt,
{
    // Negotiation on the established transport wins. The input accessor then
    // resolves an explicit target before the configured post-negotiation
    // fallback and any implicit input version.
    io.extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|target| target.0)
        .or_else(|| resolve_input_target_http_version(input))
}

#[cfg(test)]
mod target_version_tests {
    use rama_core::{ServiceInput, extensions::ExtensionsRef};
    use rama_net::{address::HostWithPort, client::ConnectRequest, http::HttpRequestVersion};

    use super::*;

    #[test]
    fn connection_version_precedes_input_and_adapter_fallback() {
        let io = ServiceInput::new(());
        io.extensions().insert(TargetHttpVersion(Version::HTTP_2));

        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(TargetHttpVersion(Version::HTTP_11));
        input
            .extensions
            .insert(HttpRequestVersion(Version::HTTP_09));

        assert_eq!(
            resolve_target_http_version(&io, &input),
            Some(Version::HTTP_2)
        );
    }

    #[test]
    fn explicit_input_version_precedes_adapter_fallback() {
        let io = ServiceInput::new(());
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(HttpRequestVersion(Version::HTTP_11));
        input
            .extensions
            .insert(FallbackHttpVersion(Version::HTTP_10));
        input.extensions.insert(TargetHttpVersion(Version::HTTP_2));

        assert_eq!(
            resolve_target_http_version(&io, &input),
            Some(Version::HTTP_2)
        );
    }

    #[test]
    fn configured_fallback_precedes_request_version() {
        let io = ServiceInput::new(());
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(HttpRequestVersion(Version::HTTP_2));
        input
            .extensions
            .insert(FallbackHttpVersion(Version::HTTP_11));

        assert_eq!(
            resolve_target_http_version(&io, &input),
            Some(Version::HTTP_11)
        );
    }

    #[test]
    fn negotiated_version_precedes_configured_fallback() {
        let io = ServiceInput::new(());
        io.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(FallbackHttpVersion(Version::HTTP_11));

        assert_eq!(
            resolve_target_http_version(&io, &input),
            Some(Version::HTTP_2)
        );
    }
}

#[cfg(test)]
mod proxy_metadata_tests {
    use rama_core::ServiceInput;
    use rama_http_types::Body;
    use rama_net::{
        address::HostWithPort,
        client::{ConnectRequest, EstablishedProxyRoute, ProxyRoute},
        http::HttpRequestVersion,
    };
    use std::time::Duration;

    use super::*;

    async fn check_established_proxy_metadata(version: Version, eager: bool) {
        let http: rama_net::address::ProxyAddress =
            "http://user:secret@selected.example:8080".parse().unwrap();
        for expected_route in [
            None,
            Some(EstablishedProxyRoute::Direct),
            Some(EstablishedProxyRoute::Tunnel(
                "socks5://selected.example:1080".parse().unwrap(),
            )),
            Some(EstablishedProxyRoute::Forward(http.clone())),
            Some(EstablishedProxyRoute::Tunnel(http)),
        ] {
            let (io, _peer) = tokio::io::duplex(4096);
            let io = ServiceInput::new(io);
            if let Some(route) = expected_route.clone() {
                io.extensions().insert(route);
            }
            let conn = tokio::time::timeout(Duration::from_secs(2), async move {
                if eager {
                    http2_eager_handshake::<_, Body>(io, Executor::default())
                        .await
                        .unwrap()
                        .0
                } else {
                    let input = ConnectRequest::new(HostWithPort::example_domain_http());
                    input.extensions.insert(HttpRequestVersion(version));
                    // Input intent must never fill gaps in established facts.
                    input.extensions.insert(EstablishedProxyRoute::Forward(
                        "http://wrong:credential@request.example:8080"
                            .parse()
                            .unwrap(),
                    ));
                    input.extensions.insert(ProxyRoute::Proxy(
                        "http://wrong:credential@request.example:8080"
                            .parse()
                            .unwrap(),
                    ));
                    http_connect::<_, _, Body>(io, input, Executor::default())
                        .await
                        .unwrap()
                        .conn
                }
            })
            .await
            .expect("HTTP handshake timed out");

            assert_eq!(
                conn.extensions().get_ref::<EstablishedProxyRoute>(),
                expected_route.as_ref(),
                "version: {version:?}, eager: {eager}",
            );
            assert_eq!(
                conn.extensions().get_ref::<ProxyRoute>(),
                None,
                "HTTP handshakes must not copy route intent onto the connection",
            );
        }
    }

    #[tokio::test]
    async fn http_connections_preserve_established_proxy_metadata_and_absence() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            check_established_proxy_metadata(version, false).await;
        }
    }

    #[tokio::test]
    async fn eager_http2_connection_preserves_established_proxy_metadata_and_absence() {
        check_established_proxy_metadata(Version::HTTP_2, true).await;
    }
}

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

    if let Some(params) = extensions.get_ref::<H2ClientContextParams>() {
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
        if let Some(sz) = params.max_frame_size {
            builder.set_max_frame_size(sz);
        }
        if let Some(max) = params.max_concurrent_streams {
            builder.set_max_concurrent_streams(max);
        }
        if let Some(adaptive_window) = params.adaptive_window {
            builder.set_adaptive_window(adaptive_window);
        }
        if let Some(initial) = params.initial_max_send_streams {
            builder.set_initial_max_send_streams(initial);
        }
        if let Some(max) = params.max_send_buf_size {
            builder.set_max_send_buf_size(max);
        }
        if let Some(max) = params.max_concurrent_reset_streams {
            builder.set_max_concurrent_reset_streams(max);
        }
        if let Some(max) = params.max_pending_accept_reset_streams {
            builder.set_max_pending_accept_reset_streams(max);
        }
        if let Some(max) = params.max_local_error_reset_streams {
            builder.set_max_local_error_reset_streams(max);
        }
        if let Some(dur) = params.reset_stream_duration {
            builder.set_reset_stream_duration(dur);
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

/// Establish an HTTP connection on the pre-established IO (bytes) stream.
///
/// The input is returned unchanged and only needs to expose the target HTTP
/// version, authority and connection-scoped extensions. It does not need to be
/// an HTTP request and may instead be a protocol-independent connection input
/// such as [`rama_net::client::ConnectRequest`].
///
/// The spawned HTTP connection span is connection-scoped and can serve many
/// requests, so request fields such as method, URI and user agent belong on
/// request spans rather than this connection span.
pub async fn http_connect<IO, Input, BodyConnection>(
    io: IO,
    input: Input,
    exec: Executor,
) -> Result<EstablishedClientConnection<HttpClientService<BodyConnection>, Input>, OpaqueError>
where
    IO: Io + Unpin + ExtensionsRef,
    Input: AuthorityInputExt
        + ExtensionsRef
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    let extensions = io.extensions().clone();
    let server_host = input.host();
    let server_address = server_host
        .as_ref()
        .map(|host| host.to_str())
        .unwrap_or_default();
    let version = resolve_target_http_version(&io, &input).ok_or_else(|| {
        BoxError::from_static_str("missing HTTP version")
            .context("HTTP connector input")
            .into_opaque_error()
    })?;

    match version {
        Version::HTTP_2 => {
            tracing::trace!("create h2 client executor");

            let mut builder = rama_http_core::client::conn::http2::Builder::new(exec.clone());

            let enable_connect_protocol = input.extensions().get_ref::<Protocol>().is_some();
            apply_h2_client_extensions_to_builder(
                &mut builder,
                input.extensions(),
                enable_connect_protocol,
            );

            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;

            let conn_span = tracing::trace_root_span!(
                "h2::conn::serve",
                otel.kind = "client",
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(version),
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

            Ok(EstablishedClientConnection { input, conn: svc })
        }
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
            tracing::trace!("create ~h1 client executor");
            let mut builder = rama_http_core::client::conn::http1::Builder::new();
            if let Some(params) = input.extensions().get_ref::<Http1ClientContextParams>() {
                builder.set_title_case_headers(params.title_header_case);
            }
            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
            let conn = conn.with_upgrades();

            let conn_span = tracing::trace_root_span!(
                "h1::conn::serve",
                otel.kind = "client",
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(version),
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

            Ok(EstablishedClientConnection { input, conn: svc })
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

impl<S, Input, BodyConnection> Service<Input> for HttpConnector<S, BodyConnection>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt
        + ExtensionsRef
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + 'static,
    // Body type this connector will be able to send, this is not necessarily the same one that
    // was used in the request that created this connection
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<HttpClientService<BodyConnection>, Input>;
    type Error = ConnectionError;

    #[inline]
    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let version = resolve_target_http_version(&conn, &input);
        if let Some(version) = version {
            // TLS has already completed. Normalize the selected version onto
            // both sides so the HTTP handshake, the request adapter and pooled
            // reuse all observe the same concrete target.
            input.extensions().insert(TargetHttpVersion(version));
            conn.extensions().insert(TargetHttpVersion(version));
        }
        http_connect(conn, input, self.exec.clone())
            .await
            .map_err(|error| {
                if matches!(
                    version,
                    Some(Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2)
                ) {
                    ConnectionError::application(error, ConnectionErrorKind::Protocol)
                        .context("HTTP connector: protocol handshake")
                } else {
                    ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                        .context("HTTP connector: select protocol version")
                }
            })
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
