use super::{
    HttpClientService, HttpTransport, IntoHttpTransport, drain::Http1DrainRuntime, svc::SendRequest,
};
#[cfg(feature = "quic")]
use super::{HttpTransportConnector, h3::coalescing};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt as _, extra::OpaqueError},
    extensions::{Extension, Extensions, ExtensionsRef},
    graceful::{WeakScope, attach_scope},
    io::{AbortableIo, Io},
};
use rama_http::{StreamingBody, opentelemetry::version_as_protocol_version};
use rama_http_core::{client::conn::http2::H2PeerSettingsHandle, h2::RateBudget};
use rama_http_types::{
    Version,
    conn::{
        FallbackHttpVersion, H2ClientContextParams, Http1ClientContextParams, TargetHttpVersion,
    },
    proto::h2::{PseudoHeaderOrder, alt_svc::AltSvcObserverExtension},
};
use rama_net::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
    pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
};
use rama_net::conn::is_connection_error;
use rama_net::{
    AuthorityInputExt, HttpVersionInputExt, ProtocolInputExt, TargetHttpVersionInputExt,
};
use rama_tls::client::NegotiatedTlsParameters;
use tokio::sync::Mutex;
#[cfg(feature = "quic")]
use {
    rama_http_core::h3::transport::Connection as _,
    rama_net::tls::{AlpnPolicy, EarlyDataPermit, ForbidEarlyData},
    std::sync::Arc,
};

use rama_core::telemetry::tracing::{self, Instrument};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{error::Error as StdError, marker::PhantomData};

/// The most interim (1xx) responses a client connection accepts for one request before it
/// fails that request, on whichever HTTP version the connection speaks.
///
/// Read when a connection is established, from the extensions of the input that opens it
/// and else from those of its transport, so a proxy or gateway can set it per request or per
/// egress connection; [`HttpConnector::with_max_informational_responses`] sets it for every
/// connection of a connector that finds neither. Without any of them each protocol applies
/// its own default of 1024.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
pub struct MaxInformationalResponses(pub usize);

impl MaxInformationalResponses {
    /// The limit for a connection opened by an input with extensions `input` on a transport
    /// with extensions `transport`, if either carries one.
    pub(crate) fn resolve(input: &Extensions, transport: &Extensions) -> Option<usize> {
        input
            .get_ref::<Self>()
            .or_else(|| transport.get_ref::<Self>())
            .map(|max| max.0)
    }
}

/// The budget of streams an HTTP/2 or HTTP/3 client connection refuses or resets for what
/// its origin sent on them, a protocol or message error or a local limit such as
/// [`MaxInformationalResponses`]: a burst tolerated at once and regained over time, past
/// which the connection is closed. `None` never closes the connection for them.
///
/// An origin staying below the rate is flagged in the logs as its lifetime total doubles;
/// [`RateBudget::with_ceiling`] ends it, [`RateBudget::lifetime`] is a plain lifetime count.
///
/// Read like [`MaxInformationalResponses`]: from the input that opens a connection, else
/// from its transport, else from [`HttpConnector::with_refused_stream_budget`]. Without
/// any of them a connection tolerates a burst of 1000 such streams regained at 33 per
/// second. HTTP/1 ends its connection with such a request.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
pub struct RefusedStreamBudget(pub Option<RateBudget>);

impl RefusedStreamBudget {
    /// The budget for a connection opened by an input with extensions `input` on a
    /// transport with extensions `transport`, if either carries one.
    pub(crate) fn resolve(input: &Extensions, transport: &Extensions) -> Option<Self> {
        input
            .get_ref::<Self>()
            .or_else(|| transport.get_ref::<Self>())
            .copied()
    }
}

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

/// Ordinary input versions permit negotiation; an explicit target or H3 prior
/// knowledge constrains the transport before it is established.
fn required_transport_http_version<Input>(input: &Input) -> Option<Version>
where
    Input: ExtensionsRef + HttpVersionInputExt + TargetHttpVersionInputExt,
{
    input
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|version| version.0)
        .or_else(|| {
            resolve_input_target_http_version(input).filter(|version| *version == Version::HTTP_3)
        })
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
                    http2_eager_handshake::<_, Body>(io, WeakScope::detached())
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
                    http_connect::<_, _, Body>(io, input, WeakScope::detached())
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
) {
    if let Some(params) = extensions.get_ref::<H2ClientContextParams>() {
        if let Some(settings) = &params.initial_settings {
            builder.set_initial_settings(settings.clone());
        }
        if let Some(order) = params.headers_pseudo_order.clone() {
            builder.set_headers_pseudo_order(order);
        } else if let Some(pseudo_order) = extensions.get_ref::<PseudoHeaderOrder>().cloned() {
            builder.set_headers_pseudo_order(pseudo_order);
        }

        if let Some(frames) = &params.replay_early_frames {
            builder.set_early_frames(frames.as_ref().to_vec());
        } else if let Some(ref frames) = params.early_frames {
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
        if let Some(size) = params.header_table_size {
            builder.set_header_table_size(size);
        }
        if let Some(max) = params.max_concurrent_streams {
            builder.set_max_concurrent_streams(max);
        }
        if let Some(adaptive_window) = params.adaptive_window {
            builder.set_adaptive_window(adaptive_window);
        }
        if let Some(refuse) = params.refuse_push_promises {
            builder.set_refuse_push_promises(refuse);
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
        if let Some(dur) = params.reset_stream_duration {
            builder.set_reset_stream_duration(dur);
        }
    } else if let Some(pseudo_order) = extensions.get_ref::<PseudoHeaderOrder>().cloned() {
        builder.set_headers_pseudo_order(pseudo_order);
    }
}

#[derive(Debug, Clone, ExtensionsRef)]
/// A [`Service`] which establishes an HTTP Connection.
///
/// A byte stream connection holds the connector's scope until its transport is gone, an
/// upgraded one included, and is cut at the hard phase of that scope. A QUIC connection holds
/// it while open, kept so by its live bodies and tunnels, and is closed at that hard phase.
pub struct HttpConnector<S, Body> {
    inner: S,
    scope: WeakScope,
    max_informational_responses: Option<usize>,
    refused_stream_budget: Option<RefusedStreamBudget>,
    // Body type this connector will be able to send, this is not
    // necessarily the same one that was used in the request that
    // created this connection
    _phantom: PhantomData<fn() -> Body>,
}

impl<S, Body> HttpConnector<S, Body> {
    /// Create a new [`HttpConnector`].
    pub fn new(inner: S, scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        Self {
            inner,
            scope,
            max_informational_responses: None,
            refused_stream_budget: None,
            _phantom: PhantomData,
        }
    }
}

impl<S, Body> HttpConnector<S, Body> {
    generate_set_and_with! {
        /// The most interim (1xx) responses accepted for one request on the connections this
        /// connector establishes, whichever HTTP version they speak, unless the input or
        /// its transport carries [`MaxInformationalResponses`]. `None` (the default) leaves
        /// each protocol its own default.
        pub fn max_informational_responses(mut self, max: Option<usize>) -> Self {
            self.max_informational_responses = max;
            self
        }
    }

    generate_set_and_with! {
        /// The budget of streams refused or reset for what the origin sent, on the HTTP/2
        /// and HTTP/3 connections this connector establishes, unless the input or its
        /// transport carries [`RefusedStreamBudget`]. `None` (the default) leaves the
        /// protocol its default.
        pub fn refused_stream_budget(mut self, budget: Option<RefusedStreamBudget>) -> Self {
            self.refused_stream_budget = budget;
            self
        }
    }

    #[cfg(feature = "quic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
    /// Add a QUIC transport connector below the common HTTP handshake.
    /// The connector returns [`super::Http3Transport`], without starting HTTP/3.
    pub fn with_http3_connector<Q>(
        self,
        quic: Q,
    ) -> HttpConnector<HttpTransportConnector<S, Q>, Body> {
        HttpConnector {
            inner: HttpTransportConnector::new(self.inner, quic),
            scope: self.scope,
            max_informational_responses: self.max_informational_responses,
            refused_stream_budget: self.refused_stream_budget,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

#[derive(Debug)]
struct UnclassifiedSecureTransport;

impl ConnectionReusePolicy for UnclassifiedSecureTransport {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        None
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        None
    }
}

/// Perform the HTTP handshake on an established byte stream or QUIC transport.
/// The selected protocol must agree with the transport; metadata remains attached
/// to the resulting service for pooling and request adaptation. The input's
/// protocol distinguishes secure origins without inferring TLS from a port.
/// Custom secure transports must publish [`ConnectionReuse`] to enable pooling.
/// Connections using HTTP/2 or HTTP/3 without ALPN wait for peer SETTINGS.
/// No default deadline is applied here or by `EasyHttpWebClient`. Callers that
/// need bounded establishment must wrap their connector in a timeout, including
/// the TLS/QUIC handshake and this readiness wait. Cancellation drops the pending
/// HTTP connection.
/// Custom QUIC transports can publish [`rama_net::tls::AlpnPolicy::OutOfBandAgreement`] in
/// connection extensions when HTTP/3 was agreed through another mechanism.
/// A byte stream holds `scope` until it is gone, after an upgrade too, and is cut
/// at the hard phase of that scope. A QUIC connection holds it while open, kept so by its
/// live bodies and tunnels, and is closed at that hard phase.
pub async fn http_connect<T, Input, BodyConnection>(
    transport: T,
    input: Input,
    scope: WeakScope,
) -> Result<EstablishedClientConnection<HttpClientService<BodyConnection>, Input>, OpaqueError>
where
    T: IntoHttpTransport,
    Input: AuthorityInputExt
        + ProtocolInputExt
        + ExtensionsRef
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + 'static,
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    http_connect_with(transport, input, scope, None, None).await
}

/// [`http_connect`] with the connector's own limit on interim responses and budget of
/// refusals, used when neither the input nor the transport carries
/// [`MaxInformationalResponses`] or [`RefusedStreamBudget`].
async fn http_connect_with<T, Input, BodyConnection>(
    transport: T,
    input: Input,
    scope: WeakScope,
    max_informational_responses: Option<usize>,
    refused_stream_budget: Option<RefusedStreamBudget>,
) -> Result<EstablishedClientConnection<HttpClientService<BodyConnection>, Input>, OpaqueError>
where
    T: IntoHttpTransport,
    Input: AuthorityInputExt
        + ProtocolInputExt
        + ExtensionsRef
        + HttpVersionInputExt
        + TargetHttpVersionInputExt
        + Send
        + 'static,
    BodyConnection:
        StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    let transport = transport.into_http_transport();
    let max_informational_responses =
        MaxInformationalResponses::resolve(input.extensions(), transport.extensions())
            .or(max_informational_responses);
    let refused_stream_budget =
        RefusedStreamBudget::resolve(input.extensions(), transport.extensions())
            .or(refused_stream_budget);
    let plaintext_origin = input
        .target_protocol()
        .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure());
    // A secure (or unknown) origin needs rules from its own TLS connector;
    // proxy-leg rules alone cannot establish whether origin TLS can be reused.
    let endpoint_policy_required = transport.is_quic() || !plaintext_origin;
    let reuse = transport.extensions().get_ref::<ConnectionReuse>();
    let classified = if endpoint_policy_required {
        reuse.is_some_and(ConnectionReuse::is_complete)
    } else {
        // Plain HTTP can rely on the route key. If TLS was used to reach a
        // proxy, retain its restrictions even though the origin is plaintext.
        !transport.extensions().contains::<NegotiatedTlsParameters>() || reuse.is_some()
    };
    if !classified {
        // Missing metadata prevents future reuse, not this request's handshake.
        transport
            .extensions()
            .insert(ConnectionReuse::new(UnclassifiedSecureTransport));
    }
    let version = match &transport {
        HttpTransport::Stream(io) => resolve_target_http_version(io, &input),
        #[cfg(feature = "quic")]
        HttpTransport::Quic(_) => Some(Version::HTTP_3),
    };
    let required = required_transport_http_version(&input);
    if required
        .zip(version)
        .is_some_and(|(required, actual)| required != actual)
    {
        return Err(BoxError::from_static_str(
            "established transport conflicts with required HTTP version",
        )
        .into_opaque_error());
    }
    match transport {
        HttpTransport::Stream(io) => {
            if let Some(version) = version {
                input.extensions().insert(TargetHttpVersion(version));
                io.extensions().insert(TargetHttpVersion(version));
            }
            http_stream_connect(
                io,
                input,
                scope,
                max_informational_responses,
                refused_stream_budget,
            )
            .await
        }
        #[cfg(feature = "quic")]
        HttpTransport::Quic(quic) => {
            let early = quic.config.early_requests
                && input.extensions().contains::<EarlyDataPermit>()
                && !input.extensions().contains::<ForbidEarlyData>()
                && !quic.connection.is_handshake_confirmed();
            if !early {
                quic.connection
                    .handshake_confirmed()
                    .await
                    .into_opaque_error()?;
            }
            let alpn = quic
                .connection
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .and_then(|tls| tls.application_layer_protocol.clone());
            let policy = input
                .extensions()
                .get_ref::<AlpnPolicy>()
                .copied()
                .or_else(|| {
                    quic.connection
                        .extensions()
                        .get_ref::<AlpnPolicy>()
                        .copied()
                })
                .unwrap_or_default();
            if !early && !policy.accepts(&quic.config.application_protocol, alpn.as_ref()) {
                return Err(BoxError::from_static_str(
                    "QUIC transport did not negotiate the configured HTTP/3 ALPN",
                )
                .into_opaque_error());
            }
            // A rejected override must not mutate a transport already used by
            // another HTTP/3 service.
            quic.connection.extensions().insert(policy);
            let verify_peer = !early && alpn.is_none();
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            quic.connection
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            coalescing::restrict_reuse(input.extensions(), quic.connection.extensions());
            let mut config = Arc::unwrap_or_clone(quic.config);
            if let Some(max) = max_informational_responses {
                config.max_informational_responses = max;
            }
            if let Some(budget) = refused_stream_budget {
                config.refused_stream_budget = budget.0;
            }
            let conn =
                HttpClientService::http3(quic.connection, config, scope).into_opaque_error()?;
            if verify_peer && let SendRequest::Http3(sender) = &conn.sender {
                sender.peer_settings().await.into_opaque_error()?;
            }
            Ok(EstablishedClientConnection { input, conn })
        }
    }
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
async fn http_stream_connect<IO, Input, BodyConnection>(
    io: IO,
    input: Input,
    weak_scope: WeakScope,
    max_informational_responses: Option<usize>,
    refused_stream_budget: Option<RefusedStreamBudget>,
) -> Result<EstablishedClientConnection<HttpClientService<BodyConnection>, Input>, OpaqueError>
where
    IO: Io + Unpin + ExtensionsRef,
    Input: AuthorityInputExt
        + ProtocolInputExt
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
    // The transport holds the scope wherever it goes, an upgrade included, and is
    // cut at its hard phase. A closed scope admits no new connection.
    let scope = weak_scope.try_hold().into_opaque_error()?;
    let io = AbortableIo::new(&scope, io);
    // The connection runs in that scope too, so a pool drains it in its graceful phase.
    attach_scope(io.extensions(), &scope);
    let extensions = io.extensions().clone();
    let server_host = input.target_authority().map(|authority| authority.host);
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
            if !io.extensions().contains::<AltSvcObserverExtension>()
                && let Some(observer) = input.extensions().get_arc::<AltSvcObserverExtension>()
            {
                io.extensions().insert_arc(observer);
            }
            tracing::trace!("create h2 client");

            let mut builder = rama_http_core::client::conn::http2::Builder::new(weak_scope.clone());

            apply_h2_client_extensions_to_builder(&mut builder, input.extensions());
            if let Some(max) = max_informational_responses {
                builder.set_max_informational_responses(max);
            }
            if let Some(budget) = refused_stream_budget {
                builder.maybe_set_refused_stream_budget(budget.0);
            }

            let verify_peer = io
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .is_some_and(|tls| tls.application_layer_protocol.is_none());
            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
            let peer_settings = verify_peer.then(|| conn.peer_settings_handle());

            let conn_span = tracing::trace_root_span!(
                "h2::conn::serve",
                otel.kind = "client",
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(version),
                server.address = %server_address,
                server.service.name = %server_address,
            );

            scope.spawn_task(
                async move {
                    if let Err(err) = conn.await {
                        log_connection_termination(&err);
                    }
                }
                .instrument(conn_span),
            );

            // A completed TLS handshake without ALPN does not prove HTTP/2 support.
            // There is no built-in deadline; a caller-supplied connector timeout
            // must include this readiness check as well as the TLS handshake.
            if let Some(peer_settings) = peer_settings
                && peer_settings.await_settings().await.is_none()
            {
                return Err(
                    BoxError::from_static_str("peer closed before HTTP/2 SETTINGS")
                        .into_opaque_error(),
                );
            }

            // The pool admits by the streams actually open, as for HTTP/3.
            extensions.insert(sender.connection_admission());
            let svc = HttpClientService {
                sender: SendRequest::Http2(sender),
                extensions,
            };

            Ok(EstablishedClientConnection { input, conn: svc })
        }
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
            tracing::trace!("create ~h1 client");
            let mut builder = rama_http_core::client::conn::http1::Builder::new();
            if let Some(params) = input.extensions().get_ref::<Http1ClientContextParams>() {
                builder.set_title_case_headers(params.title_header_case);
            }
            if let Some(max) = max_informational_responses {
                builder.set_max_informational_responses(max);
            }
            let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
            let conn = conn.with_upgrades();
            // Lets a pooled connector drain abandoned response bodies on it.
            extensions.insert(Http1DrainRuntime::new(&weak_scope));

            let conn_span = tracing::trace_root_span!(
                "h1::conn::serve",
                otel.kind = "client",
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(version),
                server.address = %server_address,
                server.service.name = %server_address,
            );

            scope.spawn_task(
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
/// UA-emulation profiles flow through the eager path as well.
pub async fn http2_eager_handshake<IO, BodyConnection>(
    io: IO,
    weak_scope: WeakScope,
) -> Result<(HttpClientService<BodyConnection>, H2PeerSettingsHandle), OpaqueError>
where
    IO: Io + Unpin + ExtensionsRef,
    BodyConnection:
        StreamingBody<Data: Send + Sync + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    // As in `http_stream_connect`: held until the transport goes, cut at the hard phase, and
    // drained by a pool in the graceful phase.
    let scope = weak_scope.try_hold().into_opaque_error()?;
    let io = AbortableIo::new(&scope, io);
    attach_scope(io.extensions(), &scope);
    let extensions = io.extensions().clone();

    tracing::trace!("eager h2 client handshake");
    let mut builder = rama_http_core::client::conn::http2::Builder::new(weak_scope.clone());
    builder.set_observe_peer_settings(true);
    apply_h2_client_extensions_to_builder(&mut builder, &extensions);
    if let Some(max) = extensions.get_ref::<MaxInformationalResponses>() {
        builder.set_max_informational_responses(max.0);
    }
    if let Some(budget) = extensions.get_ref::<RefusedStreamBudget>() {
        builder.maybe_set_refused_stream_budget(budget.0);
    }
    let (sender, conn) = builder.handshake(io).await.into_opaque_error()?;
    let peer_handle = conn.peer_settings_handle();

    let conn_span = tracing::trace_root_span!(
        "h2::conn::serve",
        otel.kind = "client",
        network.protocol.name = "http",
        network.protocol.version = version_as_protocol_version(Version::HTTP_2),
    );

    scope.spawn_task(
        async move {
            if let Err(err) = conn.await {
                log_connection_termination(&err);
            }
        }
        .instrument(conn_span),
    );

    extensions.insert(sender.connection_admission());
    let svc = HttpClientService {
        sender: SendRequest::Http2(sender),
        extensions,
    };
    Ok((svc, peer_handle))
}

impl<S, Input, BodyConnection> Service<Input> for HttpConnector<S, BodyConnection>
where
    S: ConnectorService<Input, Connection: IntoHttpTransport>,
    Input: AuthorityInputExt
        + ProtocolInputExt
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
        // Reject impossible transports before DNS, TLS or socket work. The
        // transport type is authoritative; selection keeps no capability list.
        if required_transport_http_version(&input)
            .is_some_and(|version| !S::Connection::supports_http_version(version))
        {
            return Err(ConnectionError::local(
                BoxError::from_static_str("transport cannot carry the requested HTTP version"),
                ConnectionErrorKind::Unavailable,
            ));
        }

        // Boxed so that neither transport nor handshake grows every future wrapping this one.
        let EstablishedClientConnection { input, conn } =
            Box::pin(self.inner.connect(input)).await?;
        let version = resolve_target_http_version(&conn, &input);
        Box::pin(http_connect_with(
            conn,
            input,
            self.scope.clone(),
            self.max_informational_responses,
            self.refused_stream_budget,
        ))
        .await
        .map_err(|error| {
            if matches!(
                version,
                Some(
                    Version::HTTP_09
                        | Version::HTTP_10
                        | Version::HTTP_11
                        | Version::HTTP_2
                        | Version::HTTP_3
                )
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
    scope: WeakScope,
    max_informational_responses: Option<usize>,
    refused_stream_budget: Option<RefusedStreamBudget>,
    _phantom: PhantomData<Body>,
}

impl<Body> HttpConnectorLayer<Body> {
    /// Create a new [`HttpConnectorLayer`].
    #[must_use]
    pub const fn new(scope: WeakScope) -> Self {
        Self {
            scope,
            max_informational_responses: None,
            refused_stream_budget: None,
            _phantom: PhantomData,
        }
    }

    generate_set_and_with! {
        /// See [`HttpConnector::with_max_informational_responses`].
        pub fn max_informational_responses(mut self, max: Option<usize>) -> Self {
            self.max_informational_responses = max;
            self
        }
    }

    generate_set_and_with! {
        /// See [`HttpConnector::with_refused_stream_budget`].
        pub fn refused_stream_budget(mut self, budget: Option<RefusedStreamBudget>) -> Self {
            self.refused_stream_budget = budget;
            self
        }
    }
}

impl<Body> Default for HttpConnectorLayer<Body> {
    fn default() -> Self {
        Self::new(WeakScope::detached())
    }
}

impl<S, Body> Layer<S> for HttpConnectorLayer<Body> {
    type Service = HttpConnector<S, Body>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            scope: self.scope.clone(),
            max_informational_responses: self.max_informational_responses,
            refused_stream_budget: self.refused_stream_budget,
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            scope: self.scope,
            max_informational_responses: self.max_informational_responses,
            refused_stream_budget: self.refused_stream_budget,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "quic")]
mod http3_dispatch_tests {
    use super::*;
    use crate::client::Http3Transport;
    use rama_core::{ServiceInput, service::service_fn};
    use rama_http_types::Body;
    use rama_net::{
        Protocol as ApplicationProtocol,
        client::{ConnectRequest, ConnectionErrorDomain, ConnectorTarget, ProxyRoute},
        http::HttpRequestVersion,
    };
    use rama_tls::ProtocolVersion;
    use std::assert_matches;

    fn stream_connector_must_not_connect()
    -> impl ConnectorService<ConnectRequest, Connection = ServiceInput<tokio::io::DuplexStream>>
    {
        service_fn(
            async |_input: ConnectRequest| -> Result<
                EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, ConnectRequest>,
                ConnectionError,
            > {
                panic!("HTTP/3 must not dial the byte-stream connector");
            },
        )
    }

    #[tokio::test]
    async fn stream_only_connector_rejects_h3_before_dialing() {
        let connector = HttpConnector::<_, Body>::new(
            stream_connector_must_not_connect(),
            WeakScope::detached(),
        );
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let error = connector.connect(input).await.err().unwrap();
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn quic_only_connector_rejects_h2_before_dialing() {
        let connector = HttpConnector::<_, Body>::new(
            service_fn(
                async |_: ConnectRequest| -> Result<
                    EstablishedClientConnection<Http3Transport, ConnectRequest>,
                    ConnectionError,
                > {
                    panic!("HTTP/2 must not dial a QUIC-only connector");
                },
            ),
            WeakScope::detached(),
        );
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        let error = connector.connect(input).await.err().unwrap();
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn quic_only_connector_allows_implicit_input_versions() {
        let connector = HttpConnector::<_, Body>::new(
            service_fn(
                async |_: ConnectRequest| -> Result<
                    EstablishedClientConnection<Http3Transport, ConnectRequest>,
                    ConnectionError,
                > {
                    Err(ConnectionError::transport(
                        BoxError::from_static_str("reached QUIC connector"),
                        ConnectionErrorKind::Unavailable,
                    ))
                },
            ),
            WeakScope::detached(),
        );
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let input = ConnectRequest::new("origin.example:443".parse().unwrap());
            input.extensions().insert(HttpRequestVersion(version));
            let error = connector.connect(input).await.err().unwrap();
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert!(error.to_string().contains("reached QUIC connector"));
        }
    }

    #[derive(Debug)]
    struct FixedTransportPolicy;

    impl ConnectionReusePolicy for FixedTransportPolicy {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }
    }

    #[tokio::test]
    async fn secure_transport_requires_complete_endpoint_reuse_policy() {
        for protocol in [
            None,
            Some(ApplicationProtocol::HTTP),
            Some(ApplicationProtocol::HTTPS),
            Some(ApplicationProtocol::WS),
        ] {
            for negotiated in [false, true] {
                for complete in [None, Some(false), Some(true)] {
                    let (io, _peer) = tokio::io::duplex(4096);
                    let transport = ServiceInput::new(io);
                    if negotiated {
                        transport.extensions().insert(NegotiatedTlsParameters {
                            protocol_version: ProtocolVersion::TLSv1_3,
                            application_layer_protocol: None,
                            peer_certificate_chain: None,
                            server_name: None,
                            resumed: None,
                            algorithms: Default::default(),
                            server_hello: None,
                        });
                    }
                    if let Some(complete) = complete {
                        let policy = ConnectionReuse::new(FixedTransportPolicy);
                        transport.extensions().insert(if complete {
                            policy
                        } else {
                            policy.into_restriction()
                        });
                    }
                    let mut input = ConnectRequest::new("origin.example:443".parse().unwrap());
                    input.application_protocol = protocol.clone();
                    input
                        .extensions()
                        .insert(TargetHttpVersion(Version::HTTP_11));
                    let established =
                        http_connect::<_, _, Body>(transport, input, WeakScope::detached())
                            .await
                            .unwrap();
                    let reusable = established
                        .conn
                        .extensions()
                        .get_ref::<ConnectionReuse>()
                        .is_none_or(ConnectionReuse::is_reusable);
                    let plaintext = protocol
                        .as_ref()
                        .is_some_and(|protocol| !protocol.is_secure());
                    assert_eq!(
                        reusable,
                        complete == Some(true)
                            || (plaintext && (!negotiated || complete.is_some())),
                        "protocol={protocol:?}, negotiated={negotiated}, complete={complete:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn common_handshake_honors_fallback_before_request_http3() {
        let (io, _peer) = tokio::io::duplex(4096);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input
            .extensions
            .insert(rama_net::http::HttpRequestVersion(Version::HTTP_3));
        input
            .extensions
            .insert(FallbackHttpVersion(Version::HTTP_2));
        let established =
            http_connect::<_, _, Body>(ServiceInput::new(io), input, WeakScope::detached())
                .await
                .unwrap();
        assert_eq!(
            established.input.target_http_version(),
            Some(Version::HTTP_2)
        );
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|version| version.0),
            Some(Version::HTTP_2)
        );
    }

    #[tokio::test]
    async fn common_handshake_rejects_http3_on_a_byte_stream() {
        // Direct callers bypass connector preflight, so the established
        // transport must still be checked before starting HTTP.
        let (io, _peer) = tokio::io::duplex(64);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let error = http_connect::<_, _, Body>(ServiceInput::new(io), input, WeakScope::detached())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unsupported Http version"));
    }

    #[tokio::test]
    async fn http1_and_http2_use_stream_connector() {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let stream_connector = service_fn(move |input: ConnectRequest| async move {
                assert_eq!(
                    input.extensions().get_ref::<TargetHttpVersion>().unwrap().0,
                    version
                );
                Err::<
                    EstablishedClientConnection<
                        ServiceInput<tokio::io::DuplexStream>,
                        ConnectRequest,
                    >,
                    _,
                >(ConnectionError::application(
                    BoxError::from_static_str("byte-stream connector reached"),
                    ConnectionErrorKind::Rejected,
                ))
            });
            let http3 = service_fn(
                async |_input: ConnectRequest| -> Result<
                    EstablishedClientConnection<crate::client::Http3Transport, ConnectRequest>,
                    ConnectionError,
                > {
                    panic!("HTTP/1 and HTTP/2 must not use the HTTP/3 transport");
                },
            );
            let connector = HttpConnector::<_, Body>::new(stream_connector, WeakScope::detached())
                .with_http3_connector(http3);
            let input = ConnectRequest::new("origin.example:443".parse().unwrap());
            input.extensions().insert(TargetHttpVersion(version));
            let error = connector.serve(input).await.err().unwrap();
            assert_eq!(error.kind(), ConnectionErrorKind::Rejected);
        }
    }

    #[tokio::test]
    async fn custom_http3_owns_route_capability_and_preserves_origin_and_target() {
        let http3 = service_fn(
            async |input: ConnectRequest| -> Result<
                EstablishedClientConnection<crate::client::Http3Transport, ConnectRequest>,
                ConnectionError,
            > {
                assert_eq!(input.authority.to_string(), "origin.example:443");
                assert_eq!(input.application_protocol, Some(ApplicationProtocol::HTTPS));
                assert_eq!(
                    input
                        .extensions()
                        .get_ref::<ConnectorTarget>()
                        .unwrap()
                        .0
                        .to_string(),
                    "alternative.example:8443"
                );
                assert_matches!(
                    input.extensions().get_ref::<ProxyRoute>(),
                    Some(ProxyRoute::Proxy(_)),
                );
                Err(ConnectionError::application(
                    BoxError::from_static_str("custom transport reached"),
                    ConnectionErrorKind::Rejected,
                ))
            },
        );
        let connector = HttpConnector::<_, Body>::new(
            stream_connector_must_not_connect(),
            WeakScope::detached(),
        )
        .with_http3_connector(http3);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(ApplicationProtocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input
            .extensions()
            .insert(ConnectorTarget("alternative.example:8443".parse().unwrap()));
        input.extensions().insert(ProxyRoute::Proxy(
            "http://proxy.example:8080".parse().unwrap(),
        ));
        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::Rejected);
    }
}

#[cfg(test)]
mod h2_client_params_tests {
    use super::*;
    use rama_core::ServiceInput;
    use rama_http_core::client::conn::http2::Builder as H2ClientBuilder;
    use rama_http_types::{
        Body,
        proto::h2::frame::{Setting, SettingId, Settings},
    };
    use rama_net::client::ConnectRequest;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, DuplexStream};

    const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;

    /// The entries of the first non-ACK SETTINGS frame a client writes after its preface.
    async fn client_settings(peer: &mut DuplexStream) -> Vec<(u16, u32)> {
        let mut preface = [0u8; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        loop {
            let mut head = [0u8; 9];
            peer.read_exact(&mut head).await.unwrap();
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut payload = vec![0u8; len];
            peer.read_exact(&mut payload).await.unwrap();
            if head[3] == 0x4 && (head[4] & 0x1) == 0 {
                return payload
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|[a, b, c, d, e, f]| {
                        (
                            u16::from_be_bytes([*a, *b]),
                            u32::from_be_bytes([*c, *d, *e, *f]),
                        )
                    })
                    .collect();
            }
        }
    }

    #[tokio::test]
    async fn header_table_size_param_is_advertised_in_the_client_settings() {
        for header_table_size in [None, Some(8_192)] {
            let (io, mut peer) = tokio::io::duplex(4096);
            let input = ConnectRequest::new("origin.example:443".parse().unwrap());
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            input.extensions().insert(H2ClientContextParams {
                header_table_size,
                ..Default::default()
            });
            let established =
                http_connect::<_, _, Body>(ServiceInput::new(io), input, WeakScope::detached())
                    .await
                    .unwrap();

            let advertised =
                tokio::time::timeout(Duration::from_secs(2), client_settings(&mut peer))
                    .await
                    .expect("the client writes its SETTINGS without waiting for the server")
                    .into_iter()
                    .find_map(|(id, value)| (id == SETTINGS_HEADER_TABLE_SIZE).then_some(value));
            assert_eq!(advertised, header_table_size);
            drop(established);
        }
    }

    #[tokio::test]
    async fn unrelated_context_preserves_the_base_builder_literal_settings() {
        let (io, mut peer) = tokio::io::duplex(4096);
        let literal = Arc::new(
            Settings::from_ordered_entries(
                vec![
                    Setting {
                        id: SettingId::MaxHeaderListSize,
                        value: 131072,
                    },
                    Setting {
                        id: SettingId::HeaderTableSize,
                        value: 8192,
                    },
                ]
                .into_boxed_slice(),
            )
            .unwrap(),
        );
        let mut builder =
            H2ClientBuilder::new(WeakScope::detached()).with_initial_settings(literal);
        let extensions = Extensions::new();
        extensions.insert(H2ClientContextParams {
            keep_alive_timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        });
        apply_h2_client_extensions_to_builder(&mut builder, &extensions);
        let task = tokio::spawn(async move {
            let (_sender, connection) = builder
                .handshake::<_, Body>(ServiceInput::new(io))
                .await
                .unwrap();
            connection.await.unwrap();
        });
        let emitted = tokio::time::timeout(Duration::from_secs(2), client_settings(&mut peer))
            .await
            .unwrap();
        assert_eq!(emitted, [(6, 131072), (1, 8192)]);
        task.abort();
    }
}
