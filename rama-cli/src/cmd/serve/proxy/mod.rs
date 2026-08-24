//! Multi-protocol forward proxy with optional Relay/Peek MITM inspection.

mod capture;
mod dashboard;
mod dashboard_auth;
mod har;
mod inspection;
mod mitm_policy;
mod portal;
mod upstream;

use capture::{
    CaptureHttpLayer, CaptureStore, CaptureWebSocketLayer, ConnectionId, ExchangeId,
    MarkProtocolLayer, ObserveConnectionLayer,
};
use clap::{Args, ValueEnum};
use dashboard::DashboardState;
use dashboard_auth::DashboardAuthService;
use har::HarController;
use inspection::{InspectionPermit, InspectionState};
use mitm_policy::MitmPolicy;
use portal::PortalService;
use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef as _,
    graceful::ShutdownGuard,
    http::{
        BodyLimitLayer, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            har::layer::HARExportLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{
                EagerHttpProxyConnector, LazyHttpProxyConnectReplyService, UpgradeLayer,
                mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::{DomainMatcher, MethodMatcher},
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        service::web::response::IntoResponse,
        ws::{
            handshake::{
                matcher::HttpWebSocketRelayServiceRequestMatcher,
                mitm::{
                    WebSocketRelayEvent, WebSocketRelayEventInput, WebSocketRelayEventOutput,
                    WebSocketRelayEventService, WebSocketRelayInjector, WebSocketRelayIoLayer,
                    WebSocketRelayMessage,
                },
            },
            layer::har::HARWebSocketLayer,
        },
    },
    layer::{
        ArcLayer, ConsumeErrLayer, HijackLayer, LimitLayer, MapOutputLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RatePolicy, UnlimitedPolicy},
    },
    net::{
        address::{Authority, AuthorityRef, Domain, ProxyAddress, SocketAddress},
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        stream::layer::{TcpStreamOptionsLayer, ThrottleLayer, ThrottleMode},
    },
    proxy::socks5::{
        Socks5Acceptor,
        server::{Connector as Socks5Connector, Socks5PeekRouter},
    },
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing,
    tls::{
        boring::{proxy::TlsMitmRelay, server::TlsAcceptorService},
        server::{
            CertificateSubject, GeneratedServerAuthConfig, InputWithClientHello, LeafCertRequest,
            PeekTlsClientHelloService, SelfSignedCaConfig, ServerAuthData, TlsPeekRouter,
            TlsServerConfig,
        },
    },
    ua::profile::UserAgentDatabase,
    utils::octets::mib_u64,
};
use std::{
    collections::BTreeSet, convert::Infallible, future::Future as _, path::PathBuf, sync::Arc,
    task::Poll, time::Duration,
};
use upstream::UpstreamProxyConfig;

use crate::utils::rate::opt_per_sec;

const DEFAULT_CAPTURE_BODY_LIMIT: u64 = mib_u64(8);
const DEFAULT_CAPTURE_TOTAL_LIMIT: u64 = mib_u64(512);
const MITM_PORTAL_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");
#[cfg(test)]
const TEST_DASHBOARD_TOKEN: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEFAULT_TCP_KEEPALIVE_IDLE_SECS: u64 = 15;
const DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS: u64 = 5;
const DEFAULT_TCP_KEEPALIVE_PROBES: u32 = 3;

fn default_bind() -> SocketAddress {
    SocketAddress::local_ipv4(8080)
}

fn bind_addresses_overlap(left: std::net::SocketAddr, right: std::net::SocketAddr) -> bool {
    let left_ip = left.ip();
    let right_ip = right.ip();
    left.port() == right.port()
        && left_ip.is_ipv4() == right_ip.is_ipv4()
        && (left_ip == right_ip || left_ip.is_unspecified() || right_ip.is_unspecified())
}

#[derive(Debug, Clone)]
struct MitmTargetPolicyService<I, P> {
    inspect: I,
    passthrough: P,
    policy: MitmPolicy,
    inspection: InspectionState,
    defer_ip_target: bool,
}

impl<I, P, IO> Service<IO> for MitmTargetPolicyService<I, P>
where
    IO: rama::extensions::ExtensionsRef + Send + 'static,
    I: Service<IO, Output = ()>,
    I::Error: Into<BoxError>,
    P: Service<IO, Output = ()>,
    P::Error: Into<BoxError>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: IO) -> Result<(), BoxError> {
        let should_inspect = if self.defer_ip_target {
            self.policy.should_peek_target(input.extensions())
        } else {
            self.policy.should_inspect_target(input.extensions())
        };
        if !should_inspect {
            self.passthrough.serve(input).await.map_err(Into::into)
        } else if let Some(permit) = self.inspection.try_capture() {
            serve_with_inspection_permit(&self.inspect, input, permit)
                .await
                .map_err(Into::into)
        } else {
            self.passthrough.serve(input).await.map_err(Into::into)
        }
    }
}

#[derive(Debug, Clone)]
struct TlsHelloMitmPolicyService<I, P> {
    inspect: I,
    passthrough: P,
    policy: MitmPolicy,
    inspection: InspectionState,
}

impl<I, P, IO> Service<InputWithClientHello<IO>> for TlsHelloMitmPolicyService<I, P>
where
    IO: rama::extensions::ExtensionsRef + Send + 'static,
    I: Service<InputWithClientHello<IO>, Output = ()>,
    I::Error: Into<BoxError>,
    P: Service<IO, Output = ()>,
    P::Error: Into<BoxError>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: InputWithClientHello<IO>) -> Result<(), BoxError> {
        let sni = input
            .client_hello
            .ext_server_name()
            .cloned()
            .map(rama::net::address::Host::Name);
        let should_inspect = self
            .policy
            .should_inspect_target_and_host(input.input.extensions(), sni.as_ref());
        if !should_inspect {
            self.passthrough
                .serve(input.input)
                .await
                .map_err(Into::into)
        } else if let Some(permit) = self.inspection.try_capture() {
            serve_with_inspection_permit(&self.inspect, input, permit)
                .await
                .map_err(Into::into)
        } else {
            self.passthrough
                .serve(input.input)
                .await
                .map_err(Into::into)
        }
    }
}

/// Poll an inspection service once before releasing its routing permit.
///
/// This makes a completed pause a classification boundary without retaining a
/// permit for the lifetime of an already-established tunnel or WebSocket.
async fn serve_with_inspection_permit<S, Input>(
    service: &S,
    input: Input,
    permit: InspectionPermit,
) -> Result<S::Output, S::Error>
where
    S: Service<Input>,
{
    let future = service.serve(input);
    tokio::pin!(future);
    let ready = std::future::poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Ready(result) => Poll::Ready(Some(result)),
        Poll::Pending => Poll::Ready(None),
    })
    .await;
    drop(permit);
    match ready {
        Some(result) => result,
        None => future.await,
    }
}

#[derive(Debug, Clone)]
struct MitmPortalMatcher {
    domain: DomainMatcher,
    inspection: InspectionState,
    policy: MitmPolicy,
    connect_only: bool,
}

impl MitmPortalMatcher {
    fn http(inspection: InspectionState, policy: MitmPolicy) -> Self {
        Self {
            domain: DomainMatcher::exact(MITM_PORTAL_DOMAIN),
            inspection,
            policy,
            connect_only: false,
        }
    }

    fn connect(inspection: InspectionState, policy: MitmPolicy) -> Self {
        Self {
            connect_only: true,
            ..Self::http(inspection, policy)
        }
    }
}

impl<Body> rama::matcher::Matcher<Request<Body>> for MitmPortalMatcher {
    fn matches(
        &self,
        extensions: Option<&rama::extensions::Extensions>,
        request: &Request<Body>,
    ) -> bool {
        self.inspection.is_enabled()
            && !self
                .policy
                .is_denied(&rama::net::address::Host::Name(MITM_PORTAL_DOMAIN))
            && (!self.connect_only || request.method() == rama::http::Method::CONNECT)
            && self.domain.matches(extensions, request)
    }
}

macro_rules! build_mitm_service {
    ($exec:expr, $capture:expr, $inspection:expr, $har:expr, $portal:expr, $certificate:expr, $private_key:expr, $peek_timeout:expr, $mitm_policy:expr) => {{
        let capture = $capture;
        let inspection = $inspection;
        let har = $har;
        let exec = $exec;
        let portal = $portal;
        let peek_timeout = $peek_timeout;
        let mitm_policy = $mitm_policy;
        let websocket_relay = WebSocketRelayIoLayer::new().into_layer(
            CaptureWebSocketLayer::new(Some(capture.clone())).into_layer(
                HARWebSocketLayer::new().into_layer(
                    WebSocketRelayEventService::new(service_fn({
                        let capture = capture.clone();
                        move |input| inspect_websocket_event(Some(capture.clone()), input)
                    }))
                    .with_message_injection(true),
                ),
            ),
        );
        let websocket_layer = HttpUpgradeMitmRelayLayer::new(
            exec.clone(),
            HttpWebSocketRelayServiceRequestMatcher::new(websocket_relay),
        );
        let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
            ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
            MapResponseBodyLayer::new_boxed_streaming_body(),
            StreamCompressionLayer::new()
                .with_compress_predicate(MirrorDecompressed::new())
                .with_enforce_not_acceptable(false),
            HijackLayer::new(
                MitmPortalMatcher::http(inspection.clone(), mitm_policy.clone()),
                portal,
            ),
            CaptureHttpLayer::new(Some(capture)),
            websocket_layer,
            HARExportLayer::new(har.clone(), har),
            DecompressionLayer::new()
                .with_insert_accept_encoding_header(false)
                .with_tolerate_decode_errors(true),
            ArcLayer::new(),
        ));
        let maybe_http = HttpPeekRouter::new(http_mitm_relay)
            .with_known_non_http_protocol_methods()
            .maybe_with_peek_timeout(peek_timeout)
            .with_fallback(
                MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
            );
        let passthrough = ConsumeErrLayer::trace_as_debug()
            .into_layer(MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())));
        let non_tls = MitmTargetPolicyService {
            inspect: maybe_http.clone(),
            passthrough: passthrough.clone(),
            policy: mitm_policy.clone(),
            inspection: inspection.clone(),
            defer_ip_target: false,
        };
        let tls = TlsMitmRelay::new_cached_in_memory($certificate, $private_key);
        let tls = TlsHelloMitmPolicyService {
            inspect: tls.into_layer(maybe_http.clone()),
            passthrough: passthrough.clone(),
            policy: mitm_policy.clone(),
            inspection: inspection.clone(),
        };
        let application = PeekTlsClientHelloService::new(tls)
            .maybe_with_peek_timeout(peek_timeout)
            .with_fallback(non_tls);
        let inspect = ConsumeErrLayer::trace_as_debug().into_layer(application);
        Arc::new(MitmTargetPolicyService {
            inspect,
            passthrough,
            policy: mitm_policy,
            inspection,
            defer_ip_target: true,
        })
    }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ProxyProtocol {
    /// Plain HTTP forward proxy, including CONNECT tunnels.
    Http,
    /// HTTP forward proxy carried over TLS.
    Https,
    /// SOCKS5 and SOCKS5H CONNECT proxy.
    Socks5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MitmBindAddress {
    Inherit,
    Explicit(SocketAddress),
}

impl std::str::FromStr for MitmBindAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "inherit" {
            Ok(Self::Inherit)
        } else {
            value
                .parse()
                .map(Self::Explicit)
                .map_err(|error| format!("invalid MITM inspector bind address: {error}"))
        }
    }
}

#[derive(Debug, Args)]
/// Multi-protocol Rama proxy server.
pub struct CliCommandProxy {
    /// Shared proxy bind address. Defaults to 127.0.0.1:8080 when no
    /// protocol-specific bind is supplied.
    #[arg(long)]
    bind: Option<SocketAddress>,

    /// Protocols served on --bind; comma-separated values share one peeking
    /// listener.
    #[arg(long, value_enum, value_delimiter = ',', default_value = "http")]
    protocol: Vec<ProxyProtocol>,

    /// Additional HTTP proxy bind. Repeat to use multiple listeners.
    #[arg(long)]
    http_bind: Vec<SocketAddress>,

    /// Additional HTTPS (HTTP-over-TLS) proxy bind. Repeat to use multiple
    /// listeners.
    #[arg(long)]
    https_bind: Vec<SocketAddress>,

    /// Additional SOCKS5/SOCKS5H bind. Repeat to use multiple listeners.
    #[arg(long)]
    socks5_bind: Vec<SocketAddress>,

    /// Enable MITM inspection and its live web UI. With no value, the UI
    /// inherits the effective shared proxy bind; use --mitm=IP:PORT to
    /// override it.
    #[arg(
        long,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "inherit"
    )]
    mitm: Option<MitmBindAddress>,

    /// Write the ephemeral MITM CA certificate in PEM form so clients can
    /// trust it. The same certificate is downloadable from the web UI.
    #[arg(long, requires = "mitm")]
    mitm_ca_cert: Option<PathBuf>,

    /// Maximum body bytes retained per request and response in encrypted
    /// capture storage. Traffic continues streaming after this limit.
    #[arg(long, default_value_t = DEFAULT_CAPTURE_BODY_LIMIT)]
    capture_body_limit: u64,

    /// Maximum encrypted capture bytes retained across all connections (0 =
    /// no aggregate limit). Traffic continues without capture when full.
    #[arg(long, default_value_t = DEFAULT_CAPTURE_TOTAL_LIMIT)]
    capture_total_limit: u64,

    /// Maximum connections kept in the live inspector.
    #[arg(long, default_value_t = 10_000)]
    capture_connections: usize,

    /// Maximum HTTP exchanges retained in the live inspector.
    #[arg(long, default_value_t = 10_000)]
    capture_exchanges: usize,

    /// Maximum messages captured per WebSocket exchange.
    #[arg(long, default_value_t = 10_000)]
    capture_websocket_messages: usize,

    /// Maximum time spent classifying shared-port protocols (0 = no timeout).
    #[arg(long, default_value_t = 5_000)]
    peek_timeout_ms: u64,

    /// Maximum HTTP request body size accepted by the proxy (0 = no limit).
    #[arg(long, default_value_t = 0)]
    body_limit: usize,

    /// Number of concurrent connections to allow (0 = no limit).
    #[arg(long, short = 'c', default_value_t = 0)]
    concurrent: usize,

    /// Maximum lifetime in seconds for each proxy connection (0 = no timeout).
    /// Disabled by default so long-lived WebSocket and inspector streams remain
    /// persistent.
    #[arg(long, short = 't', default_value_t = 0)]
    timeout: u64,

    /// Timeout in seconds for establishing an egress connection (0 = no
    /// timeout).
    #[arg(long, default_value_t = 30)]
    connect_timeout: u64,

    /// Rate-limit new connections per second (0 = no limit).
    #[arg(long, default_value_t = 0)]
    rate: u64,

    /// Throttle each connection at this byte rate in both directions (0 = no
    /// throttling).
    #[arg(long, default_value_t = 0)]
    throttle: u64,

    /// Acknowledge HTTP CONNECT before establishing the egress connection.
    #[arg(long, default_value_t = false)]
    lazy_connect: bool,

    /// Route egress through this HTTP, HTTPS, SOCKS5, or SOCKS5H proxy.
    #[arg(long, conflicts_with = "system_proxy")]
    upstream_proxy: Option<ProxyAddress>,

    /// Respect the operating system proxy configuration, including PAC and
    /// native bypass rules.
    #[arg(long, default_value_t = false)]
    system_proxy: bool,

    /// Destination rules that bypass --upstream-proxy or --system-proxy.
    /// Repeat the flag or supply comma-separated NO_PROXY-style rules.
    #[arg(long, value_delimiter = ',')]
    proxy_bypass: Vec<String>,

    /// Domain rules eligible for TLS interception. Once supplied, unmatched
    /// domains pass through. Browser policy can narrow but not widen this CLI
    /// scope. Plain domains include subdomains; globs work too.
    #[arg(long, value_delimiter = ',', requires = "mitm")]
    mitm_allow: Vec<String>,

    /// Domain rules that must pass through without TLS interception. Deny
    /// rules override allow rules.
    #[arg(long, value_delimiter = ',', requires = "mitm")]
    mitm_deny: Vec<String>,

    /// Disable Nagle on ingress and egress sockets. Use
    /// --tcp-no-delay=false to opt back into Nagle coalescing.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    tcp_no_delay: bool,

    /// Enable TCP keepalive on ingress and egress sockets.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    tcp_keepalive: bool,

    /// Idle seconds before the first TCP keepalive probe.
    #[arg(long, default_value_t = DEFAULT_TCP_KEEPALIVE_IDLE_SECS)]
    tcp_keepalive_idle: u64,

    /// Seconds between TCP keepalive probes where supported.
    #[arg(long, default_value_t = DEFAULT_TCP_KEEPALIVE_INTERVAL_SECS)]
    tcp_keepalive_interval: u64,

    /// Failed TCP keepalive probes before disconnect where supported.
    #[arg(long, default_value_t = DEFAULT_TCP_KEEPALIVE_PROBES)]
    tcp_keepalive_probes: u32,

    /// TCP receive buffer bytes for ingress and egress (0 = OS autotuning).
    #[arg(long, default_value_t = 0)]
    tcp_recv_buffer: usize,

    /// TCP send buffer bytes for ingress and egress (0 = OS autotuning).
    #[arg(long, default_value_t = 0)]
    tcp_send_buffer: usize,
}

fn mitm_ca_config() -> SelfSignedCaConfig {
    SelfSignedCaConfig {
        subject: CertificateSubject {
            organisation_name: Some("Rama Proxy Inspector".to_owned()),
            common_name: Some("Rama ephemeral MITM CA".to_owned()),
        },
        ..Default::default()
    }
}

fn mitm_portal_tls_config(
    ca_certificate: &rama::tls::boring::core::x509::X509,
    ca_private_key: &rama::tls::boring::core::pkey::PKey<rama::tls::boring::core::pkey::Private>,
) -> Result<TlsServerConfig, BoxError> {
    use rama::crypto::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let (certificate, private_key) = rama::crypto::cert::boring::issue_leaf_certificate(
        &LeafCertRequest::new(MITM_PORTAL_DOMAIN),
        ca_certificate,
        ca_private_key,
    )
    .context("issue MITM portal certificate")?;
    let certificate_chain = vec![
        CertificateDer::from(
            certificate
                .to_der()
                .context("encode MITM portal certificate")?,
        ),
        CertificateDer::from(
            ca_certificate
                .to_der()
                .context("encode MITM portal CA certificate")?,
        ),
    ];
    let private_key = PrivatePkcs8KeyDer::from(
        private_key
            .private_key_to_der_pkcs8()
            .context("encode MITM portal private key")?,
    )
    .into();
    Ok(TlsServerConfig::new()
        .with_server_auth(ServerAuthData::new(certificate_chain, private_key))
        .with_alpn_http_auto())
}

/// Run the Rama proxy service.
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandProxy) -> Result<(), BoxError> {
    run_with_dashboard_token(graceful, cfg, None).await
}

async fn run_with_dashboard_token(
    graceful: ShutdownGuard,
    cfg: CliCommandProxy,
    dashboard_token_override: Option<Arc<str>>,
) -> Result<(), BoxError> {
    #[cfg(test)]
    let dashboard_token_override =
        dashboard_token_override.or_else(|| Some(Arc::from(TEST_DASHBOARD_TOKEN)));
    let exec = Executor::graceful(graceful);
    let listeners = resolve_listeners(&cfg);
    let requested_mitm_address = resolve_mitm_address(&cfg, &listeners);
    let inherited_mitm_listener =
        inherited_mitm_listener_index(&cfg, &listeners, requested_mitm_address);
    let mitm_enabled = requested_mitm_address.is_some();
    let tcp_options = tcp_socket_options(&cfg);
    let upstream = UpstreamProxyConfig::new(
        cfg.upstream_proxy.clone(),
        cfg.system_proxy,
        &cfg.proxy_bypass,
    )?;
    let mitm_policy = MitmPolicy::try_new(&cfg.mitm_allow, &cfg.mitm_deny)?;
    let inspection = InspectionState::default();
    let peek_timeout =
        (cfg.peek_timeout_ms > 0).then(|| Duration::from_millis(cfg.peek_timeout_ms));

    let ua_db = mitm_enabled
        .then(|| UserAgentDatabase::try_embedded().context("load embedded user-agent profiles"))
        .transpose()?
        .map(Arc::new);
    let capture = ua_db
        .as_ref()
        .map(|ua_db| {
            CaptureStore::new_with_inspection(
                cfg.capture_connections,
                cfg.capture_exchanges,
                cfg.capture_websocket_messages,
                cfg.capture_body_limit,
                cfg.capture_total_limit,
                ua_db.clone(),
                inspection.clone(),
            )
        })
        .transpose()?;
    let har = HarController::default();

    let ca = if mitm_enabled {
        let config = mitm_ca_config();
        Some(
            rama::crypto::cert::boring::generate_certificate_authority_x509(&config)
                .context("generate ephemeral MITM certificate authority")?,
        )
    } else {
        None
    };
    let ca_pem = match &ca {
        Some((certificate, _)) => certificate.to_pem().context("encode MITM CA as PEM")?,
        None => Vec::new(),
    };
    if mitm_enabled {
        let fingerprint = portal::ca_sha256_fingerprint(&ca_pem)?;
        tracing::info!(
            ca.sha256_fingerprint = %fingerprint,
            "MITM CA SHA-256 fingerprint: {fingerprint}"
        );
    }
    let portal_tls_config = ca
        .as_ref()
        .map(|(certificate, private_key)| mitm_portal_tls_config(certificate, private_key))
        .transpose()?;
    let portal = mitm_enabled.then(|| portal::service(ca_pem.clone()));
    if let Some(path) = &cfg.mitm_ca_cert {
        write_new_file(path, &ca_pem)
            .await
            .context("write MITM CA certificate")?;
        tracing::info!(path = %path.display(), "wrote ephemeral MITM CA certificate");
    }

    let dashboard_auth_token = capture
        .as_ref()
        .map(|_| {
            dashboard_token_override
                .clone()
                .map(Ok)
                .unwrap_or_else(dashboard_auth::generate_token)
        })
        .transpose()?;
    let dashboard = match (&capture, &ua_db, &dashboard_auth_token) {
        (Some(capture), Some(_), Some(token)) => Some(DashboardAuthService::new(
            dashboard::service(DashboardState::new(
                capture.clone(),
                har.clone(),
                ca_pem,
                tcp_options.clone(),
                upstream.clone(),
                mitm_policy.clone(),
            )),
            token.clone(),
        )),
        _ => None,
    };

    let needs_https = listeners
        .iter()
        .map(|(_, protocols)| protocols)
        .any(|protocols| protocols.contains(&ProxyProtocol::Https));
    let https_config = needs_https
        .then(|| {
            TlsServerConfig::new()
                .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                .map(|config| config.with_alpn_http_auto())
        })
        .transpose()
        .context("generate HTTPS proxy server certificate")?;

    let mut bound = Vec::with_capacity(listeners.len());
    for (address, protocols) in listeners {
        let listener = TcpListener::build(exec.clone())
            .bind_address(address)
            .await
            .with_context(|| format!("bind proxy listener {address}"))?;
        let local_address = listener
            .local_addr()
            .context("get proxy listener local address")?;
        bound.push((listener, local_address, protocols));
    }

    let mitm_address = resolve_bound_mitm_address(
        requested_mitm_address,
        inherited_mitm_listener,
        &bound
            .iter()
            .map(|(_, address, _)| *address)
            .collect::<Vec<_>>(),
    );

    if let (Some(ui_address), Some(dashboard), Some(auth_token)) = (
        mitm_address,
        dashboard.clone(),
        dashboard_auth_token.clone(),
    ) && !bound
        .iter()
        .any(|(_, address, _)| bind_addresses_overlap(*address, ui_address.into()))
    {
        let listener = TcpListener::build(exec.clone())
            .bind_address(ui_address)
            .await
            .context("bind MITM inspector web UI")?;
        let local_address = listener
            .local_addr()
            .context("get MITM inspector local address")?;
        tracing::info!(
            network.local.address = %local_address.ip(),
            network.local.port = %local_address.port(),
            "MITM inspector ready: http://{local_address}/?token={auth_token}"
        );
        let dashboard = standalone_dashboard_service(dashboard, local_address.into());
        let ui_exec = exec.clone();
        let ui_tcp_options = tcp_options.clone();
        exec.clone().into_spawn_task(async move {
            listener
                .serve(
                    TcpStreamOptionsLayer::new(ui_tcp_options)
                        .into_layer(HttpServer::auto(ui_exec).service(dashboard)),
                )
                .await;
        });
    }

    for (listener, local_address, protocols) in bound {
        let http_enabled = protocols.contains(&ProxyProtocol::Http);
        let https_enabled = protocols.contains(&ProxyProtocol::Https);
        let socks5_enabled = protocols.contains(&ProxyProtocol::Socks5);
        let dashboard_here = mitm_address
            .is_some_and(|address| bind_addresses_overlap(address.into(), local_address));
        let plain_http_route = http_enabled || dashboard_here;
        let proxy_client = new_proxy_client(ProxyClientConfig {
            exec: exec.clone(),
            capture: capture.clone(),
            inspection: inspection.clone(),
            har: har.clone(),
            portal: portal.clone(),
            tcp_options: tcp_options.clone(),
            connect_timeout: (cfg.connect_timeout > 0)
                .then(|| Duration::from_secs(cfg.connect_timeout)),
            mitm_policy: mitm_policy.clone(),
            upstream: upstream.clone(),
        });

        let plain_handler = proxy_request_dispatcher(
            proxy_client.clone(),
            dashboard_here.then(|| dashboard.clone()).flatten(),
            dashboard_here.then_some(mitm_address).flatten(),
            http_enabled,
        );
        let tls_handler = proxy_request_dispatcher(
            proxy_client,
            None::<DashboardAuthService<dashboard::DashboardService>>,
            None,
            https_enabled,
        );

        let http_bridge = match (&capture, &ca, &portal) {
            (Some(capture), Some((certificate, private_key)), Some(portal)) => {
                Either::A(build_mitm_service!(
                    exec.clone(),
                    capture.clone(),
                    inspection.clone(),
                    har.clone(),
                    portal.clone(),
                    certificate.clone(),
                    private_key.clone(),
                    peek_timeout,
                    mitm_policy.clone()
                ))
            }
            _ => Either::B(ConsumeErrLayer::trace_as_debug().into_layer(
                MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
            )),
        };
        let make_egress_connector = || {
            let connector = EasyHttpWebClient::connector_builder()
                .with_custom_transport_connector(
                    rama::tcp::client::service::TcpConnector::new()
                        .with_connector(tcp_options.clone()),
                )
                .with_default_dns_connector()
                .with_tls_proxy_support_using_boringssl()
                .with_proxy_support()
                .build_connector();
            let connector = upstream.connector_service(connector);
            (cfg.connect_timeout > 0)
                .then(|| TimeoutLayer::new(Duration::from_secs(cfg.connect_timeout)))
                .into_layer(connector)
        };
        let make_upgrade = || {
            let connector = make_egress_connector();
            let generic = if cfg.lazy_connect {
                Either::A(UpgradeLayer::new_with_services(
                    exec.clone(),
                    MethodMatcher::CONNECT,
                    LazyHttpProxyConnectReplyService::new(),
                    IoToProxyBridgeIoLayer::extension_connector_target()
                        .with_connector(connector)
                        .into_layer(http_bridge.clone()),
                ))
            } else {
                Either::B(UpgradeLayer::new(
                    exec.clone(),
                    MethodMatcher::CONNECT,
                    EagerHttpProxyConnector::new(connector, http_bridge.clone()),
                ))
            };
            let portal =
                portal_tls_config
                    .clone()
                    .zip(portal.clone())
                    .map(|(tls_config, portal)| {
                        UpgradeLayer::new_with_services(
                            exec.clone(),
                            MitmPortalMatcher::connect(inspection.clone(), mitm_policy.clone()),
                            LazyHttpProxyConnectReplyService::new(),
                            TlsAcceptorService::new(
                                tls_config,
                                HttpServer::auto(exec.clone()).service(portal),
                                true,
                            ),
                        )
                    });
            (portal, generic)
        };

        let plain_http_service = (
            TraceLayer::new_for_http(),
            if http_enabled {
                Some(make_upgrade())
            } else {
                None
            },
        )
            .into_layer(plain_handler);
        let plain_http_service = classify_http_connection(
            plain_http_service,
            dashboard_here.then_some(mitm_address).flatten(),
            http_enabled,
            capture.clone(),
        );
        let plain_http = HttpServer::auto(exec.clone()).service(Arc::new(plain_http_service));
        let tls_http_service = (TraceLayer::new_for_http(), make_upgrade()).into_layer(tls_handler);
        let tls_http_service =
            classify_http_connection(tls_http_service, None, https_enabled, capture.clone());
        let tls_http = HttpServer::auto(exec.clone()).service(Arc::new(tls_http_service));
        let tls_acceptor = TlsAcceptorService::new(
            https_config.clone().unwrap_or_else(TlsServerConfig::new),
            tls_http,
            true,
        );

        let socks_bridge = match (&capture, &ca, &portal) {
            (Some(capture), Some((certificate, private_key)), Some(portal)) => {
                Either::A(build_mitm_service!(
                    exec.clone(),
                    capture.clone(),
                    inspection.clone(),
                    har.clone(),
                    portal.clone(),
                    certificate.clone(),
                    private_key.clone(),
                    peek_timeout,
                    mitm_policy.clone()
                ))
            }
            _ => Either::B(ConsumeErrLayer::trace_as_debug().into_layer(
                MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
            )),
        };
        let socks_connector = make_egress_connector();
        let socks5 = Socks5Acceptor::new(exec.clone())
            .with_connector(Socks5Connector::new(socks_connector, socks_bridge));

        let http = MarkProtocolLayer::new(capture.clone(), "http").into_layer(plain_http);
        let https = MarkProtocolLayer::new(capture.clone(), "https").into_layer(tls_acceptor);
        let socks5 = MarkProtocolLayer::new(capture.clone(), "socks5").into_layer(socks5);
        let tcp_layers = (
            TcpStreamOptionsLayer::new(tcp_options.clone()),
            BodyLimitLayer::request_only(cfg.body_limit),
            opt_per_sec(Some(cfg.rate)).map(|rate| LimitLayer::new(RatePolicy::abort(rate))),
            LimitLayer::new(if cfg.concurrent > 0 {
                Either::A(ConcurrentPolicy::max(cfg.concurrent))
            } else {
                Either::B(UnlimitedPolicy::new())
            }),
            if cfg.timeout > 0 {
                TimeoutLayer::new(Duration::from_secs(cfg.timeout))
            } else {
                TimeoutLayer::never()
            },
            opt_per_sec(Some(cfg.throttle))
                .map(|rate| ThrottleLayer::symmetric(ThrottleMode::per_conn(rate))),
            capture
                .clone()
                .map(|capture| ObserveConnectionLayer::new(capture, "classifying")),
        );

        let labels = protocols
            .iter()
            .map(|protocol| format!("{protocol:?}").to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            network.local.address = %local_address.ip(),
            network.local.port = %local_address.port(),
            protocols = %labels,
            "proxy ready: bind interface = {local_address}"
        );
        if dashboard_here && let Some(auth_token) = dashboard_auth_token.as_ref() {
            tracing::info!("MITM inspector ready: http://{local_address}/?token={auth_token}");
        }

        exec.clone().into_spawn_task(async move {
            match (plain_http_route, https_enabled, socks5_enabled) {
                (true, false, false) => listener.serve(tcp_layers.into_layer(http)).await,
                (false, true, false) => listener.serve(tcp_layers.into_layer(https)).await,
                (false, false, true) => listener.serve(tcp_layers.into_layer(socks5)).await,
                (true, true, false) => {
                    let service = TlsPeekRouter::new(https)
                        .maybe_with_peek_timeout(peek_timeout)
                        .with_fallback(http);
                    listener.serve(tcp_layers.into_layer(service)).await;
                }
                (true, false, true) => {
                    let service = Socks5PeekRouter::new(socks5)
                        .maybe_with_peek_timeout(peek_timeout)
                        .with_fallback(http);
                    listener.serve(tcp_layers.into_layer(service)).await;
                }
                (false, true, true) => {
                    let service = Socks5PeekRouter::new(socks5)
                        .maybe_with_peek_timeout(peek_timeout)
                        .with_fallback(https);
                    listener.serve(tcp_layers.into_layer(service)).await;
                }
                (true, true, true) => {
                    let tls_or_http = TlsPeekRouter::new(https)
                        .maybe_with_peek_timeout(peek_timeout)
                        .with_fallback(http);
                    let service = Socks5PeekRouter::new(socks5)
                        .maybe_with_peek_timeout(peek_timeout)
                        .with_fallback(tls_or_http);
                    listener.serve(tcp_layers.into_layer(service)).await;
                }
                (false, false, false) => {
                    tracing::error!("proxy listener started without a configured protocol");
                }
            }
        });
    }

    Ok(())
}

fn resolve_listeners(cfg: &CliCommandProxy) -> Vec<(SocketAddress, BTreeSet<ProxyProtocol>)> {
    fn extend(
        listeners: &mut Vec<(SocketAddress, BTreeSet<ProxyProtocol>)>,
        address: SocketAddress,
        protocols: impl IntoIterator<Item = ProxyProtocol>,
    ) {
        if let Some((_, current)) = listeners
            .iter_mut()
            .find(|(current, _)| *current == address)
        {
            current.extend(protocols);
        } else {
            listeners.push((address, protocols.into_iter().collect()));
        }
    }

    let mut listeners = Vec::new();
    let has_specific =
        !(cfg.http_bind.is_empty() && cfg.https_bind.is_empty() && cfg.socks5_bind.is_empty());
    if cfg.bind.is_some() || !has_specific {
        let address = cfg.bind.unwrap_or_else(default_bind);
        extend(&mut listeners, address, cfg.protocol.iter().copied());
    }
    for address in &cfg.http_bind {
        extend(&mut listeners, *address, [ProxyProtocol::Http]);
    }
    for address in &cfg.https_bind {
        extend(&mut listeners, *address, [ProxyProtocol::Https]);
    }
    for address in &cfg.socks5_bind {
        extend(&mut listeners, *address, [ProxyProtocol::Socks5]);
    }
    listeners
}

fn resolve_mitm_address(
    cfg: &CliCommandProxy,
    listeners: &[(SocketAddress, BTreeSet<ProxyProtocol>)],
) -> Option<SocketAddress> {
    match cfg.mitm {
        None => None,
        Some(MitmBindAddress::Explicit(address)) => Some(address),
        Some(MitmBindAddress::Inherit) => Some(
            cfg.bind
                .or_else(|| (listeners.len() == 1).then_some(listeners[0].0))
                .unwrap_or_else(default_bind),
        ),
    }
}

fn inherited_mitm_listener_index(
    cfg: &CliCommandProxy,
    listeners: &[(SocketAddress, BTreeSet<ProxyProtocol>)],
    requested_mitm_address: Option<SocketAddress>,
) -> Option<usize> {
    if !matches!(cfg.mitm, Some(MitmBindAddress::Inherit)) {
        return None;
    }
    let requested_mitm_address = requested_mitm_address?;
    listeners
        .iter()
        .position(|(address, _)| *address == requested_mitm_address)
}

fn resolve_bound_mitm_address(
    requested_mitm_address: Option<SocketAddress>,
    inherited_mitm_listener: Option<usize>,
    bound_addresses: &[std::net::SocketAddr],
) -> Option<SocketAddress> {
    inherited_mitm_listener
        .and_then(|index| bound_addresses.get(index).copied())
        .map(Into::into)
        .or(requested_mitm_address)
}

fn standalone_dashboard_service<D>(
    dashboard: D,
    dashboard_address: SocketAddress,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone
where
    D: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    proxy_request_dispatcher(
        service_fn(|_| async { Ok(StatusCode::NOT_FOUND.into_response()) }),
        Some(dashboard),
        Some(dashboard_address),
        false,
    )
}

fn proxy_request_dispatcher<S, D>(
    proxy: S,
    dashboard: Option<D>,
    dashboard_address: Option<SocketAddress>,
    proxy_enabled: bool,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone
where
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
    D: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    service_fn(move |request: Request| {
        let proxy = proxy.clone();
        let dashboard = dashboard.clone();
        async move {
            let is_dashboard = dashboard_address
                .is_some_and(|address| request_targets_dashboard(&request, address));
            if is_dashboard && let Some(dashboard) = dashboard {
                return dashboard.serve(request).await;
            }
            if proxy_enabled {
                proxy.serve(request).await
            } else {
                Ok(StatusCode::NOT_FOUND.into_response())
            }
        }
    })
}

fn classify_http_connection<S>(
    inner: S,
    dashboard_address: Option<SocketAddress>,
    proxy_enabled: bool,
    capture: Option<CaptureStore>,
) -> ClassifyHttpConnectionService<S> {
    ClassifyHttpConnectionService {
        inner,
        dashboard_address,
        proxy_enabled,
        capture,
    }
}

#[derive(Debug, Clone)]
struct ClassifyHttpConnectionService<S> {
    inner: S,
    dashboard_address: Option<SocketAddress>,
    proxy_enabled: bool,
    capture: Option<CaptureStore>,
}

impl<S> Service<Request> for ClassifyHttpConnectionService<S>
where
    S: Service<Request>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        if let (Some(capture), Some(connection_id)) = (
            self.capture.as_ref(),
            request.extensions().get_ref::<ConnectionId>().copied(),
        ) {
            let is_control_request = request_targets_mitm_portal(&request)
                || self
                    .dashboard_address
                    .is_some_and(|address| request_targets_dashboard(&request, address));
            if is_control_request {
                capture.discard_connection_if_empty(connection_id.0);
            } else if self.proxy_enabled {
                capture.confirm_connection_if_enabled(connection_id.0);
            }
        }
        self.inner.serve(request).await
    }
}

fn request_targets_mitm_portal(request: &Request) -> bool {
    let matches = |authority: AuthorityRef<'_>| {
        authority
            .host()
            .to_str()
            .eq_ignore_ascii_case(MITM_PORTAL_DOMAIN.as_str())
    };
    request.uri().authority().is_some_and(matches)
        || request
            .headers()
            .get("host")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Authority::try_from(value).ok())
            .is_some_and(|authority| matches(authority.view()))
}

fn request_targets_dashboard(request: &Request, dashboard_address: SocketAddress) -> bool {
    if request.method() == rama::http::Method::CONNECT {
        return false;
    }
    let dashboard_address: std::net::SocketAddr = dashboard_address.into();
    let local_address = request
        .extensions()
        .get_ref::<rama::net::stream::SocketInfo>()
        .and_then(|socket| socket.local_addr())
        .map(Into::<std::net::SocketAddr>::into);
    if !dashboard_address.ip().is_unspecified()
        && !local_address.is_some_and(|local_address| local_address == dashboard_address)
    {
        return false;
    }
    let authority = request
        .uri()
        .authority()
        .map(AuthorityRef::into_owned)
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| Authority::try_from(value).ok())
        });
    let Some(authority) = authority else {
        return request.uri().scheme().is_none();
    };
    authority_targets_socket(authority.view(), dashboard_address)
        || local_address.is_some_and(|address| authority_targets_socket(authority.view(), address))
}

fn authority_targets_socket(authority: AuthorityRef<'_>, address: std::net::SocketAddr) -> bool {
    if authority.port_u16().unwrap_or(80) != address.port() {
        return false;
    }
    match authority.host().try_as_ip() {
        Ok(ip) => ip == address.ip() || (address.ip().is_unspecified() && ip.is_loopback()),
        Err(_) => {
            address.ip().is_loopback()
                && authority.host().to_str().eq_ignore_ascii_case("localhost")
        }
    }
}

struct ProxyClientConfig {
    exec: Executor,
    capture: Option<CaptureStore>,
    inspection: InspectionState,
    har: HarController,
    portal: Option<PortalService>,
    tcp_options: Arc<SocketOptions>,
    connect_timeout: Option<Duration>,
    mitm_policy: MitmPolicy,
    upstream: UpstreamProxyConfig,
}

fn new_proxy_client(
    config: ProxyClientConfig,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let ProxyClientConfig {
        exec,
        capture,
        inspection,
        har,
        portal,
        tcp_options,
        connect_timeout,
        mitm_policy,
        upstream,
    } = config;
    let tls_config = rama::tls::client::TlsClientConfig::default_http();
    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(
            rama::tcp::client::service::TcpConnector::new().with_connector(tcp_options),
        )
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(exec.clone())
        .with_custom_connector(connect_timeout.map_or_else(TimeoutLayer::never, TimeoutLayer::new))
        .with_default_connection_pool()
        .build_client();
    let client = upstream.http_service(client);
    let base = require_request_service(
        (
            HARExportLayer::new(har.clone(), har),
            DecompressionLayer::new()
                .with_insert_accept_encoding_header(false)
                .with_tolerate_decode_errors(true),
            ArcLayer::new(),
        )
            .into_layer(client),
    );
    let ordinary = require_request_service(
        CaptureHttpLayer::new(capture.clone()).into_layer(
            (
                RemoveResponseHeaderLayer::hop_by_hop(),
                RemoveRequestHeaderLayer::hop_by_hop(),
            )
                .into_layer(base.clone()),
        ),
    );
    let websocket_relay = WebSocketRelayIoLayer::new().into_layer(
        CaptureWebSocketLayer::new(capture.clone()).into_layer(
            HARWebSocketLayer::new().into_layer(
                WebSocketRelayEventService::new(service_fn({
                    let capture = capture.clone();
                    move |input| inspect_websocket_event(capture.clone(), input)
                }))
                .with_message_injection(true),
            ),
        ),
    );
    let websocket = require_request_service(
        HttpUpgradeMitmRelayLayer::new(
            exec,
            HttpWebSocketRelayServiceRequestMatcher::new(websocket_relay),
        )
        .into_layer(CaptureHttpLayer::new(capture).into_layer(base)),
    );
    let proxy = require_request_service(
        rama::layer::HijackLayer::new(
            rama::http::ws::handshake::matcher::WebSocketMatcher::new(),
            websocket,
        )
        .into_layer(ordinary),
    );
    let proxy = portal
        .map(|portal| HijackLayer::new(MitmPortalMatcher::http(inspection, mitm_policy), portal))
        .into_layer(proxy);
    let proxy = StreamCompressionLayer::new()
        .with_compress_predicate(MirrorDecompressed::new())
        .with_enforce_not_acceptable(false)
        .into_layer(proxy);
    ConsumeErrLayer::trace_as_debug()
        .with_response(DefaultErrorResponse::new())
        .into_layer(MapResponseBodyLayer::new_boxed_streaming_body().into_layer(proxy))
}

fn tcp_socket_options(cfg: &CliCommandProxy) -> Arc<SocketOptions> {
    let mut keep_alive = TcpKeepAlive {
        time: Some(Duration::from_secs(cfg.tcp_keepalive_idle)),
        ..Default::default()
    };
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    {
        keep_alive.interval = Some(Duration::from_secs(cfg.tcp_keepalive_interval));
    }
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "windows",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    {
        keep_alive.retries = Some(cfg.tcp_keepalive_probes);
    }

    Arc::new(SocketOptions {
        keep_alive: Some(cfg.tcp_keepalive),
        tcp_keep_alive: cfg.tcp_keepalive.then_some(keep_alive),
        tcp_no_delay: Some(cfg.tcp_no_delay),
        recv_buffer_size: (cfg.tcp_recv_buffer > 0).then_some(cfg.tcp_recv_buffer),
        send_buffer_size: (cfg.tcp_send_buffer > 0).then_some(cfg.tcp_send_buffer),
        ..SocketOptions::default_tcp()
    })
}

fn require_request_service<S>(service: S) -> S
where
    S: Service<Request>,
{
    service
}

async fn inspect_websocket_event(
    capture: Option<CaptureStore>,
    input: WebSocketRelayEventInput,
) -> Result<WebSocketRelayEventOutput, Infallible> {
    let WebSocketRelayEventInput {
        direction,
        event,
        extensions,
    } = input;
    if let (Some(capture), Some(exchange_id)) =
        (capture, extensions.get_ref::<ExchangeId>().copied())
    {
        if let Some(injector) = extensions.get_ref::<WebSocketRelayInjector>() {
            capture.register_websocket_injector(exchange_id.0, injector.clone());
        }
        let (kind, data, close_code) = match &event {
            WebSocketRelayEvent::Open => {
                return Ok(WebSocketRelayEventInput {
                    direction,
                    event,
                    extensions,
                }
                .into());
            }
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(text)) => {
                ("text", text.as_bytes().to_vec(), None)
            }
            WebSocketRelayEvent::Data(WebSocketRelayMessage::Binary(data)) => {
                ("binary", data.to_vec(), None)
            }
            WebSocketRelayEvent::Ping(data) => ("ping", data.to_vec(), None),
            WebSocketRelayEvent::Pong(data) => ("pong", data.to_vec(), None),
            WebSocketRelayEvent::Close(frame) => (
                "close",
                frame
                    .as_ref()
                    .map(|frame| frame.reason.as_bytes().to_vec())
                    .unwrap_or_default(),
                frame.as_ref().map(|frame| u16::from(&frame.code)),
            ),
        };
        capture
            .record_websocket_message(
                exchange_id.0,
                format!("{direction:?}"),
                kind.to_owned(),
                data,
                close_code,
            )
            .await;
    }
    Ok(WebSocketRelayEventOutput::from(WebSocketRelayEventInput {
        direction,
        event,
        extensions,
    }))
}

async fn write_new_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), BoxError> {
    use tokio::io::AsyncWriteExt as _;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
