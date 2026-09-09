//! Multi-protocol forward proxy with optional Relay/Peek MITM inspection.

mod capture;
mod dashboard;
mod dashboard_auth;
mod har;
mod portal;
mod upstream;

use std::{
    collections::BTreeSet,
    convert::Infallible,
    num::NonZeroU64,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(test)]
use capture::HttpExchangeId;
use capture::{
    CaptureHttpLayer, CaptureStore, CaptureWebSocketLayer, ConnectionId, MarkProtocolLayer,
    ObserveConnectionLayer,
};
use clap::{Args, ValueEnum};
use control::{Control, ControlConnection};
use dashboard::DashboardState;
use dashboard_auth::DashboardAuthService;
use har::HarController;
use inspection::{InspectionGate, InspectionState};
use mitm_policy::MitmPolicy;
use portal::PortalService;
use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::ExtensionsRef as _,
    graceful::ShutdownGuard,
    http::{
        BodyLimitLayer, Method, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        inspect::{control, mitm_policy},
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
                mitm::{WebSocketRelayEventService, WebSocketRelayIoLayer},
            },
            inspect::inspect_websocket_event,
            layer::har::HARWebSocketLayer,
        },
    },
    icap::{
        client::{
            Client as IcapClient,
            options::{
                MethodSupport, OptionsCache, OptionsCacheLayer, OptionsRequest, OptionsService,
                ServiceCapabilities,
            },
        },
        http::layer::{AdaptationLayer, ServiceEndpoint, UnsupportedMethodPolicy},
        proto::{MethodKind as IcapMethodKind, Preview},
    },
    inspect as inspection,
    io::timeout::TimeoutIo,
    layer::{
        ArcLayer, ConsumeErrLayer, HijackLayer, LimitLayer, MapOutputLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RatePolicy, UnlimitedPolicy},
    },
    net::{
        Protocol,
        address::{Authority, AuthorityRef, Domain, ProxyAddress, SocketAddress},
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
            EstablishedClientConnection,
            pool::{BasicConnId, BasicConnIdentifier, LruDropPool, PooledConnector},
        },
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        stream::{
            SocketInfo,
            layer::{TcpStreamOptionsLayer, ThrottleLayer, ThrottleMode},
        },
        uri::Uri,
    },
    proxy::socks5::{
        Socks5Acceptor,
        server::{Connector as Socks5Connector, Socks5PeekRouter},
    },
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::{client::service::TcpConnector, proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing,
    tls::{
        boring::{
            client::{AutoTlsStream, TlsConnector as IcapTlsConnector},
            proxy::TlsMitmRelay,
            server::TlsAcceptorService,
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::{
            CertificateSubject, GeneratedServerAuthConfig, InputWithClientHello, LeafCertRequest,
            PeekTlsClientHelloService, SelfSignedCaConfig, ServerAuthData, TlsPeekRouter,
            TlsServerConfig,
        },
    },
    ua::profile::UserAgentDatabase,
    utils::{
        fs::OpenOptions,
        octets::{kib_u64, mib_u64},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore},
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
const DEFAULT_ICAP_PREVIEW_BYTES: u64 = kib_u64(1);
const DEFAULT_ICAP_CONNECTIONS: usize = 64;
const DEFAULT_ICAP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_ICAP_IDLE_TIMEOUT_SECS: u64 = 60;

type IcapTcpConnector = TcpConnector<Arc<SocketOptions>>;
type IcapDnsConnector = rama::dns::client::DnsConnector<IcapTcpConnector>;
type IcapRawConnector = IcapTlsConnector<IcapDnsConnector>;
type IcapConnectTimeoutConnector = rama::layer::timeout::DefaultTimeout<IcapRawConnector>;
type IcapTimedConnector = IcapIoTimeoutConnector<IcapConnectTimeoutConnector>;
type IcapTransport = IcapTimeoutIo<AutoTlsStream<rama::tcp::TcpStream>>;
type IcapTransportPool = LruDropPool<IcapTransport, BasicConnId>;
type IcapPooledConnector =
    PooledConnector<IcapTimedConnector, IcapTransportPool, BasicConnIdentifier>;
type IcapRotatingConnector = ConnectorGeneration<IcapPooledConnector, IcapTransportPool>;
type IcapLimitedConnector = ConnectionLimitConnector<IcapRotatingConnector>;
type ProxyIcapClient = IcapClient<IcapLimitedConnector>;
type ProxyIcapOptions = ConnectionLimitOptions<OptionsCache<OptionsService<Arc<ProxyIcapClient>>>>;
type RawProxyIcapLayer = AdaptationLayer<Arc<ProxyIcapClient>, ProxyIcapOptions>;

struct IcapTimeoutIo<IO> {
    inner: Pin<Box<TimeoutIo<IO>>>,
}

impl<IO> IcapTimeoutIo<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    fn new(inner: IO, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(
                TimeoutIo::new(inner)
                    .with_read_timeout(timeout)
                    .with_write_timeout(timeout),
            ),
        }
    }
}

impl<IO> rama::extensions::ExtensionsRef for IcapTimeoutIo<IO>
where
    IO: rama::extensions::ExtensionsRef + AsyncRead + AsyncWrite,
{
    fn extensions(&self) -> &rama::extensions::Extensions {
        self.inner.as_ref().get_ref().get_ref().extensions()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for IcapTimeoutIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().inner.as_mut().poll_read(context, buffer)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for IcapTimeoutIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.get_mut().inner.as_mut().poll_write(context, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.get_mut().inner.as_mut().poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.get_mut().inner.as_mut().poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.get_mut()
            .inner
            .as_mut()
            .poll_write_vectored(context, buffers)
    }
}

#[derive(Clone)]
struct IcapIoTimeoutConnector<S> {
    inner: S,
    timeout: Duration,
}

impl<S> IcapIoTimeoutConnector<S> {
    const fn new(inner: S, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<S, IO> Service<ConnectRequest> for IcapIoTimeoutConnector<S>
where
    S: ConnectorService<ConnectRequest, Connection = IO>,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<IcapTimeoutIo<IO>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: IcapTimeoutIo::new(conn, self.timeout),
        })
    }
}

trait RetirePool {
    fn retire(&self);
}

impl<C, ID> RetirePool for LruDropPool<C, ID> {
    fn retire(&self) {
        Self::retire(self);
    }
}

struct ConnectorGenerationState<S, P> {
    limit: usize,
    connector: Arc<S>,
    pool: P,
}

struct ConnectorGeneration<S, P> {
    state: Arc<RwLock<ConnectorGenerationState<S, P>>>,
}

impl<S, P> Clone for ConnectorGeneration<S, P> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<S, P> ConnectorGeneration<S, P>
where
    P: RetirePool + Send + Sync + 'static,
{
    fn new(limit: usize, connector: S, pool: P) -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectorGenerationState {
                limit,
                connector: Arc::new(connector),
                pool,
            })),
        }
    }

    async fn replace(&self, limit: usize, connector: S, pool: P) {
        let mut state = self.state.write().await;
        if state.limit != limit {
            state.pool.retire();
            state.limit = limit;
            state.connector = Arc::new(connector);
            state.pool = pool;
        }
    }

    async fn limit(&self) -> usize {
        self.state.read().await.limit
    }
}

impl<Input, S, P> Service<Input> for ConnectorGeneration<S, P>
where
    Input: Send + 'static,
    S: Service<Input>,
    P: RetirePool + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let connector = self.state.read().await.connector.clone();
        connector.serve(input).await
    }
}

#[derive(Clone)]
struct IcapPoolController {
    connector: IcapRotatingConnector,
    inner: IcapTimedConnector,
    wait_timeout: Option<Duration>,
    idle_timeout: Duration,
}

impl IcapPoolController {
    async fn update(&self, limit: usize) -> Result<(), BoxError> {
        if self.connector.limit().await == limit {
            return Ok(());
        }
        let (connector, pool) = build_icap_pool(
            self.inner.clone(),
            limit,
            self.wait_timeout,
            self.idle_timeout,
        )?;
        self.connector.replace(limit, connector, pool).await;
        Ok(())
    }
}

#[derive(Clone)]
struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    reserved: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
    local_max: usize,
    wait_timeout: Option<Duration>,
}

impl ConnectionLimiter {
    fn new(local_max: usize, wait_timeout: Option<Duration>) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(local_max)),
            reserved: Arc::new(Mutex::new(None)),
            local_max,
            wait_timeout,
        }
    }

    async fn update(&self, peer_max: Option<u64>) -> Result<usize, BoxError> {
        let peer_max = match peer_max {
            Some(0) => {
                let reserved = self.reserved.lock().await;
                let effective = self.local_max
                    - reserved
                        .as_ref()
                        .map_or(0, OwnedSemaphorePermit::num_permits);
                tracing::warn!(
                    effective,
                    "ignoring invalid ICAP Max-Connections value of zero"
                );
                return Ok(effective);
            }
            Some(value) => usize::try_from(value).unwrap_or(usize::MAX),
            None => self.local_max,
        };
        let effective = self.local_max.min(peer_max);
        let target_reserved = self.local_max - effective;
        let mut reserved = self.reserved.lock().await;
        let current_reserved = reserved
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits);
        match target_reserved.cmp(&current_reserved) {
            std::cmp::Ordering::Greater => {
                let count = u32::try_from(target_reserved - current_reserved)
                    .context("convert reserved ICAP connection capacity")?;
                let permit = match self.semaphore.clone().try_acquire_many_owned(count) {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        // Capacity discovery runs on the request path. Do not put a
                        // multi-permit waiter ahead of live transactions: retain the
                        // last fully applied limit and retry on the next request.
                        return Ok(self.local_max - current_reserved);
                    }
                    Err(error) => return Err(Box::new(error)),
                };
                if let Some(reserved) = reserved.as_mut() {
                    reserved.merge(permit);
                } else {
                    *reserved = Some(permit);
                }
            }
            std::cmp::Ordering::Less => {
                let released = reserved
                    .as_mut()
                    .and_then(|permit| permit.split(current_reserved - target_reserved))
                    .ok_or_else(|| {
                        BoxError::from_static_str(
                            "reserved ICAP connection permits do not match the tracked limit",
                        )
                    })?;
                drop(released);
                if target_reserved == 0 {
                    *reserved = None;
                }
            }
            std::cmp::Ordering::Equal => {}
        }
        Ok(effective)
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, ConnectionError> {
        let acquire = self.semaphore.clone().acquire_owned();
        match self.wait_timeout {
            Some(duration) => tokio::time::timeout(duration, acquire)
                .await
                .map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::Timeout)
                        .context("wait for ICAP peer connection capacity")
                })?
                .map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::Internal)
                        .context("acquire ICAP peer connection capacity")
                }),
            None => acquire.await.map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::Internal)
                    .context("acquire ICAP peer connection capacity")
            }),
        }
    }
}

#[derive(Clone)]
struct ConnectionLimitConnector<S> {
    inner: S,
    limit: ConnectionLimiter,
}

impl<S> Service<ConnectRequest> for ConnectionLimitConnector<S>
where
    S: ConnectorService<ConnectRequest>,
    S::Connection: AsyncRead + AsyncWrite + Unpin,
{
    type Output = EstablishedClientConnection<LimitedConnection<S::Connection>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let permit = self.limit.acquire().await?;
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: LimitedConnection {
                inner: conn,
                _permit: permit,
            },
        })
    }
}

struct LimitedConnection<C> {
    inner: C,
    _permit: OwnedSemaphorePermit,
}

impl<C: rama::extensions::ExtensionsRef> rama::extensions::ExtensionsRef for LimitedConnection<C> {
    fn extensions(&self) -> &rama::extensions::Extensions {
        self.inner.extensions()
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for LimitedConnection<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for LimitedConnection<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }
}

#[derive(Clone)]
struct ConnectionLimitOptions<S> {
    inner: S,
    limit: ConnectionLimiter,
    pool: IcapPoolController,
    update: Arc<Mutex<()>>,
    request_enabled: bool,
    response_enabled: bool,
}

impl<S> Service<OptionsRequest> for ConnectionLimitOptions<S>
where
    S: Service<OptionsRequest>,
    S::Output: Into<Arc<ServiceCapabilities>>,
    S::Error: Into<BoxError>,
{
    type Output = Arc<ServiceCapabilities>;
    type Error = BoxError;

    async fn serve(&self, input: OptionsRequest) -> Result<Self::Output, Self::Error> {
        let capabilities: Arc<ServiceCapabilities> = self
            .inner
            .serve(input)
            .await
            .map_err(Into::into)
            .context("discover ICAP service connection capacity")?
            .into();
        let supported = (self.request_enabled
            && capabilities.methods().support(IcapMethodKind::Reqmod) == MethodSupport::Supported)
            || (self.response_enabled
                && capabilities.methods().support(IcapMethodKind::Respmod)
                    == MethodSupport::Supported);
        if !supported {
            return Err(BoxError::from_static_str(
                "ICAP service advertises none of the enabled adaptation methods",
            ));
        }
        let _update = self.update.lock().await;
        let effective = self.limit.update(capabilities.max_connections()).await?;
        // The semaphore drains active leases before a lower limit lands. A
        // fresh pool generation then drops every idle transport from the old
        // generation; active old leases cannot return and close on release.
        self.pool.update(effective).await?;
        Ok(capabilities)
    }
}

#[derive(Clone)]
struct ProxyIcapLayer(RawProxyIcapLayer);

#[cfg(test)]
impl ProxyIcapLayer {
    fn request_service(&self) -> Option<&ServiceEndpoint> {
        self.0.request_service()
    }

    fn response_service(&self) -> Option<&ServiceEndpoint> {
        self.0.response_service()
    }

    async fn physical_connection_limit(&self) -> Result<usize, BoxError> {
        let options = self
            .0
            .options_service()
            .context("ICAP OPTIONS service is missing")?;
        Ok(options.pool.connector.limit().await)
    }

    async fn update_physical_connection_limit(&self, limit: usize) -> Result<(), BoxError> {
        let options = self
            .0
            .options_service()
            .context("ICAP OPTIONS service is missing")?;
        options.pool.update(limit).await
    }

    fn physical_idle_timeout(&self) -> Result<Duration, BoxError> {
        let options = self
            .0
            .options_service()
            .context("ICAP OPTIONS service is missing")?;
        Ok(options.pool.idle_timeout)
    }
}

impl<S> Layer<S> for ProxyIcapLayer
where
    RawProxyIcapLayer: Layer<S>,
    <RawProxyIcapLayer as Layer<S>>::Service: Service<Request, Output = Response, Error = BoxError>,
{
    type Service = BoxService<Request, Response, BoxError>;

    fn layer(&self, inner: S) -> Self::Service {
        BoxService::new(self.0.layer(inner))
    }

    fn into_layer(self, inner: S) -> Self::Service {
        BoxService::new(self.0.into_layer(inner))
    }
}

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
    control: Option<Control>,
    defer_ip_target: bool,
    inspection: InspectionState,
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
        let should_inspect = self.inspection.is_enabled()
            && if self.defer_ip_target {
                self.policy.should_peek_target(input.extensions())
            } else {
                self.policy.should_inspect_target(input.extensions())
            };
        if !self.defer_ip_target || !should_inspect {
            observe_target(
                self.control.as_ref(),
                input.extensions(),
                None,
                should_inspect,
            );
        }
        if should_inspect {
            self.inspect.serve(input).await.map_err(Into::into)
        } else {
            self.passthrough.serve(input).await.map_err(Into::into)
        }
    }
}

#[derive(Debug, Clone)]
struct TlsHelloMitmPolicyService<I, P> {
    inspection: InspectionState,
    inspect: I,
    passthrough: P,
    policy: MitmPolicy,
    control: Option<Control>,
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
        observe_target(
            self.control.as_ref(),
            input.input.extensions(),
            sni.as_ref(),
            should_inspect,
        );
        if should_inspect && let Some(session) = self.inspection.session() {
            return session
                .run(self.inspect.serve(input))
                .await
                .map_err(Into::into);
        }
        self.passthrough
            .serve(input.input)
            .await
            .map_err(Into::into)
    }
}

fn observe_target(
    control: Option<&Control>,
    extensions: &rama::extensions::Extensions,
    sni: Option<&rama::net::address::Host>,
    inspected: bool,
) {
    let Some(control) = control else {
        return;
    };
    let Some(connection) = extensions.get_ref::<ControlConnection>() else {
        return;
    };
    let target = extensions.get_ref::<rama::net::client::ConnectorTarget>();
    let host = sni.or_else(|| target.as_ref().map(|t| &t.0.host));
    if let Some(host) = host {
        control.observe(
            connection,
            host,
            inspected,
            if sni.is_some() {
                "TLS SNI"
            } else {
                "proxy destination"
            },
            if inspected {
                "MITM eligible"
            } else {
                "passed through without inspection"
            },
        );
    }
}

/// Record the final outcome when protocol peeking falls back to a byte tunnel.
#[derive(Debug, Clone)]
struct ObservePassthroughService<S> {
    inner: S,
    control: Control,
}

impl<S, IO> Service<IO> for ObservePassthroughService<S>
where
    IO: rama::extensions::ExtensionsRef + Send + 'static,
    S: Service<IO, Output = (), Error: Into<BoxError>>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: IO) -> Result<(), BoxError> {
        observe_target(Some(&self.control), input.extensions(), None, false);
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
struct MitmPortalMatcher {
    domain: DomainMatcher,
    policy: MitmPolicy,
    connect_only: bool,
}

impl MitmPortalMatcher {
    fn http(_inspection: InspectionState, policy: MitmPolicy) -> Self {
        Self {
            domain: DomainMatcher::exact(MITM_PORTAL_DOMAIN),
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
        !self
            .policy
            .is_denied(&rama::net::address::Host::Name(MITM_PORTAL_DOMAIN))
            && (!self.connect_only || request.method() == Method::CONNECT)
            && self.domain.matches(extensions, request)
    }
}

macro_rules! build_mitm_service {
    ($exec:expr, $capture:expr, $inspection:expr, $har:expr, $portal:expr, $certificate:expr, $private_key:expr, $peek_timeout:expr, $mitm_policy:expr, $icap:expr) => {{
        let capture = $capture;
        let capture_control = capture.control();
        let inspection = $inspection;
        let har = $har;
        let exec = $exec;
        let portal = $portal;
        let peek_timeout = $peek_timeout;
        let mitm_policy = $mitm_policy;
        let icap = $icap;
        let error_level = if icap.is_some() {
            tracing::Level::WARN
        } else {
            tracing::Level::DEBUG
        };
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
        let websocket_relay = InspectionGate {
            inspection: inspection.clone(),
            inspect: websocket_relay,
            passthrough: MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
        };
        let websocket_layer = HttpUpgradeMitmRelayLayer::new(
            exec.clone(),
            HttpWebSocketRelayServiceRequestMatcher::new(websocket_relay),
        );
        let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
            ConsumeErrLayer::trace_as(error_level).with_response(DefaultErrorResponse::new()),
            MapResponseBodyLayer::new_boxed_streaming_body(),
            StreamCompressionLayer::new()
                .with_compress_predicate(MirrorDecompressed::new())
                .with_enforce_not_acceptable(false),
            HijackLayer::new(
                MitmPortalMatcher::http(inspection.clone(), mitm_policy.clone()),
                portal,
            ),
            CaptureHttpLayer::new(Some(capture.clone())),
            websocket_layer,
            RemoveResponseHeaderLayer::proxy_auth(),
            icap,
            RemoveRequestHeaderLayer::proxy_auth(),
            HARExportLayer::new(har.clone(), har),
            DecompressionLayer::new()
                .with_insert_accept_encoding_header(false)
                .with_tolerate_decode_errors(true),
            ArcLayer::new(),
        ));
        // Only inspected HTTP/TLS/WebSocket sessions are cancelled on pause.
        // Unsupported protocols and excluded hosts remain ordinary tunnels.
        let http_mitm_relay = InspectionGate {
            inspection: inspection.clone(),
            inspect: http_mitm_relay,
            passthrough: MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
        };
        let maybe_http = HttpPeekRouter::new(http_mitm_relay)
            .with_known_non_http_protocol_methods()
            .maybe_with_peek_timeout(peek_timeout)
            .with_fallback(ObservePassthroughService {
                inner: MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
                control: capture_control.clone(),
            });
        let passthrough = ConsumeErrLayer::trace_as_debug()
            .into_layer(MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())));
        let non_tls = MitmTargetPolicyService {
            inspect: maybe_http.clone(),
            passthrough: passthrough.clone(),
            policy: mitm_policy.clone(),
            control: Some(capture_control.clone()),
            defer_ip_target: false,
            inspection: inspection.clone(),
        };
        let tls = TlsMitmRelay::new_cached_in_memory($certificate, $private_key);
        let tls = TlsHelloMitmPolicyService {
            inspection: inspection.clone(),
            inspect: tls.into_layer(maybe_http.clone()),
            passthrough: passthrough.clone(),
            policy: mitm_policy.clone(),
            control: Some(capture_control.clone()),
        };
        let application = PeekTlsClientHelloService::new(tls)
            .maybe_with_peek_timeout(peek_timeout)
            .with_fallback(non_tls);
        let inspect = ConsumeErrLayer::trace_as(error_level).into_layer(application);
        Arc::new(MitmTargetPolicyService {
            inspect,
            passthrough,
            policy: mitm_policy,
            control: Some(capture_control),
            defer_ip_target: true,
            inspection,
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
    /// listener. HTTP and SOCKS5 are both enabled by default.
    #[arg(long, value_enum, value_delimiter = ',', default_value = "http,socks5")]
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

    /// Maximum connections kept in the live inspector. Connection summaries and
    /// TLS observations use memory in addition to the capture storage byte limit.
    #[arg(long, default_value_t = 10_000)]
    capture_connections: usize,

    /// Maximum HTTP exchanges retained in the live inspector. Exchange summaries
    /// use memory in addition to the capture storage byte limit.
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

    /// Maximum simultaneous inspector HAR/profile exports, including downloads
    /// (0 = no limit). Shared across both export formats.
    #[arg(long, default_value_t = 0)]
    inspect_export_concurrency: usize,

    /// Maximum lifetime in seconds for each proxy connection (0 = no timeout).
    /// Disabled by default so long-lived WebSocket and inspector streams remain
    /// persistent.
    #[arg(long, short = 't', default_value_t = 0)]
    timeout: u64,

    /// Timeout in seconds for establishing an egress connection (0 = no
    /// timeout).
    #[arg(long, default_value_t = 30)]
    connect_timeout: u64,

    /// Adapt visible HTTP requests and responses through this ICAP or ICAPS
    /// service. CONNECT and SOCKS5 streams bypass adaptation unless --mitm
    /// classifies them as HTTP.
    #[arg(long)]
    icap: Option<Uri>,

    /// Enable ICAP request adaptation.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, requires = "icap")]
    icap_reqmod: bool,

    /// Enable ICAP response adaptation.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, requires = "icap")]
    icap_respmod: bool,

    /// Body bytes offered to the ICAP service as a Preview (0 = disabled).
    #[arg(long, default_value_t = DEFAULT_ICAP_PREVIEW_BYTES, requires = "icap")]
    icap_preview: u64,

    /// Permit ICAP 204 responses after the Preview phase. This retains the
    /// original body within Rama's bounded replay limits.
    #[arg(long, requires = "icap")]
    icap_allow_204: bool,

    /// Permit the ICAP 206 partial-content extension when advertised by the
    /// service.
    #[arg(long, requires = "icap")]
    icap_allow_206: bool,

    /// Maximum persistent connections to the configured ICAP service.
    #[arg(long, default_value_t = DEFAULT_ICAP_CONNECTIONS, requires = "icap")]
    icap_connections: usize,

    /// Maximum ICAP read, write, and pool-wait inactivity in seconds.
    #[arg(long, default_value_t = NonZeroU64::new(DEFAULT_ICAP_TIMEOUT_SECS).unwrap(), requires = "icap")]
    icap_timeout: NonZeroU64,

    /// Idle seconds before a pooled ICAP connection is discarded (0 = no
    /// reuse).
    #[arg(long, default_value_t = DEFAULT_ICAP_IDLE_TIMEOUT_SECS, requires = "icap")]
    icap_idle_timeout: u64,

    /// Disable certificate verification for an ICAPS service.
    #[arg(long, requires = "icap")]
    icap_insecure: bool,

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

    /// Disable automatic configured credentials on plaintext HTTP requests
    /// forwarded to an HTTP(S) upstream proxy.
    #[arg(long, default_value_t = false)]
    no_upstream_proxy_forward_auth: bool,

    /// Use HTTP CONNECT even for plaintext HTTP requests sent through an
    /// HTTP(S) upstream proxy. This does not encrypt origin traffic.
    #[arg(long, default_value_t = false)]
    upstream_proxy_tunnel: bool,

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

    /// Initial MITM scope. Selected starts with no hosts until selected in the UI.
    #[arg(long, default_value_t = mitm_policy::ScopeMode::All, requires = "mitm")]
    mitm_scope: mitm_policy::ScopeMode,

    /// Print one JSON readiness record to stdout with the inspector link, API URL,
    /// and bearer token. Diagnostics continue through the configured logger.
    #[arg(long, requires = "mitm")]
    inspect_json: bool,

    /// Require approval for all supported protocols (HTTP and WebSocket) from startup.
    #[arg(long, requires = "mitm")]
    intercept: bool,

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

fn build_icap_pool(
    connector: IcapTimedConnector,
    limit: usize,
    wait_timeout: Option<Duration>,
    idle_timeout: Duration,
) -> Result<(IcapPooledConnector, IcapTransportPool), BoxError> {
    let pool = LruDropPool::try_new(limit, limit)?
        .with_idle_timeout(idle_timeout)
        .with_drop_connection_if_no_response(false);
    let connector = PooledConnector::new(connector, pool.clone(), BasicConnIdentifier::new())
        .maybe_with_wait_for_pool_timeout(wait_timeout);
    Ok((connector, pool))
}

fn build_icap_adaptation(
    cfg: &CliCommandProxy,
    tcp_options: Arc<SocketOptions>,
    connect_timeout: Option<Duration>,
) -> Result<Option<ProxyIcapLayer>, BoxError> {
    let Some(uri) = cfg.icap.as_ref() else {
        return Ok(None);
    };
    if !cfg.icap_reqmod && !cfg.icap_respmod {
        return Err(BoxError::from_static_str(
            "at least one of ICAP REQMOD and RESPMOD must be enabled",
        ));
    }
    if cfg.icap_connections == 0 {
        return Err(BoxError::from_static_str(
            "ICAP connection limit must be greater than zero",
        ));
    }
    if cfg.icap_connections > Semaphore::MAX_PERMITS {
        return Err(BoxError::from_static_str(
            "ICAP connection limit exceeds the supported semaphore capacity",
        ));
    }

    let uri = uri.as_str();
    let endpoint = ServiceEndpoint::new(uri.as_ref()).context("configure ICAP service endpoint")?;
    if cfg.icap_allow_206 && !cfg.icap_allow_204 {
        return Err(BoxError::from_static_str(
            "--icap-allow-206 requires --icap-allow-204",
        ));
    }
    if endpoint.service_protocol() == &Protocol::ICAP && endpoint.uri().userinfo().is_some() {
        tracing::warn!(
            service = ?endpoint.uri(),
            "ICAP URI credentials will be sent over a plaintext connection"
        );
    }
    let icap_timeout = Duration::from_secs(cfg.icap_timeout.get());
    let idle_timeout = Duration::from_secs(cfg.icap_idle_timeout);
    let tls_config = cfg
        .icap_insecure
        .then(|| TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable));
    // This is intentionally a dedicated ICAP connector. In particular, it
    // does not inherit the HTTP egress client's default ALPN configuration.
    let connector = IcapTlsConnector::auto(rama::dns::client::DnsConnector::new(
        TcpConnector::new().with_connector(tcp_options),
    ))
    .maybe_with_base_config(tls_config);
    let connector = connect_timeout
        .map_or_else(TimeoutLayer::never, TimeoutLayer::new)
        .into_layer(connector);
    let connector = IcapIoTimeoutConnector::new(connector, icap_timeout);
    let (pooled, pooled_storage) = build_icap_pool(
        connector.clone(),
        cfg.icap_connections,
        Some(icap_timeout),
        idle_timeout,
    )?;
    let rotating = ConnectorGeneration::new(cfg.icap_connections, pooled, pooled_storage);
    let pool = IcapPoolController {
        connector: rotating.clone(),
        inner: connector,
        wait_timeout: Some(icap_timeout),
        idle_timeout,
    };
    let limit = ConnectionLimiter::new(cfg.icap_connections, Some(icap_timeout));
    let connector = ConnectionLimitConnector {
        inner: rotating,
        limit: limit.clone(),
    };
    let client = Arc::new(IcapClient::new(connector));
    // Cache only the network discovery. Applying a live capacity change after
    // the cache returns keeps connection draining out of its single-flight
    // critical section.
    let options_cache = OptionsCacheLayer::new().layer(OptionsService::new(client.clone()));
    let options_cache_handle = options_cache.handle();
    let options = ConnectionLimitOptions {
        inner: options_cache,
        limit,
        pool,
        update: Arc::new(Mutex::new(())),
        request_enabled: cfg.icap_reqmod,
        response_enabled: cfg.icap_respmod,
    };
    let endpoint = endpoint
        .maybe_with_preview((cfg.icap_preview > 0).then(|| Preview::new(cfg.icap_preview)))
        .with_allow_204(cfg.icap_allow_204)
        .with_allow_206(cfg.icap_allow_206);
    let mut adaptation = AdaptationLayer::new(client)
        .with_options_service_and_cache_handle(options, options_cache_handle)
        .with_unsupported_method_policy(UnsupportedMethodPolicy::Bypass);
    if cfg.icap_reqmod {
        adaptation.set_request_service(endpoint.clone());
    }
    if cfg.icap_respmod {
        adaptation.set_response_service(endpoint);
    }
    Ok(Some(ProxyIcapLayer(adaptation)))
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
    if cfg.icap.is_some() && !mitm_enabled {
        tracing::warn!(
            "ICAP adaptation covers visible HTTP only; CONNECT and SOCKS5 streams bypass it without --mitm"
        );
    }
    let tcp_options = tcp_socket_options(&cfg);
    let connect_timeout =
        (cfg.connect_timeout > 0).then(|| Duration::from_secs(cfg.connect_timeout));
    let icap = build_icap_adaptation(&cfg, tcp_options.clone(), connect_timeout)?;
    let upstream = UpstreamProxyConfig::new(
        cfg.upstream_proxy.clone(),
        cfg.system_proxy,
        &cfg.proxy_bypass,
    )?
    .with_forward_proxy_auth(!cfg.no_upstream_proxy_forward_auth)
    .with_tunnel_plaintext_http(cfg.upstream_proxy_tunnel);
    let mitm_policy = MitmPolicy::try_new(&cfg.mitm_allow, &cfg.mitm_deny)?;
    mitm_policy.update_scope(cfg.mitm_scope, &[], &[])?;
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
            Ok::<_, BoxError>(CaptureStore::with_storage(
                capture::storage(cfg.capture_total_limit)?,
                capture::CaptureConfig {
                    max_connections: cfg.capture_connections,
                    max_exchanges: cfg.capture_exchanges,
                    body_limit: cfg.capture_body_limit,
                    total_limit: 0, // The filesystem service bounds encrypted bytes.
                    observer: Arc::new(capture::ProxyCaptureObserver::new(
                        ua_db.clone(),
                        cfg.capture_websocket_messages,
                    )),
                    ..capture::CaptureConfig::default()
                },
                inspection.clone(),
            ))
        })
        .transpose()?;
    if let Some(capture) = &capture {
        capture.control().configure(
            0,
            control::Config {
                enabled: cfg.intercept,
                ..Default::default()
            },
        )?;
    }
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
            dashboard::service(
                DashboardState::new(
                    capture.clone(),
                    har.clone(),
                    ca_pem,
                    tcp_options.clone(),
                    &upstream,
                    mitm_policy.clone(),
                )?
                .with_export_limit(cfg.inspect_export_concurrency)?,
            ),
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
    upstream.set_listener_addresses(bound.iter().map(|(_, address, _)| *address));

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
        print_inspector_ready(local_address, &auth_token, cfg.inspect_json);
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
            connect_timeout,
            mitm_policy: mitm_policy.clone(),
            upstream: upstream.clone(),
            icap: icap.clone(),
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
                    mitm_policy.clone(),
                    icap.clone()
                ))
            }
            _ => Either::B(ConsumeErrLayer::trace_as_debug().into_layer(
                MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
            )),
        };
        let make_egress_connector = || {
            let connector = EasyHttpWebClient::connector_builder()
                .with_custom_transport_connector(
                    TcpConnector::new().with_connector(tcp_options.clone()),
                )
                .with_default_dns_connector()
                .with_tls_proxy_support_using_boringssl()
                .with_proxy_support()
                .build_connector();
            let connector = upstream.connector_service(connector);
            connect_timeout.map(TimeoutLayer::new).into_layer(connector)
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
                    mitm_policy.clone(),
                    icap.clone()
                ))
            }
            _ => Either::B(ConsumeErrLayer::trace_as_debug().into_layer(
                MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
            )),
        };
        let socks_connector = make_egress_connector();
        let socks5 = Socks5Acceptor::new(exec.clone())
            .with_connector(Socks5Connector::new(socks_connector, socks_bridge));

        let http = MarkProtocolLayer::new(capture.clone(), Protocol::HTTP).into_layer(plain_http);
        let https =
            MarkProtocolLayer::new(capture.clone(), Protocol::HTTPS).into_layer(tls_acceptor);
        let socks5 = MarkProtocolLayer::new(capture.clone(), Protocol::SOCKS5).into_layer(socks5);
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
            capture.clone().map(|capture| {
                ObserveConnectionLayer::new(capture, Protocol::from_static("classifying"))
            }),
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
            print_inspector_ready(local_address, auth_token, cfg.inspect_json);
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
    if request.method() == Method::CONNECT {
        return false;
    }
    let dashboard_address: std::net::SocketAddr = dashboard_address.into();
    let local_address = request
        .extensions()
        .get_ref::<SocketInfo>()
        .and_then(|socket| socket.local_addr())
        .map(Into::<std::net::SocketAddr>::into);
    if !dashboard_address.ip().is_unspecified()
        && local_address.is_none_or(|local_address| local_address != dashboard_address)
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
    icap: Option<ProxyIcapLayer>,
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
        icap,
    } = config;
    let error_level = if icap.is_some() {
        tracing::Level::WARN
    } else {
        tracing::Level::DEBUG
    };
    let tls_config = TlsClientConfig::default_http();
    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(TcpConnector::new().with_connector(tcp_options))
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(exec.clone())
        .with_custom_connector(connect_timeout.map_or_else(TimeoutLayer::never, TimeoutLayer::new))
        .with_default_connection_pool()
        .build_client()
        .with_forward_proxy_auth(upstream.forward_proxy_auth())
        .with_tunnel_plaintext_http(upstream.tunnel_plaintext_http())
        .with_isolate_forward_proxy_auth_error(true);
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
    // Sanitize each source hop before adaptation. Let ICAP see proxy
    // authentication metadata, but consume it before the origin or downstream
    // client sees the message.
    let ordinary = require_request_service(
        (
            RemoveRequestHeaderLayer::hop_by_hop(),
            RemoveResponseHeaderLayer::proxy_auth(),
            icap.clone(),
            RemoveRequestHeaderLayer::proxy_auth(),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(base.clone()),
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
    let websocket_relay = InspectionGate {
        inspection: inspection.clone(),
        inspect: websocket_relay,
        passthrough: MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())),
    };
    let websocket = (
        RemoveRequestHeaderLayer::hop_by_hop(),
        RemoveResponseHeaderLayer::proxy_auth(),
        icap,
        RemoveRequestHeaderLayer::proxy_auth(),
        RemoveResponseHeaderLayer::hop_by_hop(),
    )
        .into_layer(base);
    let websocket = require_request_service(
        HttpUpgradeMitmRelayLayer::new(
            exec,
            HttpWebSocketRelayServiceRequestMatcher::new(websocket_relay),
        )
        .into_layer(websocket),
    );
    let proxy = require_request_service(
        rama::layer::HijackLayer::new(
            rama::http::ws::handshake::matcher::WebSocketMatcher::new(),
            websocket,
        )
        .into_layer(ordinary),
    );
    let proxy = CaptureHttpLayer::new(capture)
        .with_policy(mitm_policy.clone())
        .into_layer(proxy);
    let proxy = portal
        .map(|portal| {
            HijackLayer::new(
                MitmPortalMatcher::http(inspection, mitm_policy.clone()),
                portal,
            )
        })
        .into_layer(proxy);
    let proxy = StreamCompressionLayer::new()
        .with_compress_predicate(MirrorDecompressed::new())
        .with_enforce_not_acceptable(false)
        .into_layer(proxy);
    ConsumeErrLayer::trace_as(error_level)
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

async fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), BoxError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    Ok(())
}

fn inspector_ready(address: std::net::SocketAddr, token: &str) -> serde_json::Value {
    serde_json::json!({
        "event": "rama.inspector.ready", "version": 1,
        "inspector_url": format!("http://{address}/?token={token}"),
        "api_url": format!("http://{address}/api"),
        "authorization": { "scheme": "Bearer", "token": token },
        "help_url": format!("http://{address}/api/help"),
    })
}

#[expect(
    clippy::print_stdout,
    reason = "Explicitly requested machine-readable CLI output"
)]
fn print_inspector_ready(address: std::net::SocketAddr, token: &str, enabled: bool) {
    if enabled {
        println!("{}", inspector_ready(address, token));
    }
}

#[cfg(test)]
mod tests;
