//! Serving HTTP/3 next to the TCP listener of a serve command.

use std::{future::Future, sync::Arc, time::Duration};

use clap::{Args, value_parser};
use parking_lot::Mutex;
use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _, error_chain},
    futures::future::join_all,
    http::{
        core::h3::connection::Config,
        headers::{AltSvc, AlternativeService},
        proto::h3::observation::ObservationLimits,
    },
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{
        Connection, Endpoint, MtuDiscoveryConfig, ServerConfig, TransportConfig,
        proto::capture::CaptureLimits,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::server::TlsServerConfig,
    utils::octets,
};
#[cfg(target_os = "windows")]
use rama::{
    net::socket::opts::SocketOptions, quic::DEFAULT_SOCKET_BUFFER_SIZE, udp::UdpSocketConfig,
};

use super::http::HttpVersions;

mod bootstrap;
pub(crate) use self::bootstrap::Http3BootstrapCleanupLayer;

#[derive(Debug, Clone, Args)]
pub struct Http3Args {
    #[arg(long)]
    /// the UDP address to serve HTTP/3 on
    ///
    /// Defaults to the address of the TCP listener, or `--bind` without one.
    /// HTTP/3 is served when TLS is enabled and `--http-version` includes it.
    /// When only `auto` implies HTTP/3, failing to bind it leaves h1 and h2
    /// serving alone; this flag or `h3` in `--http-version` makes it an error.
    pub h3_bind: Option<SocketAddress>,

    #[arg(long, value_parser = value_parser!(u16).range(1200..))]
    /// the largest UDP payload HTTP/3 path MTU discovery probes for (default 1452)
    ///
    /// Lower it where the network drops larger datagrams without signalling it.
    pub h3_mtu_upper_bound: Option<u16>,

    #[arg(long)]
    /// a TCP address that only sends browsers on to HTTP/3
    ///
    /// For HTTP/3-only serving (`--http-version h3`): browsers always start over TCP, so
    /// this answers every request there with `Alt-Svc` and a reload, serving nothing else.
    pub h3_bootstrap_bind: Option<SocketAddress>,
}

impl Http3Args {
    /// Whether any HTTP/3 option was given explicitly.
    pub fn requested(&self) -> bool {
        self.h3_bind.is_some()
            || self.h3_mtu_upper_bound.is_some()
            || self.h3_bootstrap_bind.is_some()
    }
}

/// Diagnostic capture budgets: 8 KiB per retained component and four live snapshots.
pub(crate) const OBSERVATION_LIMITS: ObservationLimits = ObservationLimits {
    bytes: octets::kib(8),
    events: 64,
    fields: 128,
    streams: 16,
    retained_snapshots: 4,
    pending_fields: 8,
};

/// What a serve command listens on: TCP for HTTP/1.1 and h2, QUIC for HTTP/3.
#[derive(Debug)]
pub struct HttpListeners {
    pub tcp: Option<TcpListener>,
    pub http3: Option<Endpoint>,
}

impl HttpListeners {
    /// Bind the listeners `versions` asks for, given the TLS configuration if any.
    pub async fn bind(
        exec: Executor,
        bind: SocketAddress,
        versions: HttpVersions,
        tls: Option<&TlsServerConfig>,
        http3: &Http3Args,
    ) -> Result<Self, BoxError> {
        Self::bind_with_capture(exec, bind, versions, tls, http3, false).await
    }

    /// Bind echo/fingerprint listeners with bounded QUIC observation enabled.
    pub async fn bind_observed(
        exec: Executor,
        bind: SocketAddress,
        versions: HttpVersions,
        tls: Option<&TlsServerConfig>,
        http3: &Http3Args,
    ) -> Result<Self, BoxError> {
        Self::bind_with_capture(exec, bind, versions, tls, http3, true).await
    }

    async fn bind_with_capture(
        exec: Executor,
        bind: SocketAddress,
        versions: HttpVersions,
        tls: Option<&TlsServerConfig>,
        http3: &Http3Args,
        capture: bool,
    ) -> Result<Self, BoxError> {
        let serve_http3 = versions.http3(tls.is_some())?;
        if http3.requested() && !serve_http3 {
            return Err(BoxError::from_static_str(
                "--h3-bind, --h3-mtu-upper-bound and --h3-bootstrap-bind require HTTP/3: enable TLS and serve h3 (see --http-version)",
            ));
        }
        if http3.h3_bootstrap_bind.is_some() && versions.tcp().is_some() {
            return Err(BoxError::from_static_str(
                "--h3-bootstrap-bind is for HTTP/3-only serving (--http-version h3)",
            ));
        }
        if bind.port == 0
            && versions.tcp().is_some()
            && http3.h3_bind.is_none()
            && let Some(tls) = tls.filter(|_| serve_http3)
        {
            let (tcp, http3) =
                bind_shared_ephemeral(exec, bind, 20, !versions.http3_explicit(), |addr| {
                    bind_http3_with_capture(addr, tls, http3.h3_mtu_upper_bound, None, capture)
                })
                .await?;
            return Ok(Self {
                tcp: Some(tcp),
                http3,
            });
        }
        let bootstrap_exec = exec.clone();
        let tcp = match versions.tcp() {
            Some(_) => Some(
                TcpListener::build(exec)
                    .bind_address(bind)
                    .await
                    .context("bind TCP listener")?,
            ),
            None => None,
        };

        let listeners = Self::bind_with_tcp(
            tcp,
            bind,
            versions,
            tls.filter(|_| serve_http3),
            http3,
            capture,
        )
        .await?;
        if let (Some(addr), Some(tls), Some(alt_svc)) =
            (http3.h3_bootstrap_bind, tls, listeners.alt_svc()?)
        {
            bootstrap::serve(bootstrap_exec, addr, tls.clone(), alt_svc).await?;
        }
        Ok(listeners)
    }

    /// Complete setup while retaining the TCP listener, including when HTTP/3 cannot bind.
    async fn bind_with_tcp(
        tcp: Option<TcpListener>,
        bind: SocketAddress,
        versions: HttpVersions,
        http3_tls: Option<&TlsServerConfig>,
        http3: &Http3Args,
        capture: bool,
    ) -> Result<Self, BoxError> {
        let http3 = match http3_tls {
            Some(tls) => {
                let addr = match (http3.h3_bind, &tcp) {
                    (Some(addr), _) => addr,
                    (None, Some(tcp)) => tcp.local_addr().context("TCP listener address")?.into(),
                    (None, None) => bind,
                };
                match bind_http3_with_capture(addr, tls, http3.h3_mtu_upper_bound, None, capture)
                    .await
                {
                    Ok(endpoint) => Some(endpoint),
                    // HTTP/3 that `auto` only implied must not take h1 and h2 down with it.
                    Err(error)
                        if tcp.is_some()
                            && !versions.http3_explicit()
                            && http3.h3_bind.is_none() =>
                    {
                        tracing::error!(
                            %error,
                            network.local.address = %addr.ip_addr,
                            network.local.port = addr.port,
                            "HTTP/3 unavailable: serving HTTP/1.1 and h2 only",
                        );
                        None
                    }
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        Ok(Self { tcp, http3 })
    }

    /// The `Alt-Svc` value advertising the HTTP/3 endpoint, when serving one.
    pub fn alt_svc(&self) -> Result<Option<AltSvc>, BoxError> {
        self.http3
            .as_ref()
            .map(|endpoint| {
                let port = endpoint
                    .local_addr()
                    .context("QUIC endpoint address")?
                    .port();
                alt_svc(port)
            })
            .transpose()
    }
}

/// Bind TCP and HTTP/3 to one ephemeral port, keeping each candidate reserved
/// while checking the other transport. TCP and UDP have independent port ranges
/// and exclusions; let the transport that rejected a candidate choose the next.
pub(crate) async fn bind_shared_ephemeral<H>(
    exec: Executor,
    bind: SocketAddress,
    attempts: usize,
    allow_http3_fallback: bool,
    bind_http3: impl FnMut(SocketAddress) -> H,
) -> Result<(TcpListener, Option<Endpoint>), BoxError>
where
    H: Future<Output = Result<Endpoint, BoxError>>,
{
    bind_shared_ephemeral_with(
        bind,
        attempts,
        allow_http3_fallback,
        |addr| TcpListener::bind_address(addr, exec.clone()),
        bind_http3,
    )
    .await
}

async fn bind_shared_ephemeral_with<T, H>(
    bind: SocketAddress,
    attempts: usize,
    allow_http3_fallback: bool,
    mut bind_tcp: impl FnMut(SocketAddress) -> T,
    mut bind_http3: impl FnMut(SocketAddress) -> H,
) -> Result<(TcpListener, Option<Endpoint>), BoxError>
where
    T: Future<Output = Result<TcpListener, BoxError>>,
    H: Future<Output = Result<Endpoint, BoxError>>,
{
    debug_assert_eq!(bind.port, 0);
    debug_assert!(attempts > 0);
    let mut tcp_chooses = true;
    // Releasing rejected candidates here could make an allocator return the
    // same unusable port again. At most `attempts` sockets are retained.
    let mut rejected_tcp: Vec<TcpListener> = Vec::new();
    let mut rejected_http3: Vec<Endpoint> = Vec::new();
    let result = async {
        for attempt in 1..=attempts {
            if tcp_chooses {
                let tcp = bind_tcp(bind)
                    .await
                    .context("bind ephemeral TCP listener")?;
                let addr = tcp.local_addr().context("TCP listener address")?;
                if let Some(index) = rejected_http3
                    .iter()
                    .position(|socket| socket.local_addr().is_ok_and(|candidate| candidate == addr))
                {
                    return Ok((tcp, Some(rejected_http3.swap_remove(index))));
                }
                match bind_http3(addr.into()).await {
                    Ok(http3) => return Ok((tcp, Some(http3))),
                    Err(error) if attempt < attempts && ephemeral_bind_conflict(&error) => {
                        tracing::debug!(%error, %addr, attempt,
                            "HTTP/3 rejected the TCP port; allocating the next port with UDP");
                        rejected_tcp.push(tcp);
                        tcp_chooses = false;
                    }
                    Err(error) if allow_http3_fallback => {
                        tracing::error!(%error, %addr,
                            "HTTP/3 unavailable: serving HTTP/1.1 and h2 only");
                        return Ok((tcp, None));
                    }
                    Err(error) => {
                        return Err(error.with_context(|| {
                            format!("bind HTTP/3 on TCP ephemeral port {addr} (attempt {attempt})")
                        }));
                    }
                }
            } else {
                let endpoint = match bind_http3(bind).await {
                    Ok(endpoint) => endpoint,
                    Err(error) if allow_http3_fallback => {
                        tracing::error!(%error,
                            "HTTP/3 unavailable: serving HTTP/1.1 and h2 only");
                        let tcp = match rejected_tcp.pop() {
                            Some(tcp) => tcp,
                            None => bind_tcp(bind).await.context("bind TCP listener")?,
                        };
                        return Ok((tcp, None));
                    }
                    Err(error) => return Err(error),
                };
                let addr = match endpoint.local_addr() {
                    Ok(addr) => addr,
                    Err(error) => {
                        rejected_http3.push(endpoint);
                        return Err(error.context("QUIC endpoint address"));
                    }
                };
                if let Some(index) = rejected_tcp
                    .iter()
                    .position(|socket| socket.local_addr().is_ok_and(|candidate| candidate == addr))
                {
                    return Ok((rejected_tcp.swap_remove(index), Some(endpoint)));
                }
                match bind_tcp(addr.into()).await {
                    Ok(tcp) => return Ok((tcp, Some(endpoint))),
                    Err(error) => {
                        // Shut these endpoints down after selection, including error
                        // exits; shutdown here would release their port reservation.
                        rejected_http3.push(endpoint);
                        if attempt == attempts
                            && allow_http3_fallback
                            && ephemeral_bind_conflict(&error)
                            && let Some(tcp) = rejected_tcp.pop()
                        {
                            tracing::error!(%error, %addr, attempt,
                                "No shared HTTP/3 port available: serving HTTP/1.1 and h2 only");
                            return Ok((tcp, None));
                        }
                        if attempt == attempts || !ephemeral_bind_conflict(&error) {
                            return Err(error.with_context(|| {
                                format!(
                                    "bind TCP on HTTP/3 ephemeral port {addr} (attempt {attempt})"
                                )
                            }));
                        }
                        tracing::debug!(%error, %addr, attempt,
                            "TCP rejected the HTTP/3 port; allocating the next port with TCP");
                        tcp_chooses = true;
                    }
                }
            }
        }
        Err(BoxError::from_static_str(
            "no shared TCP and HTTP/3 ephemeral bind attempts available",
        ))
    }
    .await;
    join_all(rejected_http3.iter().map(Endpoint::shutdown)).await;
    drop(rejected_tcp);
    result
}

fn ephemeral_bind_conflict(error: &BoxError) -> bool {
    error_chain(error.as_ref()).any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            error.kind() == std::io::ErrorKind::AddrInUse
                // Winsock also uses WSAEACCES for excluded/exclusively held ports.
                // Other permission errors are not evidence of a port conflict.
                || (cfg!(target_os = "windows") && error.raw_os_error() == Some(10013))
        })
    })
}

/// Bind QUIC on `addr` for HTTP/3, presenting the identity of `tls` and offering only `h3`.
///
/// Certificates issued per ClientHello are supported, sharing the issuer cache with `tls`;
/// a client asking for one the cache lacks first proves its address with a Retry.
/// The endpoint stays outside graceful shutdown, so HTTP/3 can drain its connections first;
/// serve it with [`Http3Endpoints::serve`].
pub async fn bind_http3(addr: SocketAddress, tls: &TlsServerConfig) -> Result<Endpoint, BoxError> {
    bind_http3_with_capture(addr, tls, None, None, false).await
}

/// [`bind_http3`] with connections starting from `transport`, such as the room and idle
/// timeout a MASQUE proxy's connections need; HTTP/3 limits are applied on top.
pub async fn bind_http3_with_transport(
    addr: SocketAddress,
    tls: &TlsServerConfig,
    transport: TransportConfig,
) -> Result<Endpoint, BoxError> {
    bind_http3_with_capture(addr, tls, None, Some(transport), false).await
}

async fn bind_http3_with_capture(
    addr: SocketAddress,
    tls: &TlsServerConfig,
    mtu_upper_bound: Option<u16>,
    transport: Option<TransportConfig>,
    capture: bool,
) -> Result<Endpoint, BoxError> {
    let tls = tls
        .clone()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = transport.unwrap_or_default();
    Config::default()
        .configure_transport(&mut transport)
        .context("HTTP/3 transport limits")?;
    if let Some(upper_bound) = mtu_upper_bound {
        transport
            .set_mtu_discovery_config(MtuDiscoveryConfig::default().with_upper_bound(upper_bound));
    }
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .context("QUIC TLS server config")?;
    config.set_transport_config(Arc::new(transport));
    if capture {
        config.set_capture(CaptureLimits::default());
    }
    let builder = Endpoint::build(Executor::new()).with_server_config(config);
    #[cfg(target_os = "windows")]
    let endpoint = builder
        .bind_address_with_socket_config(addr, exclusive_socket_config())
        .await;
    #[cfg(not(target_os = "windows"))]
    let endpoint = builder.bind_address(addr).await;
    endpoint.context("bind QUIC endpoint for HTTP/3")
}

/// Rama's QUIC socket defaults, with the port bound exclusively: Windows would otherwise let
/// another socket take its traffic by binding it on a more specific address, while `Alt-Svc`
/// still advertises it.
#[cfg(target_os = "windows")]
fn exclusive_socket_config() -> UdpSocketConfig {
    let config = UdpSocketConfig::default().with_min_buffer_size(DEFAULT_SOCKET_BUFFER_SIZE);
    let options = SocketOptions {
        exclusive_address_use: Some(true),
        ..config.socket_options().clone()
    };
    config.with_socket_options(options)
}

/// The HTTP/3 endpoints a serve command serves, so they can be closed when graceful shutdown
/// runs out of time: unlike a TCP peer, a QUIC peer gets no reset from an exited process and
/// would wait out its idle timeout.
#[derive(Debug, Clone, Default)]
pub struct Http3Endpoints(Arc<Mutex<Vec<Endpoint>>>);

impl Http3Endpoints {
    /// Serve the HTTP/3 connections of `endpoint` with `service` on the graceful `exec`.
    pub fn serve<S>(&self, exec: &Executor, name: &str, endpoint: Endpoint, service: S)
    where
        S: Service<Connection> + Clone,
    {
        match endpoint.local_addr() {
            Ok(addr) => tracing::info!(
                network.local.address = %addr.ip(),
                network.local.port = %addr.port(),
                "{name} HTTP/3 service ready: bind interface = {addr}",
            ),
            Err(error) => tracing::warn!(%error, "{name} HTTP/3 service ready: unknown address"),
        }
        self.0.lock().push(endpoint.clone());
        exec.spawn_task(endpoint.serve(exec.clone(), service));
    }

    /// Close every endpoint served, waiting at most `within` for their peers to be told.
    pub async fn shutdown(&self, within: Duration) {
        let endpoints = std::mem::take(&mut *self.0.lock());
        _ = tokio::time::timeout(within, join_all(endpoints.iter().map(Endpoint::shutdown))).await;
    }
}

/// The `Alt-Svc` value advertising HTTP/3 on `port` of the origin host (RFC 9114 §3.1.1).
pub fn alt_svc(port: u16) -> Result<AltSvc, BoxError> {
    Ok(AltSvc::new(AlternativeService::new(
        ApplicationProtocol::HTTP_3,
        port,
    )?))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use clap::Parser;
    use rama::{
        extensions::ExtensionsRef as _,
        quic::{ClientConfig, ConnectionError, proto::capture::QuicObservation},
        service::service_fn,
        tls::{
            client::{ServerVerifyMode, TlsClientConfig},
            server::{GeneratedServerAuthConfig, ServerAuthData},
        },
    };

    use super::*;

    fn tls() -> TlsServerConfig {
        TlsServerConfig::new().with_server_auth(
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap(),
        )
    }

    fn localhost() -> SocketAddress {
        SocketAddress::local_ipv4(0)
    }

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        http3: Http3Args,
    }

    #[test]
    fn mtu_upper_bound_accepts_only_quic_sized_payloads() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(["rama"].iter().chain(args)).map(|cli| cli.http3.h3_mtu_upper_bound)
        };
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(
            parse(&["--h3-mtu-upper-bound", "1280"]).unwrap(),
            Some(1280)
        );
        parse(&["--h3-mtu-upper-bound", "1199"]).unwrap_err();
    }

    #[tokio::test]
    async fn http3_shares_the_port_of_the_tcp_listener_by_default() {
        let listeners = HttpListeners::bind(
            Executor::new(),
            localhost(),
            HttpVersions::AUTO,
            Some(&tls()),
            &Http3Args {
                h3_bind: None,
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            },
        )
        .await
        .unwrap();
        let tcp = listeners.tcp.as_ref().unwrap().local_addr().unwrap();
        let quic = listeners.http3.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(tcp, quic);
        assert_eq!(
            listeners.alt_svc().unwrap(),
            Some(alt_svc(quic.port()).unwrap())
        );
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_escape_conflicts_in_both_transports() {
        use std::cell::RefCell;

        let tcp_candidates = &RefCell::new(Vec::<std::net::SocketAddr>::new());
        let udp_candidates = &RefCell::new(Vec::<std::net::SocketAddr>::new());
        let (available_tcp, available_udp, _) = occupied_udp_port().await;
        let available_tcp = &RefCell::new(Some(available_tcp));
        let available_udp = &RefCell::new(Some(available_udp));
        let (tcp, http3) = bind_shared_ephemeral_with(
            localhost(),
            20,
            false,
            |addr: SocketAddress| async move {
                if addr.port != 0 {
                    // Model a UDP-selected port unavailable to TCP. An allocator
                    // that only asks UDP for candidates can never escape this.
                    return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                }
                for rejected in tcp_candidates.borrow().iter() {
                    assert!(
                        std::net::TcpListener::bind(rejected).is_err(),
                        "a rejected TCP candidate must stay reserved during selection"
                    );
                }
                for rejected in udp_candidates.borrow().iter() {
                    assert!(
                        std::net::UdpSocket::bind(rejected).is_err(),
                        "a rejected UDP candidate must stay reserved during selection"
                    );
                }
                let first_candidate = tcp_candidates.borrow().is_empty();
                let tcp = if first_candidate {
                    TcpListener::bind_address(addr, Executor::new()).await?
                } else {
                    available_tcp.borrow_mut().take().unwrap()
                };
                tcp_candidates.borrow_mut().push(tcp.local_addr()?);
                Ok(tcp)
            },
            |addr: SocketAddress| async move {
                if addr.port != 0 && tcp_candidates.borrow().len() == 1 {
                    // The first TCP candidate is independently unavailable to UDP.
                    return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse)
                        .context("wrapped UDP bind failure"));
                }
                if addr.port == 0 {
                    let endpoint = Endpoint::build(Executor::new()).bind_address(addr).await?;
                    udp_candidates.borrow_mut().push(endpoint.local_addr()?);
                    Ok(endpoint)
                } else {
                    let endpoint = available_udp.borrow_mut().take().unwrap();
                    assert_eq!(SocketAddress::from(endpoint.local_addr()?), addr);
                    Ok(endpoint)
                }
            },
        )
        .await
        .unwrap();
        let http3 = http3.unwrap();
        assert_eq!(tcp_candidates.borrow().len(), 2);
        assert_eq!(udp_candidates.borrow().len(), 1);
        assert_eq!(tcp.local_addr().unwrap(), http3.local_addr().unwrap());
        // Both rejected reservations have been released before returning.
        let _tcp = std::net::TcpListener::bind(tcp_candidates.borrow()[0]).unwrap();
        let _udp = std::net::UdpSocket::bind(udp_candidates.borrow()[0]).unwrap();
        http3.shutdown().await;
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_reuse_retained_counterparts() {
        use std::cell::{Cell, RefCell};

        for reuse_tcp in [false, true] {
            let (available_tcp, available_udp, addr) = occupied_udp_port().await;
            let available_tcp = &RefCell::new(Some(available_tcp));
            let available_udp = &RefCell::new(Some(available_udp));
            let tcp_calls = &Cell::new(0);
            let (tcp, http3) = bind_shared_ephemeral_with(
                localhost(),
                20,
                false,
                |requested: SocketAddress| async move {
                    if requested.port != 0 {
                        assert!(!reuse_tcp, "reuse TCP instead of binding its address again");
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    tcp_calls.set(tcp_calls.get() + 1);
                    if !reuse_tcp && tcp_calls.get() == 1 {
                        return TcpListener::bind_address(requested, Executor::new()).await;
                    }
                    Ok(available_tcp.borrow_mut().take().unwrap())
                },
                |requested: SocketAddress| async move {
                    if requested.port != 0 {
                        assert_eq!(
                            tcp_calls.get(),
                            1,
                            "reuse UDP instead of binding its address again"
                        );
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    Ok(available_udp.borrow_mut().take().unwrap())
                },
            )
            .await
            .unwrap();
            let http3 = http3.unwrap();
            assert_eq!(tcp.local_addr().unwrap(), addr);
            assert_eq!(http3.local_addr().unwrap(), addr);
            http3.shutdown().await;
        }
    }

    #[tokio::test]
    async fn cancelling_shared_ephemeral_selection_releases_retained_sockets() {
        use std::cell::{Cell, RefCell};

        let tcp_addr = &Cell::new(None);
        let udp_addr = &Cell::new(None);
        let udp_port_tcp_guard = &RefCell::new(None);
        let selecting_next_port = &tokio::sync::Notify::new();
        {
            let selection = bind_shared_ephemeral_with(
                localhost(),
                20,
                false,
                |addr: SocketAddress| async move {
                    if addr.port != 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    if tcp_addr.get().is_some() {
                        selecting_next_port.notify_one();
                        return std::future::pending().await;
                    }
                    let tcp = TcpListener::bind_address(addr, Executor::new()).await?;
                    tcp_addr.set(Some(tcp.local_addr()?));
                    Ok(tcp)
                },
                |addr: SocketAddress| async move {
                    if addr.port != 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    // Reserve the opposite transport too, so this candidate cannot
                    // coincide with and reuse the first retained TCP listener.
                    let (guard, endpoint, addr) = occupied_udp_port().await;
                    *udp_port_tcp_guard.borrow_mut() = Some(guard);
                    udp_addr.set(Some(addr));
                    Ok(endpoint)
                },
            );
            tokio::pin!(selection);
            tokio::select! {
                _ = &mut selection => panic!("selection should be waiting for its third candidate"),
                _ = selecting_next_port.notified() => {},
            }
            // Dropping the selection cancels the pending bind and drops both
            // rejected reservations, without calling their explicit cleanup.
        }
        let _tcp = std::net::TcpListener::bind(tcp_addr.get().unwrap()).unwrap();
        // Endpoint Drop wakes its driver; allow that asynchronous teardown to run.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match std::net::UdpSocket::bind(std::net::SocketAddr::from(udp_addr.get().unwrap()))
                {
                    Ok(socket) => break socket,
                    Err(error) => {
                        let error: BoxError = error.into();
                        assert!(
                            ephemeral_bind_conflict(&error),
                            "rebind UDP after cancellation: {error}"
                        );
                        tokio::task::yield_now().await;
                    }
                }
            }
        })
        .await
        .expect("cancelled selection must release its endpoint driver and UDP reservation");
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_propagate_non_conflict_errors() {
        use std::cell::Cell;

        let calls = &Cell::new(0);
        let error = bind_shared_ephemeral_with(
            localhost(),
            20,
            false,
            |addr| TcpListener::bind_address(addr, Executor::new()),
            |_| async move {
                calls.set(calls.get() + 1);
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)
                    .context("HTTP/3 permission failure"))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            calls.get(),
            1,
            "a generic permission failure is not a port collision"
        );
        assert!(error.to_string().contains("HTTP/3 permission failure"));

        let calls = &Cell::new(0);
        let error = bind_shared_ephemeral_with(
            localhost(),
            20,
            false,
            |_| async move {
                calls.set(calls.get() + 1);
                Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into())
            },
            |_| async {
                panic!("failed ephemeral allocation must propagate before binding HTTP/3")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert!(error.to_string().contains("bind ephemeral TCP listener"));
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_release_reservations_after_exhaustion() {
        use std::cell::RefCell;

        let tcp_candidates = &RefCell::new(Vec::<std::net::SocketAddr>::new());
        let udp_candidates = &RefCell::new(Vec::<std::net::SocketAddr>::new());
        let tcp_guards = &RefCell::new(Vec::new());
        let udp_guards = &RefCell::new(Vec::new());
        let error = bind_shared_ephemeral_with(
            localhost(),
            20,
            false,
            |addr: SocketAddress| async move {
                if addr.port != 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                }
                let (tcp, guard, _) = occupied_udp_port().await;
                udp_guards.borrow_mut().push(guard);
                tcp_candidates.borrow_mut().push(tcp.local_addr()?);
                Ok(tcp)
            },
            |addr: SocketAddress| async move {
                if addr.port != 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse)
                        .context("wrapped UDP bind failure"));
                }
                let (guard, endpoint, _) = occupied_udp_port().await;
                tcp_guards.borrow_mut().push(guard);
                udp_candidates.borrow_mut().push(endpoint.local_addr()?);
                Ok(endpoint)
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("attempt 20"), "{error}");
        assert_eq!(tcp_candidates.borrow().len(), 10);
        assert_eq!(udp_candidates.borrow().len(), 10);
        for addr in tcp_candidates.borrow().iter() {
            let _tcp = std::net::TcpListener::bind(addr).unwrap();
        }
        for addr in udp_candidates.borrow().iter() {
            let _udp = std::net::UdpSocket::bind(addr).unwrap();
        }
        let udp_guards = std::mem::take(&mut *udp_guards.borrow_mut());
        join_all(udp_guards.iter().map(Endpoint::shutdown)).await;
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_keep_tcp_when_implied_http3_is_unavailable() {
        let (tcp, http3) = bind_shared_ephemeral_with(
            localhost(),
            20,
            true,
            |addr| TcpListener::bind_address(addr, Executor::new()),
            |_| async { Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into()) },
        )
        .await
        .unwrap();
        assert!(http3.is_none());
        let addr = tcp.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
    }

    #[tokio::test]
    async fn shared_ephemeral_ports_keep_tcp_after_implied_http3_conflicts() {
        use std::cell::RefCell;

        for exhaust_candidates in [false, true] {
            let tcp_guards = &RefCell::new(Vec::new());
            let udp_guards = &RefCell::new(Vec::new());
            let (tcp, http3) = bind_shared_ephemeral_with(
                localhost(),
                20,
                true,
                |addr: SocketAddress| async move {
                    if addr.port != 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    let (tcp, guard, _) = occupied_udp_port().await;
                    udp_guards.borrow_mut().push(guard);
                    Ok(tcp)
                },
                |addr: SocketAddress| async move {
                    if addr.port != 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into());
                    }
                    if !exhaust_candidates {
                        return Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into());
                    }
                    let (guard, endpoint, _) = occupied_udp_port().await;
                    tcp_guards.borrow_mut().push(guard);
                    Ok(endpoint)
                },
            )
            .await
            .unwrap();
            assert!(http3.is_none());
            let _client = std::net::TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
            let udp_guards = std::mem::take(&mut *udp_guards.borrow_mut());
            join_all(udp_guards.iter().map(Endpoint::shutdown)).await;
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn excluded_windows_ephemeral_ports_are_conflicts() {
        let error = std::io::Error::from_raw_os_error(10013).context("UDP bind");
        assert!(ephemeral_bind_conflict(&error));
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
        assert!(!ephemeral_bind_conflict(&error));
    }

    #[tokio::test]
    async fn listener_capture_is_explicit_and_survives_tcp_setup() {
        for capture in [false, true] {
            let versions = "h1,h2,h3".parse().unwrap();
            let tls = tls();
            let http3 = Http3Args {
                h3_bind: None,
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            };
            let listeners = if capture {
                HttpListeners::bind_observed(
                    Executor::new(),
                    localhost(),
                    versions,
                    Some(&tls),
                    &http3,
                )
                .await
            } else {
                HttpListeners::bind(Executor::new(), localhost(), versions, Some(&tls), &http3)
                    .await
            }
            .unwrap();
            let server = listeners.http3.as_ref().unwrap();
            let client = Endpoint::build(Executor::new())
                .bind_address(localhost())
                .await
                .unwrap();
            let config = ClientConfig::try_from_rama_tls_with_provider(
                &TlsClientConfig::new()
                    .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                    .with_server_verify(ServerVerifyMode::Disable),
                TlsOptions::default(),
                &BoringTlsProvider,
            )
            .unwrap();
            let connecting = client
                .connect_with(config, server.local_addr().unwrap(), "localhost")
                .unwrap();
            let (client_connection, server_connection) =
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(connecting, async { server.accept().await.unwrap().await })
                })
                .await
                .unwrap();
            let client_connection = client_connection.unwrap();
            let server_connection = server_connection.unwrap();
            assert_eq!(
                server_connection
                    .extensions()
                    .get_ref::<QuicObservation>()
                    .is_some(),
                capture
            );
            client_connection.close(0u8, b"done");
            server_connection.close(0u8, b"done");
            tokio::join!(client.shutdown(), server.shutdown());
        }
    }

    #[tokio::test]
    async fn no_http3_without_tls_or_when_left_out() {
        for (versions, tls) in [
            (HttpVersions::AUTO, None),
            ("h1,h2".parse().unwrap(), Some(tls())),
        ] {
            let listeners = HttpListeners::bind(
                Executor::new(),
                localhost(),
                versions,
                tls.as_ref(),
                &Http3Args {
                    h3_bind: None,
                    h3_mtu_upper_bound: None,
                    h3_bootstrap_bind: None,
                },
            )
            .await
            .unwrap();
            assert!(listeners.tcp.is_some());
            assert!(listeners.http3.is_none());
            assert_eq!(listeners.alt_svc().unwrap(), None);
        }
    }

    #[tokio::test]
    async fn h3_bind_requires_http3() {
        let error = HttpListeners::bind(
            Executor::new(),
            localhost(),
            "h1,h2".parse().unwrap(),
            Some(&tls()),
            &Http3Args {
                h3_bind: Some(localhost()),
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--h3-bind"), "{error}");
    }

    #[tokio::test]
    async fn h3_bootstrap_is_only_for_http3_only_serving() {
        let args = Http3Args {
            h3_bind: None,
            h3_mtu_upper_bound: None,
            h3_bootstrap_bind: Some(localhost()),
        };
        let error = HttpListeners::bind(
            Executor::new(),
            localhost(),
            HttpVersions::AUTO,
            Some(&tls()),
            &args,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--h3-bootstrap-bind"), "{error}");
        let listeners = HttpListeners::bind(
            Executor::new(),
            localhost(),
            "h3".parse().unwrap(),
            Some(&tls()),
            &args,
        )
        .await
        .unwrap();
        assert!(listeners.tcp.is_none() && listeners.http3.is_some());
    }

    /// Retain both transports so that only the subsequent HTTP/3 bind can fail.
    async fn occupied_udp_port() -> (TcpListener, Endpoint, SocketAddress) {
        let (tcp, endpoint) =
            bind_shared_ephemeral(Executor::new(), localhost(), 20, false, |addr| async move {
                Ok(Endpoint::build(Executor::new()).bind_address(addr).await?)
            })
            .await
            .unwrap();
        let addr = tcp.local_addr().unwrap().into();
        (tcp, endpoint.unwrap(), addr)
    }

    #[tokio::test]
    async fn implied_http3_that_cannot_bind_leaves_h1_and_h2_serving() {
        let (tcp, _held, addr) = occupied_udp_port().await;
        let listeners = HttpListeners::bind_with_tcp(
            Some(tcp),
            addr,
            HttpVersions::AUTO,
            Some(&tls()),
            &Http3Args {
                h3_bind: None,
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            },
            false,
        )
        .await
        .unwrap();
        let tcp = listeners.tcp.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(tcp, addr);
        assert!(listeners.http3.is_none());
        assert_eq!(listeners.alt_svc().unwrap(), None, "nothing to advertise");
    }

    #[tokio::test]
    async fn explicit_http3_that_cannot_bind_is_an_error() {
        for explicit_bind in [false, true] {
            let (tcp, _held, addr) = occupied_udp_port().await;
            let (versions, h3_bind) = if explicit_bind {
                (HttpVersions::AUTO, Some(addr))
            } else {
                ("h1,h2,h3".parse().unwrap(), None)
            };
            let result = HttpListeners::bind_with_tcp(
                Some(tcp),
                addr,
                versions,
                Some(&tls()),
                &Http3Args {
                    h3_bind,
                    h3_mtu_upper_bound: None,
                    h3_bootstrap_bind: None,
                },
                false,
            )
            .await;
            let Err(error) = result else {
                panic!("{versions:?} with --h3-bind {h3_bind:?} must fail");
            };
            assert!(error.to_string().contains("QUIC"), "{error}");
        }
    }

    #[tokio::test]
    async fn http3_alone_binds_no_tcp_listener() {
        let listeners = HttpListeners::bind(
            Executor::new(),
            localhost(),
            "h3".parse().unwrap(),
            Some(&tls()),
            &Http3Args {
                h3_bind: None,
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            },
        )
        .await
        .unwrap();
        assert!(listeners.tcp.is_none());
        let quic = listeners.http3.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(
            listeners.alt_svc().unwrap(),
            Some(alt_svc(quic.port()).unwrap())
        );
    }

    /// Shutting the served endpoints down tells their peers at once, instead of leaving them to
    /// their idle timeout.
    #[tokio::test]
    async fn shutting_served_endpoints_down_closes_their_connections() {
        let endpoint = bind_http3(localhost(), &tls()).await.unwrap();
        let addr = endpoint.local_addr().unwrap();
        let served = Http3Endpoints::default();
        served.serve(
            &Executor::new(),
            "test",
            endpoint,
            service_fn(async |connection: Connection| {
                _ = connection.closed().await;
                Ok::<_, Infallible>(())
            }),
        );

        let client = Endpoint::build(Executor::new())
            .bind_address(localhost())
            .await
            .unwrap();
        let config = ClientConfig::try_from_rama_tls_with_provider(
            &TlsClientConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_verify(ServerVerifyMode::Disable),
            TlsOptions::default(),
            &BoringTlsProvider,
        )
        .unwrap();
        let connection = client
            .connect_with(config, addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        served.shutdown(Duration::from_secs(1)).await;
        let error = tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("the peer is told at once");
        assert!(!matches!(error, ConnectionError::TimedOut), "{error:?}");
    }
}
