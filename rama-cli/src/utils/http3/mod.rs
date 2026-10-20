//! Serving HTTP/3 next to the TCP listener of a serve command.

use std::{sync::Arc, time::Duration};

use clap::{Args, value_parser};
use parking_lot::Mutex;
use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
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
                match bind_http3_with_capture(addr, tls, http3.h3_mtu_upper_bound, capture).await {
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

/// Bind QUIC on `addr` for HTTP/3, presenting the identity of `tls` and offering only `h3`.
///
/// Certificates issued per ClientHello are supported, sharing the issuer cache with `tls`;
/// a client asking for one the cache lacks first proves its address with a Retry.
/// The endpoint stays outside graceful shutdown, so HTTP/3 can drain its connections first;
/// serve it with [`Http3Endpoints::serve`].
pub async fn bind_http3(addr: SocketAddress, tls: &TlsServerConfig) -> Result<Endpoint, BoxError> {
    bind_http3_with_capture(addr, tls, None, false).await
}

async fn bind_http3_with_capture(
    addr: SocketAddress,
    tls: &TlsServerConfig,
    mtu_upper_bound: Option<u16>,
    capture: bool,
) -> Result<Endpoint, BoxError> {
    let tls = tls
        .clone()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = TransportConfig::default();
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
    async fn listener_capture_is_explicit_and_survives_tcp_setup() {
        for capture in [false, true] {
            let versions = "h1,h2,h3".parse().unwrap();
            let tls = tls();
            let http3 = Http3Args {
                h3_bind: None,
                h3_mtu_upper_bound: None,
                h3_bootstrap_bind: None,
            };
            // HTTP/3 reuses the OS-picked TCP port, whose UDP twin another process may hold.
            let mut attempts = 0;
            let listeners = loop {
                let bound = if capture {
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
                };
                attempts += 1;
                match bound {
                    Err(_) if attempts < 20 => {}
                    bound => break bound.unwrap(),
                }
            };
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
    fn occupied_udp_port() -> (TcpListener, std::net::UdpSocket, SocketAddress) {
        let mut last_conflict = None;

        for _ in 0..100 {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = tcp.local_addr().unwrap();
            match std::net::UdpSocket::bind(addr) {
                Ok(udp) => {
                    let tcp = TcpListener::try_from_std_tcp_listener(tcp, Executor::new()).unwrap();
                    return (tcp, udp, addr.into());
                }
                // Windows can exclude a UDP port that TCP was allowed to use.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    last_conflict = Some(error);
                }
                Err(error) => panic!("bind UDP conflict fixture: {error}"),
            }
        }

        panic!("could not bind a shared TCP/UDP port within 100 attempts: {last_conflict:?}");
    }

    #[tokio::test]
    async fn implied_http3_that_cannot_bind_leaves_h1_and_h2_serving() {
        let (tcp, _held, addr) = occupied_udp_port();
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
            let (tcp, _held, addr) = occupied_udp_port();
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
