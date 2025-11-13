//! Echo service that echos the http request and tls client config
//! when using in HTTP(S) mode or else when using in udp/tcp/tls mode
//! it simply echos the bytes back.

use rama::{
    Layer as _,
    cli::{ForwardKind, service::echo::EchoServiceBuilder},
    combinators::Either,
    error::{BoxError, ErrorContext, ErrorExt as _, OpaqueError},
    graceful::ShutdownGuard,
    layer::{
        ConsumeErrLayer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, UnlimitedPolicy},
    },
    net::{
        socket::Interface,
        stream::service::EchoService,
        tls::{ApplicationProtocol, server::ServerConfig},
    },
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, Instrument},
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
    ua::profile::UserAgentDatabase,
    udp::UdpSocket,
};

use clap::{Args, ValueEnum};
use std::{fmt, sync::Arc, time::Duration};
use tokio::sync::mpsc::Sender;

use crate::utils::{http::HttpVersion, tls::new_server_config};

#[derive(Debug, Clone, Args)]
/// rama echo service (rich https echo or else raw tcp/udp bytes)
pub struct CliCommandEcho {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(short = 'c', long)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit),
    /// not supppoted in UDP mode
    concurrent: Option<usize>,

    #[arg(short = 't', long)]
    /// the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    /// Default is 300s, unless in UDP mode, there no timeout is supported.
    timeout: Option<u64>,

    #[arg(long, short = 'f')]
    /// enable support for one of the following "forward" headers or protocols
    ///
    /// Supported headers:
    ///
    /// Forwarded ("for="), X-Forwarded-For
    ///
    /// X-Client-IP Client-IP, X-Real-IP
    ///
    /// CF-Connecting-IP, True-Client-IP
    ///
    /// Or using HaProxy protocol.
    ///
    /// Headers only available in http(s) mode.
    forward: Option<ForwardKind>,

    #[arg(long, default_value_t = Default::default())]
    /// the transport mode to use
    mode: Mode,

    /// http version to serve echo Service from (only in http(s) mode)
    #[arg(long, default_value = "auto")]
    http_version: HttpVersion,

    #[arg(long)]
    /// enable ws support (only in http(s) mode)
    ws: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum Mode {
    /// Bind Echo service directly on top of TCP
    Tcp,
    /// Bind discard service directly on top of UDP
    Udp,
    /// Bind discard service directly on top of TCP over TLS.
    ///
    /// Meaning that the TLS connection will be established,
    /// prior to the echo'ng of bytes kicking in.
    Tls,
    /// Serve the echo service in http mode
    #[default]
    Http,
    /// Serve the echo service in http mode over TLS
    Https,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp => "tcp",
                Self::Udp => "udp",
                Self::Tls => "tls",
                Self::Http => "http",
                Self::Https => "https",
            }
        )
    }
}

/// run the rama echo service
pub async fn run(
    graceful: ShutdownGuard,
    etx: Sender<OpaqueError>,
    cfg: CliCommandEcho,
) -> Result<(), BoxError> {
    let maybe_tls_server_config = matches!(cfg.mode, Mode::Tls | Mode::Https).then(|| {
        tracing::info!("create tls server config...");
        new_server_config(matches!(cfg.mode, Mode::Http | Mode::Https).then(|| {
            match cfg.http_version {
                HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
                HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
                HttpVersion::Auto => {
                    vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                }
            }
        }))
    });

    match cfg.mode {
        Mode::Tcp | Mode::Tls => {
            bind_echo_tcp_service(graceful, cfg.clone(), maybe_tls_server_config).await?
        }
        Mode::Udp => {
            bind_echo_udp_service(graceful, cfg.clone(), maybe_tls_server_config, etx.clone())
                .await?
        }
        Mode::Http | Mode::Https => {
            bind_echo_http_service(graceful, cfg.clone(), maybe_tls_server_config).await?
        }
    }

    Ok(())
}

async fn bind_echo_http_service(
    graceful: ShutdownGuard,
    cfg: CliCommandEcho,
    maybe_tls_config: Option<ServerConfig>,
) -> Result<(), OpaqueError> {
    let tcp_service = EchoServiceBuilder::new()
        .with_concurrent(cfg.concurrent.unwrap_or_default())
        .with_timeout(Duration::from_secs(cfg.timeout.unwrap_or(300)))
        .with_ws_support(cfg.ws)
        .maybe_with_http_version(cfg.http_version.into())
        .maybe_with_forward(cfg.forward)
        .maybe_with_tls_server_config(maybe_tls_config)
        .with_user_agent_database(Arc::new(UserAgentDatabase::embedded()))
        .build(Executor::graceful(graceful.clone()))
        .map_err(OpaqueError::from_boxed)
        .context("build http(s) echo service")?;

    tracing::info!(
        "starting http(s) echo service: bind interface = {:?}",
        cfg.bind
    );
    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind tcp socker for http(s) echo service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let span =
        tracing::trace_root_span!("echo", otel.kind = "server", network.protocol.name = "http");

    graceful.into_spawn_task_fn(async move |guard| {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "http(s) echo service ready: bind interface = {}", cfg.bind,
        );

        tcp_listener
            .serve_graceful(guard, tcp_service)
            .instrument(span)
            .await;
    });

    Ok(())
}

async fn bind_echo_tcp_service(
    graceful: ShutdownGuard,
    cfg: CliCommandEcho,
    maybe_tls_config: Option<ServerConfig>,
) -> Result<(), OpaqueError> {
    if cfg.ws {
        return Err(OpaqueError::from_display(
            "websocket support is only possible in http(s) mode",
        ));
    }
    if cfg.http_version != HttpVersion::Auto {
        return Err(OpaqueError::from_display(
            "http version selection is only possible in http(s) mode",
        ));
    }

    let with_ha_proxy = match cfg.forward {
        Some(
            ForwardKind::Forwarded
            | ForwardKind::XForwardedFor
            | ForwardKind::XClientIp
            | ForwardKind::ClientIp
            | ForwardKind::XRealIp
            | ForwardKind::CFConnectingIp
            | ForwardKind::TrueClientIp,
        ) => {
            return Err(OpaqueError::from_display(
                "forward http headers are only possible in http(s) mode",
            ));
        }
        Some(ForwardKind::HaProxy) => true,
        None => false,
    };

    let maybe_tls_data: Option<TlsAcceptorData> = if let Some(tls_config) = maybe_tls_config {
        Some(tls_config.try_into()?)
    } else {
        None
    };

    let concurrent = cfg.concurrent.unwrap_or_default();
    let timeout = cfg.timeout.unwrap_or(300);

    let middleware = (
        ConsumeErrLayer::trace(tracing::Level::DEBUG),
        LimitLayer::new(if concurrent > 0 {
            Either::A(ConcurrentPolicy::max(concurrent))
        } else {
            Either::B(UnlimitedPolicy::new())
        }),
        if timeout > 0 {
            TimeoutLayer::new(Duration::from_secs(timeout))
        } else {
            TimeoutLayer::never()
        },
        with_ha_proxy.then(|| HaProxyLayer::new().with_peek(true)),
        maybe_tls_data.map(TlsAcceptorLayer::new),
    );
    let echo_svc = middleware.into_layer(EchoService::new());

    tracing::info!("starting TCP echo service: bind interface = {:?}", cfg.bind);
    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind TCP echo service socket")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let span =
        tracing::trace_root_span!("echo", otel.kind = "server", network.protocol.name = "tcp");

    graceful.into_spawn_task_fn(async move |guard| {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "tcp echo service ready: bind interface = {}", cfg.bind,
        );

        tcp_listener
            .serve_graceful(guard, echo_svc)
            .instrument(span)
            .await;
    });

    Ok(())
}

async fn bind_echo_udp_service(
    graceful: ShutdownGuard,
    cfg: CliCommandEcho,
    maybe_tls_config: Option<ServerConfig>,
    etx: tokio::sync::mpsc::Sender<OpaqueError>,
) -> Result<(), OpaqueError> {
    if cfg.ws {
        return Err(OpaqueError::from_display(
            "websocket support is only possible in http(s) mode",
        ));
    }
    if cfg.http_version != HttpVersion::Auto {
        return Err(OpaqueError::from_display(
            "http version selection is only possible in http(s) mode",
        ));
    }
    if maybe_tls_config.is_some() {
        return Err(OpaqueError::from_display(
            "TLS is not supported for UDP mode",
        ));
    }
    if cfg.forward.is_some() {
        return Err(OpaqueError::from_display(
            "Forward info capabilities is not supported for UDP mode",
        ));
    }
    if cfg.timeout.is_some() {
        return Err(OpaqueError::from_display(
            "connection timeout is not supported for UDP mode",
        ));
    }

    tracing::info!("starting UDP echo service: bind interface = {:?}", cfg.bind);
    let udp_socket = UdpSocket::bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind UDP echo service socket")?;

    let bind_address = udp_socket
        .local_addr()
        .context("get local addr of udp socket")?;

    let span =
        tracing::trace_root_span!("echo", otel.kind = "server", network.protocol.name = "udp");

    graceful.into_spawn_task_fn(move |guard| {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "udp echo service ready: bind interface = {}", cfg.bind,
        );

        let shared_udp_socket = Arc::new(udp_socket);

        let concurrent = cfg.concurrent.unwrap_or_default();
        let semaphore = tokio::sync::Semaphore::new(if concurrent == 0 {
            tokio::sync::Semaphore::MAX_PERMITS
        } else {
            concurrent
        });

        async move {
            let weak_guard = guard.downgrade();
            let mut buf = [0; 1024];

            loop {
                let permit = match semaphore.acquire().await {
                    Ok(permit) => permit,
                    Err(err) => {
                        etx.send(err.context("acquire concurrency permit"))
                            .await
                            .unwrap();
                        return;
                    }
                };

                let (len, addr) = match shared_udp_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        tracing::trace!("{len} bytes received from {addr}");
                        (len, addr)
                    }
                    Err(err) => {
                        etx.send(err.context("receive bytes from udp socket"))
                            .await
                            .unwrap();
                        return;
                    }
                };

                let socket = shared_udp_socket.clone();
                let data = buf[..len].to_vec();
                weak_guard.clone().upgrade().into_spawn_task(async move {
                    let _ = permit;
                    match socket.send_to(&data, addr).await {
                        Ok(len) => {
                            tracing::trace!("sent {len} bytes sent to {addr}");
                        }
                        Err(err) => {
                            tracing::debug!("failed to send bytes sent to {addr}: {err}");
                        }
                    }
                });
            }
        }
        .instrument(span)
    });

    Ok(())
}
