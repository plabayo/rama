//! rama ip service

use rama::{
    Service,
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    graceful::ShutdownGuard,
    net::{
        address::{SocketAddress, ip::geo::IpGeoDb},
        tls::ApplicationProtocol,
    },
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing,
};

use clap::Args;
use std::{convert::Infallible, sync::Arc, time::Duration};

use crate::utils::{
    http::{HttpVersions, TcpHttpVersion},
    http3::{Http3Args, HttpListeners, serve_http3},
    rate::opt_per_sec,
    tls::try_new_server_config,
};

#[derive(Debug, Args)]
/// rama ip service (returns the ip address of the client)
pub struct CliCommandIp {
    /// the address to bind to
    #[arg(long, default_value_t = SocketAddress::local_ipv4(8080))]
    bind: SocketAddress,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value = "300")]
    /// the timeout in seconds for each connection
    timeout: u64,

    #[arg(long, default_value_t = 0)]
    /// rate limit the service, in requests per second (http mode)
    /// or new connections per second (transport mode)
    ///
    /// (0 = no limit)
    rate: u64,

    #[arg(long, default_value_t = 0)]
    /// throttle each connection at the given byte rate
    /// (bytes per second, both directions)
    ///
    /// (0 = no throttling)
    throttle: u64,

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
    forward: Option<ForwardKind>,

    #[arg(long, short = 'T')]
    /// operate the IP service on transport layer (tcp)
    transport: bool,

    #[arg(long, short = 's')]
    /// run IP service in secure mode (enable TLS)
    secure: bool,

    /// http versions to serve: `auto` or a comma separated list of h1, h2 and h3
    /// (http mode only)
    ///
    /// `auto` serves HTTP/1.1 and h2 over TCP and, in secure mode, HTTP/3 over QUIC.
    #[arg(long, default_value = "auto")]
    http_version: HttpVersions,

    #[command(flatten)]
    http3: Http3Args,
}

/// run the rama ip service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandIp) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);

    // opt-in IP geolocation, configured via the RAMA_IP_GEO_DB env var
    let geo_db = crate::utils::geo::load_geo_db_from_env();

    if cfg.transport {
        return run_transport(exec, cfg, geo_db).await;
    }

    let tcp_version = cfg.http_version.tcp();
    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                Some(match tcp_version {
                    Some(TcpHttpVersion::H1) => vec![ApplicationProtocol::HTTP_11],
                    Some(TcpHttpVersion::H2) => vec![ApplicationProtocol::HTTP_2],
                    Some(TcpHttpVersion::Auto) | None => {
                        vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                    }
                }),
                exec.clone(),
            )
        })
        .transpose()?;

    tracing::info!("starting ip service: bind interface = {}", cfg.bind);
    let listeners = HttpListeners::bind(
        exec.clone(),
        cfg.bind,
        cfg.http_version,
        maybe_tls_server_config.as_ref(),
        &cfg.http3,
    )
    .await
    .context("bind ip service")?;

    let (tcp_service, http3_service) = IpServiceBuilder::http()
        .with_concurrent(cfg.concurrent)
        .maybe_with_rate_limit(opt_per_sec(Some(cfg.rate)))
        .maybe_with_throttle(opt_per_sec(Some(cfg.throttle)))
        .with_timeout(Duration::from_secs(cfg.timeout))
        .maybe_with_forward(cfg.forward)
        .maybe_with_geo_db(geo_db)
        .maybe_with_tls_server_config(maybe_tls_server_config)
        .maybe_with_http_version(tcp_version.and_then(Into::into))
        .maybe_with_alt_svc(listeners.alt_svc()?)
        .build_with_http3(exec.clone())
        .context("build ip HTTP service")?;

    if let Some(endpoint) = listeners.http3 {
        serve_http3(&exec, "ip", endpoint, Arc::new(http3_service));
    }
    if let Some(tcp_listener) = listeners.tcp {
        serve_tcp(&exec, cfg.bind, tcp_listener, tcp_service)?;
    }

    Ok(())
}

async fn run_transport(
    exec: Executor,
    cfg: CliCommandIp,
    geo_db: Option<Arc<IpGeoDb>>,
) -> Result<(), BoxError> {
    if cfg.http_version != HttpVersions::AUTO || cfg.http3.h3_bind.is_some() {
        return Err(BoxError::from_static_str(
            "http version selection is only possible in http mode",
        ));
    }
    let maybe_tls_server_config = cfg
        .secure
        .then(|| try_new_server_config(None, exec.clone()))
        .transpose()?;

    let tcp_service = IpServiceBuilder::tcp()
        .with_concurrent(cfg.concurrent)
        .maybe_with_rate_limit(opt_per_sec(Some(cfg.rate)))
        .maybe_with_throttle(opt_per_sec(Some(cfg.throttle)))
        .with_timeout(Duration::from_secs(cfg.timeout))
        .maybe_with_forward(cfg.forward)
        .maybe_with_geo_db(geo_db)
        .maybe_with_tls_server_config(maybe_tls_server_config)
        .build()
        .context("build ip TCP service")?;

    tracing::info!("starting ip service: bind interface = {}", cfg.bind);
    let tcp_listener = TcpListener::build(exec.clone())
        .bind_address(cfg.bind)
        .await
        .context("bind ip service")?;
    serve_tcp(&exec, cfg.bind, tcp_listener, tcp_service)
}

fn serve_tcp(
    exec: &Executor,
    bind: SocketAddress,
    tcp_listener: TcpListener,
    tcp_service: impl Service<TcpStream, Output = (), Error = Infallible>,
) -> Result<(), BoxError> {
    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    exec.clone().into_spawn_task(async move {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "ip service ready: bind interface = {}", bind
        );

        tcp_listener.serve(Arc::new(tcp_service)).await;
    });

    Ok(())
}
