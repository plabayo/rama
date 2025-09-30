//! rama ip service

use clap::Args;
use rama::{
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    combinators::Either3,
    error::{BoxError, ErrorContext, OpaqueError},
    net::socket::Interface,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};
use std::time::Duration;

#[derive(Debug, Args)]
/// rama ip service (returns the ip address of the client)
pub struct CliCommandIp {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value = "5")]
    /// the timeout in seconds for each connection
    timeout: u64,

    #[arg(long, short = 'P', default_value = "1")]
    /// the timeout in seconds for each connection
    peek_timeout: u64,

    #[arg(long, short = 'a')]
    /// enable HaProxy PROXY Protocol
    ha_proxy: bool,

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

    #[arg(long)]
    /// operate the IP service on transport layer (http)
    http: bool,
}

/// run the rama ip service
pub async fn run(cfg: CliCommandIp) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = match (cfg.transport, cfg.http) {
        (true, true) | (false, false) => Either3::A(
            IpServiceBuilder::auto()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .with_peek_timeout(Duration::from_secs(cfg.peek_timeout))
                .maybe_with_forward(cfg.forward)
                .build(Executor::graceful(graceful.guard()))
                .expect("build ip HTTP service"),
        ),
        (true, false) => Either3::B(
            IpServiceBuilder::tcp()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .build()
                .expect("build ip TCP service"),
        ),
        (false, true) => Either3::C(
            IpServiceBuilder::http()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .build(Executor::graceful(graceful.guard()))
                .expect("build ip HTTP service"),
        ),
    };

    tracing::info!("starting ip service: bind interface = {}", cfg.bind);
    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind ip service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    graceful.spawn_task_fn(async move |guard| {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "ip service ready: bind interface = {}", cfg.bind
        );

        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful.shutdown_with_limit(Duration::from_secs(5)).await?;

    Ok(())
}
