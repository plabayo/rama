//! rama ip service

use clap::Args;
use rama::{
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    combinators::Either,
    error::BoxError,
    rt::Executor,
    tcp::server::TcpListener,
};
use std::time::Duration;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Args)]
/// rama ip service (returns the ip address of the client)
pub struct CliCommandIp {
    #[arg(long, short = 'p', default_value_t = 8080)]
    /// the port to listen on
    port: u16,

    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    /// the interface to listen on
    interface: String,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value = "8")]
    /// the timeout in seconds for each connection
    ///
    /// (0 = default timeout of 30s)
    timeout: u64,

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
}

/// run the rama ip service
pub async fn run(cfg: CliCommandIp) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = if cfg.transport {
        Either::A(
            IpServiceBuilder::tcp()
                .concurrent(cfg.concurrent)
                .timeout(Duration::from_secs(cfg.timeout))
                .maybe_forward(cfg.forward)
                .build()
                .expect("build ip TCP service"),
        )
    } else {
        Either::B(
            IpServiceBuilder::http()
                .concurrent(cfg.concurrent)
                .timeout(Duration::from_secs(cfg.timeout))
                .maybe_forward(cfg.forward)
                .build(Executor::graceful(graceful.guard()))
                .expect("build ip HTTP service"),
        )
    };

    let address = format!("{}:{}", cfg.interface, cfg.port);
    tracing::info!("starting ip service on: {}", address);

    graceful.spawn_task_fn(async move |guard| {
        let tcp_listener = TcpListener::build()
            .bind(address)
            .await
            .expect("bind ip service");

        tracing::info!("ip service ready");
        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}
