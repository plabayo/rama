//! rama ip service

use clap::Args;
use rama::{
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    combinators::Either,
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
    crate::trace::init_tracing(LevelFilter::INFO);

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

    tracing::info!(
        bind = %cfg.bind,
        "starting ip service",
    );
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
            bind = %cfg.bind,
            %bind_address,
            "ip service ready",
        );

        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}
