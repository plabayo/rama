//! rama ip service

use rama::{
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    combinators::Either,
    error::{BoxError, ErrorContext},
    graceful::ShutdownGuard,
    net::{socket::Interface, tls::ApplicationProtocol},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use clap::Args;
use std::{sync::Arc, time::Duration};

use crate::utils::tls::try_new_server_config;

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

    #[arg(long, short = 't', default_value = "300")]
    /// the timeout in seconds for each connection
    timeout: u64,

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
}

/// run the rama ip service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandIp) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);
    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                (!cfg.transport).then_some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
                exec.clone(),
            )
        })
        .transpose()?;

    let tcp_service = if cfg.transport {
        Either::A(
            IpServiceBuilder::tcp()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .maybe_with_tls_server_config(maybe_tls_server_config)
                .build()
                .context("build ip TCP service")?,
        )
    } else {
        Either::B(
            IpServiceBuilder::http()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .maybe_with_tls_server_config(maybe_tls_server_config)
                .build(exec.clone())
                .context("build ip HTTP service")?,
        )
    };

    tracing::info!("starting ip service: bind interface = {}", cfg.bind);
    let tcp_listener = TcpListener::build(exec.clone())
        .bind(cfg.bind.clone())
        .await
        .context("bind ip service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    exec.clone().into_spawn_task(async move {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "ip service ready: bind interface = {}", cfg.bind
        );

        tcp_listener.serve(Arc::new(tcp_service)).await;
    });

    Ok(())
}
