//! Echo service that echos the http request and tls client config

use rama::{
    cli::{ForwardKind, service::echo::EchoServiceBuilder},
    error::{BoxError, ErrorContext, OpaqueError},
    net::{socket::Interface, tls::ApplicationProtocol},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, Instrument, level_filters::LevelFilter},
    ua::profile::UserAgentDatabase,
};

use clap::Args;
use std::{sync::Arc, time::Duration};

use crate::utils::{http::HttpVersion, tls::new_server_config};

#[derive(Debug, Args)]
/// rama echo service (echos the http request and tls client config)
pub struct CliCommandEcho {
    /// enable debug logs for tracing
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(short = 't', long, default_value_t = 300)]
    /// the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
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

    /// http version to serve echo Service from
    #[arg(long, default_value = "auto")]
    http_version: HttpVersion,

    #[arg(long, short = 's')]
    /// run echo service in secure mode (enable TLS)
    secure: bool,

    #[arg(long)]
    /// enable ws support
    ws: bool,
}

/// run the rama echo service
pub async fn run(cfg: CliCommandEcho) -> Result<(), BoxError> {
    crate::trace::init_tracing(if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    });

    let maybe_tls_server_config = cfg.secure.then(|| {
        tracing::info!("create tls server config...");
        new_server_config(Some(match cfg.http_version {
            HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
            HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
            HttpVersion::Auto => {
                vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
            }
        }))
    });

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = EchoServiceBuilder::new()
        .with_concurrent(cfg.concurrent)
        .with_timeout(Duration::from_secs(cfg.timeout))
        .with_ws_support(cfg.ws)
        .maybe_with_http_version(cfg.http_version.into())
        .maybe_with_forward(cfg.forward)
        .maybe_with_tls_server_config(maybe_tls_server_config)
        .with_user_agent_database(Arc::new(UserAgentDatabase::embedded()))
        .build(Executor::graceful(graceful.guard()))
        .map_err(OpaqueError::from_boxed)
        .context("build echo service")?;

    tracing::info!("starting echo service: bind interface = {:?}", cfg.bind);
    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind echo service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let span =
        tracing::trace_root_span!("echo", otel.kind = "server", network.protocol.name = "http");

    graceful.spawn_task_fn(async move |guard| {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "echo service ready: bind interface = {}", cfg.bind,
        );

        tcp_listener
            .serve_graceful(guard, tcp_service)
            .instrument(span)
            .await;
    });

    graceful.shutdown_with_limit(Duration::from_secs(5)).await?;

    Ok(())
}
