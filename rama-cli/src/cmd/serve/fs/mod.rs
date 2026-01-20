//! Serve service that serves a file, directory or placeholder page.

use rama::{
    cli::{ForwardKind, service::fs::FsServiceBuilder},
    error::{BoxError, ErrorContext, OpaqueError},
    graceful::ShutdownGuard,
    http::service::fs::DirectoryServeMode,
    net::{socket::Interface, tls::ApplicationProtocol},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use clap::Args;
use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::utils::tls::try_new_server_config;

#[derive(Debug, Args)]
/// rama serve service (serves a file, directory or placeholder page)
pub struct CliCommandFs {
    /// The path to the file or directory to serve
    ///
    /// If not provided, a placeholder page will be served.
    #[arg()]
    path: Option<PathBuf>,

    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(short = 't', long, default_value_t = 8)]
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

    #[arg(long, short = 's')]
    /// run serve service in secure mode (enable TLS)
    secure: bool,

    #[arg(long, default_value_t = DirectoryServeMode::HtmlFileList)]
    /// define how to serve directories
    ///
    /// 'append-index': only serve directories if it contains an index.html
    ///
    /// 'not-found': return 404 for directories
    ///
    /// 'html-file-list': render directory file structure as a html page (default)
    dir_serve: DirectoryServeMode,
}

/// run the rama serve service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandFs) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);
    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
                exec.clone(),
            )
        })
        .transpose()?;

    let tcp_service = FsServiceBuilder::new()
        .with_concurrent(cfg.concurrent)
        .with_timeout(Duration::from_secs(cfg.timeout))
        .maybe_with_forward(cfg.forward)
        .maybe_with_tls_server_config(maybe_tls_server_config)
        .maybe_with_content_path(cfg.path)
        .with_directory_serve_mode(cfg.dir_serve)
        .build(exec.clone())
        .map_err(OpaqueError::from_boxed)
        .context("build serve service")?;

    tracing::info!("starting serve service on: bind interface = {}", cfg.bind);
    let tcp_listener = TcpListener::build(exec.clone())
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind serve service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    exec.spawn_task(async move {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "ready to serve: bind interface = {}", cfg.bind,
        );
        tcp_listener.serve(Arc::new(tcp_service)).await;
    });

    Ok(())
}
