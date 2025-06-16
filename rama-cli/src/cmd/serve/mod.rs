//! Serve service that serves a file, directory or placeholder page.

use clap::Args;
use rama::{
    Service,
    cli::{ForwardKind, service::serve::ServeServiceBuilder},
    error::{BoxError, ErrorContext, OpaqueError},
    http::service::web::response::IntoResponse,
    http::{Request, Response, matcher::HttpMatcher, service::fs::DirectoryServeMode},
    layer::HijackLayer,
    net::{
        socket::Interface,
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{SelfSignedData, ServerAuth, ServerAuthData, ServerConfig},
        },
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

use std::{convert::Infallible, path::PathBuf, time::Duration};

#[derive(Debug, Args)]
/// rama serve service (serves a file, directory or placeholder page)
pub struct CliCommandServe {
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
pub async fn run(cfg: CliCommandServe) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let maybe_tls_server_config = cfg.secure.then(|| {
        let tls_key_pem_raw = match std::env::var("RAMA_TLS_KEY") {
            Ok(raw) => raw,
            Err(_) => {
                return ServerConfig {
                    application_layer_protocol_negotiation: Some(vec![
                        ApplicationProtocol::HTTP_2,
                        ApplicationProtocol::HTTP_11,
                    ]),
                    ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
                };
            }
        };
        let tls_key_pem_raw = std::str::from_utf8(
            &ENGINE
                .decode(tls_key_pem_raw)
                .expect("base64 decode RAMA_TLS_KEY")[..],
        )
        .expect("base64-decoded RAMA_TLS_KEY valid utf-8")
        .try_into()
        .expect("tls_key_pem_raw => NonEmptyStr (RAMA_TLS_KEY)");
        let tls_crt_pem_raw = std::env::var("RAMA_TLS_CRT").expect("RAMA_TLS_CRT");
        let tls_crt_pem_raw = std::str::from_utf8(
            &ENGINE
                .decode(tls_crt_pem_raw)
                .expect("base64 decode RAMA_TLS_CRT")[..],
        )
        .expect("base64-decoded RAMA_TLS_CRT valid utf-8")
        .try_into()
        .expect("tls_crt_pem_raw => NonEmptyStr (RAMA_TLS_CRT)");
        ServerConfig {
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
            ..ServerConfig::new(ServerAuth::Single(ServerAuthData {
                private_key: DataEncoding::Pem(tls_key_pem_raw),
                cert_chain: DataEncoding::Pem(tls_crt_pem_raw),
                ocsp: None,
            }))
        }
    });

    let maybe_acme_service = std::env::var("RAMA_ACME_DATA")
        .map(|data| {
            let mut iter = data.trim().splitn(2, ',');
            let key = iter.next().expect("acme data key");
            let value = iter.next().expect("acme data value");

            HijackLayer::new(
                HttpMatcher::path(format!("/.well-known/acme-challenge/{key}")),
                AcmeService(value.to_owned()),
            )
        })
        .ok();

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = ServeServiceBuilder::new()
        .concurrent(cfg.concurrent)
        .timeout(Duration::from_secs(cfg.timeout))
        .maybe_forward(cfg.forward)
        .maybe_tls_server_config(maybe_tls_server_config)
        .http_layer(maybe_acme_service)
        .maybe_content_path(cfg.path)
        .directory_serve_mode(cfg.dir_serve)
        .build(Executor::graceful(graceful.guard()))
        .map_err(OpaqueError::from_boxed)
        .context("build serve service")?;

    tracing::info!(
        bind = %cfg.bind,
        "starting serve service on",
    );
    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind serve service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    graceful.spawn_task_fn(async move |guard| {
        tracing::info!(
            bind = %cfg.bind,
            %bind_address,
            "ready to serve",
        );
        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct AcmeService(String);

impl Service<(), Request> for AcmeService {
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        _ctx: rama::Context<()>,
        _req: Request,
    ) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}
