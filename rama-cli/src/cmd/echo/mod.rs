//! Echo service that echos the http request and tls client config

use clap::Args;
use rama::{
    cli::{service::echo::EchoServiceBuilder, ForwardKind, TlsServerCertKeyPair},
    error::BoxError,
    http::{matcher::HttpMatcher, IntoResponse, Request, Response},
    rt::Executor,
    service::{layer::HijackLayer, Service},
    tcp::server::TcpListener,
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Args)]
/// rama echo service (echos the http request and tls client config)
pub struct CliCommandEcho {
    #[arg(short = 'p', long, default_value_t = 8080)]
    /// the port to listen on
    port: u16,

    #[arg(short = 'i', long, default_value = "127.0.0.1")]
    /// the interface to listen on
    interface: String,

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
}

/// run the rama echo service
pub async fn run(cfg: CliCommandEcho) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let maybe_tls_server_cert_key_pair = std::env::var("RAMA_TLS_CRT")
        .map(|tls_crt_pem_raw| {
            let tls_key_pem_raw = std::env::var("RAMA_TLS_KEY").expect("RAMA_TLS_KEY");
            TlsServerCertKeyPair::new(tls_crt_pem_raw, tls_key_pem_raw)
        })
        .ok();

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

    let graceful = rama::utils::graceful::Shutdown::default();

    let tcp_service = EchoServiceBuilder::new()
        .concurrent(cfg.concurrent)
        .timeout(Duration::from_secs(cfg.timeout))
        .maybe_forward(cfg.forward)
        .maybe_tls_server_config(maybe_tls_server_cert_key_pair)
        .http_layer(maybe_acme_service)
        .build(Executor::graceful(graceful.guard()))
        .expect("build echo service");

    let address = format!("{}:{}", cfg.interface, cfg.port);
    tracing::info!("starting echo service on: {}", address);

    graceful.spawn_task_fn(move |guard| async move {
        let tcp_listener = TcpListener::build()
            .bind(address)
            .await
            .expect("bind echo service");

        tracing::info!("echo service ready");
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
        _ctx: rama::service::Context<()>,
        _req: Request,
    ) -> Result<Self::Response, Self::Error> {
        Ok(self.0.clone().into_response())
    }
}
