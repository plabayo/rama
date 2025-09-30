//! rama ip service

use rama::{
    Layer as _, Service as _,
    cli::{ForwardKind, service::ip::IpServiceBuilder},
    combinators::Either3,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        Uri, client::EasyHttpWebClient, headers::Authorization,
        layer::set_header::SetRequestHeaderLayer, tls::CertIssuerHttpClient,
    },
    net::{
        socket::Interface,
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{
                CacheKind, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
                ServerConfig,
            },
        },
        user::Bearer,
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use clap::Args;
use std::{num::NonZeroU64, time::Duration};

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

    #[arg(long, short = 's')]
    /// run IP service in secure mode (enable TLS)
    secure: bool,
}

/// run the rama ip service
pub async fn run(cfg: CliCommandIp) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let maybe_tls_server_config = cfg.secure.then(|| {
        if let Ok(uri_raw) = std::env::var("RAMA_TLS_REMOTE") {
            let uri: Uri = uri_raw.parse().expect("RAMA_TLS_REMOTE to be a valid URI");
            let client = if let Ok(auth_raw) = std::env::var("RAMA_TLS_REMOTE_AUTH") {
                CertIssuerHttpClient::new_with_client(
                    uri,
                    SetRequestHeaderLayer::overriding_typed(Authorization::new(
                        Bearer::new(auth_raw)
                            .expect("RAMA_TLS_REMOTE_AUTH to be a valid Bearer token"),
                    ))
                    .into_layer(EasyHttpWebClient::default())
                    .boxed(),
                )
            } else {
                CertIssuerHttpClient::new(uri)
            };

            return ServerConfig {
                application_layer_protocol_negotiation: cfg.http.then_some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
                ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
                    kind: client.into(),
                    cache_kind: CacheKind::MemCache {
                        max_size: NonZeroU64::new(1).unwrap(),
                        ttl: Some(Duration::from_secs(60 * 60 * 24 * 89)),
                    },
                }))
            };
        }

        let Ok(tls_key_pem_raw) = std::env::var("RAMA_TLS_KEY") else {
            return ServerConfig {
                application_layer_protocol_negotiation: Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
                ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
            };
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

    let graceful = rama::graceful::Shutdown::default();

    let tcp_service = match (cfg.transport, cfg.http) {
        (true, true) | (false, false) => Either3::A(
            IpServiceBuilder::auto()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .with_peek_timeout(Duration::from_secs(cfg.peek_timeout))
                .maybe_with_forward(cfg.forward)
                .maybe_with_tls_server_config(maybe_tls_server_config)
                .build(Executor::graceful(graceful.guard()))
                .expect("build ip HTTP service"),
        ),
        (true, false) => Either3::B(
            IpServiceBuilder::tcp()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .maybe_with_tls_server_config(maybe_tls_server_config)
                .build()
                .expect("build ip TCP service"),
        ),
        (false, true) => Either3::C(
            IpServiceBuilder::http()
                .with_concurrent(cfg.concurrent)
                .with_timeout(Duration::from_secs(cfg.timeout))
                .maybe_with_forward(cfg.forward)
                .maybe_with_tls_server_config(maybe_tls_server_config)
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
