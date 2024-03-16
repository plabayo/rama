use rama::{
    http::{
        layer::{compression::CompressionLayer, trace::TraceLayer},
        matcher::HttpMatcher,
        response::Redirect,
        server::HttpServer,
        service::web::{k8s_health, WebService},
        HeaderName, IntoResponse,
    },
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, HijackLayer, LimitLayer, TimeoutLayer},
        service_fn,
        util::backoff::ExponentialBackoff,
        ServiceBuilder,
    },
    tcp::server::TcpListener,
    tls::rustls::{
        dep::{
            pemfile,
            rustls::{KeyLogFile, ServerConfig},
        },
        server::{TlsAcceptorLayer, TlsClientConfigHandler},
    },
};
use std::{convert::Infallible, io::BufReader, sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod data;
mod endpoints;
mod report;
mod state;

pub use state::State;

#[derive(Debug)]
pub struct Config {
    pub interface: String,
    pub port: u16,
    pub http_version: String,
    pub health_port: u16,
    pub tls_cert_dir: Option<String>,
    pub secure_port: u16,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let health_address = format!("{}:{}", cfg.interface, cfg.health_port);

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());

        tracing::info!("FP Health Service listening on: {health_address}");

        HttpServer::auto(exec)
            .listen_graceful(guard, health_address, k8s_health())
            .await
            .unwrap();
    });

    let http_address = format!("{}:{}", cfg.interface, cfg.port);
    let https_address = format!("{}:{}", cfg.interface, cfg.secure_port);

    graceful.spawn_task_fn(|guard| async move {
        let inner_http_service = ServiceBuilder::new()
            .layer(HijackLayer::new(
                HttpMatcher::header_exists(HeaderName::from_static("referer"))
                    .and_header_exists(HeaderName::from_static("cookie"))
                    .negate(),
                service_fn(|| async move {
                    Ok::<_, Infallible>(Redirect::temporary("/consent").into_response())
                }),
            ))
            .service(
                WebService::default()
                    .not_found(Redirect::temporary("/consent"))
                    .get("/report", endpoints::get_report)
                    // XHR
                    .get("/api/fetch/number", endpoints::get_api_fetch_number)
                    .post(
                        "/api/fetch/number/:number",
                        endpoints::post_api_fetch_number,
                    )
                    .get(
                        "/api/xml/number",
                        endpoints::get_api_xml_http_request_number,
                    )
                    .post(
                        "/api/xml/number/:number",
                        endpoints::post_api_xml_http_request_number,
                    )
                    // Form
                    .get("/form", endpoints::form)
                    .post("/form", endpoints::form),
            );

        let http_service = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .service(
                WebService::default()
                    // Navigate
                    .get("/", endpoints::get_root)
                    .get("/consent", endpoints::get_consent)
                    // Assets
                    .get("/assets/style.css", endpoints::get_assets_style)
                    .get("/assets/script.js", endpoints::get_assets_script)
                    // Fingerprint Endpoints
                    .nest("/", inner_http_service),
            );

        let tcp_service_builder = ServiceBuilder::new()
            .map_result(|result| {
                if let Err(err) = result {
                    tracing::warn!(error = %err, "rama service failed");
                }
                Ok::<_, Infallible>(())
            })
            .layer(TimeoutLayer::new(Duration::from_secs(16)))
            // Why the below layer makes it no longer cloneable?!?!
            .layer(LimitLayer::new(ConcurrentPolicy::with_backoff(
                2048,
                ExponentialBackoff::default(),
            )));

        // also spawn a TLS listener if tls_cert_dir is set
        if let Some(tls_cert_dir) = &cfg.tls_cert_dir {
            let tls_listener = TcpListener::build_with_state(State::default())
                .bind(&https_address)
                .await
                .expect("bind TLS Listener");

            let http_service = http_service.clone();

            // create tls service builder
            let server_config = get_server_config(tls_cert_dir.as_str(), cfg.http_version.as_str())
                .await
                .expect("read rama-fp TLS server config");
            let tls_service_builder =
                tcp_service_builder
                    .clone()
                    .layer(TlsAcceptorLayer::with_client_config_handler(
                        server_config,
                        TlsClientConfigHandler::default().store_client_hello(),
                    ));

            let http_version = cfg.http_version.clone();
            guard.spawn_task_fn(|guard| async move {
                match http_version.as_str() {
                    "" | "auto" => {
                        tracing::info!("FP Secure Service (auto) listening on: {https_address}");
                        tls_listener
                            .serve_graceful(
                                guard.clone(),
                                tls_service_builder.service(
                                    HttpServer::auto(Executor::graceful(guard))
                                        .service(http_service),
                                ),
                            )
                            .await;
                    }
                    "h1" | "http1" | "http/1" | "http/1.0" | "http/1.1" => {
                        tracing::info!(
                            "FP Secure Service (http/1.1) listening on: {https_address}"
                        );
                        tls_listener
                            .serve_graceful(
                                guard,
                                tls_service_builder
                                    .service(HttpServer::http1().service(http_service)),
                            )
                            .await;
                    }
                    "h2" | "http2" | "http/2" | "http/2.0" => {
                        tracing::info!("FP Secure Service (h2) listening on: {https_address}");
                        tls_listener
                            .serve_graceful(
                                guard.clone(),
                                tls_service_builder.service(
                                    HttpServer::h2(Executor::graceful(guard)).service(http_service),
                                ),
                            )
                            .await;
                    }
                    _version => {
                        panic!("unsupported http version: {http_version}")
                    }
                }
            });
        }

        let tcp_listener = TcpListener::build_with_state(State::default())
            .bind(&http_address)
            .await
            .expect("bind TCP Listener");

        match cfg.http_version.as_str() {
            "" | "auto" => {
                tracing::info!("FP Service (auto) listening on: {http_address}");
                tcp_listener
                    .serve_graceful(
                        guard.clone(),
                        tcp_service_builder.service(
                            HttpServer::auto(Executor::graceful(guard)).service(http_service),
                        ),
                    )
                    .await;
            }
            "h1" | "http1" | "http/1" | "http/1.0" | "http/1.1" => {
                tracing::info!("FP Service (http/1.1) listening on: {http_address}");
                tcp_listener
                    .serve_graceful(
                        guard,
                        tcp_service_builder.service(HttpServer::http1().service(http_service)),
                    )
                    .await;
            }
            "h2" | "http2" | "http/2" | "http/2.0" => {
                tracing::info!("FP Service (h2) listening on: {http_address}");
                tcp_listener
                    .serve_graceful(
                        guard.clone(),
                        tcp_service_builder.service(
                            HttpServer::h2(Executor::graceful(guard)).service(http_service),
                        ),
                    )
                    .await;
            }
            _version => {
                panic!("unsupported http version: {}", cfg.http_version)
            }
        }
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

async fn get_server_config(tls_cert_dir: &str, http_version: &str) -> anyhow::Result<ServerConfig> {
    // Client mTLS Cert
    let cert_path = format!("{tls_cert_dir}/rama-fp.crt");
    let cert_content = tokio::fs::read(cert_path).await.expect("read TLS cert");
    let mut pem = BufReader::new(&cert_content[..]);
    let mut certs = Vec::new();
    for cert in pemfile::certs(&mut pem) {
        certs.push(cert.expect("parse mTLS client cert"));
    }

    // Client mTLS (private) Key
    let key_path = format!("{tls_cert_dir}/rama-fp.key");
    let key_content = tokio::fs::read(key_path).await.expect("read TLS key");
    let mut key_reader = BufReader::new(&key_content[..]);
    let key = pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private found");

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // support key logging
    if std::env::var("SSLKEYLOGFILE").is_ok() {
        server_config.key_log = Arc::new(KeyLogFile::new());
    }

    // set ALPN protocols
    server_config.alpn_protocols = match http_version {
        "" | "auto" => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "h2" | "http2" | "http/2" | "http/2.0" => vec![b"h2".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    };

    // return the server config
    Ok(server_config)
}
