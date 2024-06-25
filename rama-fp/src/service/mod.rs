use base64::Engine as _;
use rama::{
    error::BoxError,
    http::{
        layer::{
            catch_panic::CatchPanicLayer, compression::CompressionLayer,
            opentelemetry::RequestMetricsLayer, required_header::AddRequiredResponseHeadersLayer,
            set_header::SetResponseHeaderLayer, trace::TraceLayer,
        },
        matcher::HttpMatcher,
        response::Redirect,
        server::HttpServer,
        service::web::{match_service, PrometheusMetricsHandler},
        HeaderName, HeaderValue, IntoResponse,
    },
    net::stream::layer::{http::BodyLimitLayer, opentelemetry::NetworkMetricsLayer},
    proxy::pp::server::HaProxyLayer,
    rt::Executor,
    service::{
        layer::{
            limit::policy::ConcurrentPolicy, ConsumeErrLayer, HijackLayer, LimitLayer, TimeoutLayer,
        },
        service_fn, ServiceBuilder,
    },
    tcp::server::TcpListener,
    telemetry::{opentelemetry, prometheus},
    tls::rustls::{
        dep::{
            pemfile,
            rustls::{KeyLogFile, ServerConfig},
        },
        server::{TlsAcceptorLayer, TlsClientConfigHandler},
    },
    ua::UserAgentClassifierLayer,
    utils::backoff::ExponentialBackoff,
};
use std::{convert::Infallible, io::BufReader, sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod data;
mod endpoints;
mod report;
mod state;

#[doc(inline)]
pub use state::State;

use self::state::ACMEData;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug)]
pub struct Config {
    pub interface: String,
    pub port: u16,
    pub secure_port: u16,
    pub prometheus_port: u16,
    pub http_version: String,
    pub ha_proxy: bool,
}

pub async fn run(cfg: Config) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // prometheus registry & exporter
    let registry = prometheus::Registry::new();
    let exporter = prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .unwrap();

    // set up a meter meter to create instruments
    let provider = opentelemetry::sdk::metrics::SdkMeterProvider::builder()
        .with_reader(exporter)
        .build();

    opentelemetry::global::set_meter_provider(provider);

    // prometheus metrics http handler (exporter)
    let metrics_http_handler = Arc::new(PrometheusMetricsHandler::new().with_registry(registry));

    let graceful = rama::utils::graceful::Shutdown::default();

    let acme_data = if let Ok(raw_acme_data) = std::env::var("RAMA_FP_ACME_DATA") {
        let acme_data: Vec<_> = raw_acme_data
            .split(';')
            .map(|s| {
                let mut iter = s.trim().splitn(2, ',');
                let key = iter.next().expect("acme data key");
                let value = iter.next().expect("acme data value");
                (key.to_owned(), value.to_owned())
            })
            .collect();
        ACMEData::with_challenges(acme_data)
    } else {
        ACMEData::default()
    };

    let http_address = format!("{}:{}", cfg.interface, cfg.port);
    let https_address = format!("{}:{}", cfg.interface, cfg.secure_port);
    let prometheus_address = format!("{}:{}", cfg.interface, cfg.prometheus_port);

    let ha_proxy = cfg.ha_proxy;

    let ch_headers = [
        "Width",
        "Downlink",
        "Sec-CH-UA",
        "Sec-CH-UA-Mobile",
        "Sec-CH-UA-Full-Version",
        "ETC",
        "Save-Data",
        "Sec-CH-UA-Platform",
        "Sec-CH-Prefers-Reduced-Motion",
        "Sec-CH-UA-Arch",
        "Sec-CH-UA-Bitness",
        "Sec-CH-UA-Model",
        "Sec-CH-UA-Platform-Version",
        "Sec-CH-UA-Prefers-Color-Scheme",
        "Device-Memory",
        "RTT",
        "Sec-GPC",
    ]
    .join(", ")
    .parse::<HeaderValue>()
    .expect("parse header value");

    graceful.spawn_task_fn(move |guard| async move {
        let inner_http_service = ServiceBuilder::new()
            .layer(HijackLayer::new(
                HttpMatcher::header_exists(HeaderName::from_static("referer"))
                    .and_header_exists(HeaderName::from_static("cookie"))
                    .negate(),
                service_fn(|| async move {
                    Ok::<_, Infallible>(Redirect::temporary("/consent").into_response())
                }),
            ))
            .service(match_service!{
                HttpMatcher::get("/report") => endpoints::get_report,
                HttpMatcher::get("/api/fetch/number") => endpoints::get_api_fetch_number,
                HttpMatcher::post("/api/fetch/number/:number") => endpoints::post_api_fetch_number,
                HttpMatcher::get("/api/xml/number") => endpoints::get_api_xml_http_request_number,
                HttpMatcher::post("/api/xml/number/:number") => endpoints::post_api_xml_http_request_number,
                HttpMatcher::method_get().or_method_post().and_path("/form") => endpoints::form,
                _ => Redirect::temporary("/consent"),
            });

        let http_service = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(RequestMetricsLayer::default())
            .layer(CompressionLayer::new())
            .layer(CatchPanicLayer::new())
            .layer(AddRequiredResponseHeadersLayer::default())
            .layer(SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-sponsored-by"),
                HeaderValue::from_static("fly.io"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("accept-ch"),
                ch_headers.clone(),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("critical-ch"),
                ch_headers.clone(),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("vary"),
                ch_headers,
            ))
            .layer(UserAgentClassifierLayer::new())
            .service(
                Arc::new(match_service!{
                    // Navigate
                    HttpMatcher::get("/") => Redirect::temporary("/consent"),
                    HttpMatcher::get("/consent") => endpoints::get_consent,
                    // ACME
                    HttpMatcher::get("/.well-known/acme-challenge/:token") => endpoints::get_acme_challenge,
                    // Assets
                    HttpMatcher::get("/assets/style.css") => endpoints::get_assets_style,
                    HttpMatcher::get("/assets/script.js") => endpoints::get_assets_script,
                    // Fingerprinting Endpoints
                    _ => inner_http_service,
                })
            );

        let tcp_service_builder = ServiceBuilder::new()
            .layer(ConsumeErrLayer::trace(tracing::Level::WARN))
            .layer(NetworkMetricsLayer::default())
            .layer(TimeoutLayer::new(Duration::from_secs(16)))
            .layer(LimitLayer::new(ConcurrentPolicy::max_with_backoff(
                2048,
                ExponentialBackoff::default(),
            )))
            // Limit the body size to 1MB for both request and response
            .layer(BodyLimitLayer::symmetric(1024 * 1024));

        // also spawn a TLS listener if tls_cert_dir is set
        if let Ok(tls_cert_pem_raw) = std::env::var("RAMA_FP_TLS_CRT") {
            let tls_key_pem_raw = std::env::var("RAMA_FP_TLS_KEY").expect("RAMA_FP_TLS_KEY");

            let tls_listener = TcpListener::build_with_state(State::new(acme_data.clone()))
                .bind(&https_address)
                .await
                .expect("bind TLS Listener");

            let http_service = http_service.clone();

            let tcp_service_builder = tcp_service_builder.clone()
                .layer(ha_proxy.then(HaProxyLayer::default));

            // create tls service builder
            let server_config =
                get_server_config(tls_cert_pem_raw, tls_key_pem_raw, cfg.http_version.as_str())
                    .await
                    .expect("read rama-fp TLS server config");
            let tls_service_builder =
                tcp_service_builder
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

        let tcp_service_builder = tcp_service_builder
        .layer(ha_proxy.then(HaProxyLayer::default));

        let tcp_listener = TcpListener::build_with_state(State::new(acme_data))
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

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_graceful(
                guard,
                prometheus_address,
                match_service!{
                    HttpMatcher::get("/metrics") => metrics_http_handler,
                    _ => service_fn(|_| async { Ok::<_, Infallible>(Redirect::temporary("/metrics").into_response()) }),
                },
            )
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

pub async fn echo(cfg: Config) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // prometheus registry & exporter
    let registry = prometheus::Registry::new();
    let exporter = prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .unwrap();

    // set up a meter meter to create instruments
    let provider = opentelemetry::sdk::metrics::SdkMeterProvider::builder()
        .with_reader(exporter)
        .build();

    opentelemetry::global::set_meter_provider(provider);

    // prometheus metrics http handler (exporter)
    let metrics_http_handler = Arc::new(PrometheusMetricsHandler::new().with_registry(registry));

    let graceful = rama::utils::graceful::Shutdown::default();

    let acme_data = if let Ok(raw_acme_data) = std::env::var("RAMA_FP_ACME_DATA") {
        let acme_data: Vec<_> = raw_acme_data
            .split(';')
            .map(|s| {
                let mut iter = s.trim().splitn(2, ',');
                let key = iter.next().expect("acme data key");
                let value = iter.next().expect("acme data value");
                (key.to_owned(), value.to_owned())
            })
            .collect();
        ACMEData::with_challenges(acme_data)
    } else {
        ACMEData::default()
    };

    let http_address = format!("{}:{}", cfg.interface, cfg.port);
    let https_address = format!("{}:{}", cfg.interface, cfg.secure_port);
    let prometheus_address = format!("{}:{}", cfg.interface, cfg.prometheus_port);
    let ha_proxy = cfg.ha_proxy;

    graceful.spawn_task_fn(move |guard| async move {
        let http_service = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(RequestMetricsLayer::default())
            .layer(CompressionLayer::new())
            .layer(CatchPanicLayer::new())
            .layer(AddRequiredResponseHeadersLayer::default())
            .layer(SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-sponsored-by"),
                HeaderValue::from_static("fly.io"),
            ))
            .layer(UserAgentClassifierLayer::new())
            .service(
                Arc::new(match_service!{
                    HttpMatcher::get("/.well-known/acme-challenge/:token") => endpoints::get_acme_challenge,
                    _ => endpoints::echo,
                })
            );

        let tcp_service_builder = ServiceBuilder::new()
            .layer(ConsumeErrLayer::trace(tracing::Level::WARN))
            .layer(NetworkMetricsLayer::default())
            .layer(TimeoutLayer::new(Duration::from_secs(16)))
            // Why the below layer makes it no longer cloneable?!?!
            .layer(LimitLayer::new(ConcurrentPolicy::max_with_backoff(
                2048,
                ExponentialBackoff::default(),
            )))
            // Limit the body size to 1MB for both request and response
            .layer(BodyLimitLayer::symmetric(1024 * 1024));

        // also spawn a TLS listener if tls_cert_dir is set
        if let Ok(tls_cert_pem_raw) = std::env::var("RAMA_FP_TLS_CRT") {
            let tls_key_pem_raw = std::env::var("RAMA_FP_TLS_KEY").expect("RAMA_FP_TLS_KEY");

            let tls_listener = TcpListener::build_with_state(State::new(acme_data.clone()))
                .bind(&https_address)
                .await
                .expect("bind TLS Listener");

            let http_service = http_service.clone();

            let tcp_service_builder = tcp_service_builder.clone()
                .layer(ha_proxy.then(HaProxyLayer::default));

            // create tls service builder
            let server_config =
                get_server_config(tls_cert_pem_raw, tls_key_pem_raw, cfg.http_version.as_str())
                    .await
                    .expect("read rama-fp TLS server config");
            let tls_service_builder =
                tcp_service_builder
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

        let tcp_listener = TcpListener::build_with_state(State::new(acme_data))
            .bind(&http_address)
            .await
            .expect("bind TCP Listener");

        let tcp_service_builder = tcp_service_builder
            .layer(ha_proxy.then(HaProxyLayer::default));

        match cfg.http_version.as_str() {
            "" | "auto" => {
                tracing::info!("FP Echo Service (auto) listening on: {http_address}");
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
                tracing::info!("FP Echo Service (http/1.1) listening on: {http_address}");
                tcp_listener
                    .serve_graceful(
                        guard,
                        tcp_service_builder.service(HttpServer::http1().service(http_service)),
                    )
                    .await;
            }
            "h2" | "http2" | "http/2" | "http/2.0" => {
                tracing::info!("FP Echo Service (h2) listening on: {http_address}");
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

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_graceful(
                guard,
                prometheus_address,
                match_service!{
                    HttpMatcher::get("/metrics") => metrics_http_handler,
                    _ => service_fn(|_| async { Ok::<_, Infallible>(Redirect::temporary("/metrics").into_response()) }),
                },
            )
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

async fn get_server_config(
    tls_cert_pem_raw: String,
    tls_key_pem_raw: String,
    http_version: &str,
) -> Result<ServerConfig, BoxError> {
    // server TLS Certs
    let tls_cert_pem_raw = BASE64.decode(tls_cert_pem_raw.as_bytes())?;
    let mut pem = BufReader::new(&tls_cert_pem_raw[..]);
    let mut certs = Vec::new();
    for cert in pemfile::certs(&mut pem) {
        certs.push(cert.expect("parse tls server cert"));
    }

    // server TLS key
    let tls_key_pem_raw = BASE64.decode(tls_key_pem_raw.as_bytes())?;
    let mut key_reader = BufReader::new(&tls_key_pem_raw[..]);
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
