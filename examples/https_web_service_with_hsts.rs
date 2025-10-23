//! This example demonstrates how to setup a https web service
//! with HTTP Strict Transport Security (HSTS) enabled.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example https_web_service_with_hsts --features=http-full,rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62043` (http) and `:62044` (https).
//! You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k -v -L http://127.0.0.1:62043
//! curl -k -v https://127.0.0.1:62044
//! ```
//!
//! The Http server should redirect to the https server,
//! and the https server should return a html rsponse.

use rama::{
    Layer,
    graceful::Shutdown,
    http::{
        headers::StrictTransportSecurity,
        layer::trace::TraceLayer,
        layer::{
            required_header::AddRequiredResponseHeadersLayer, set_header::SetResponseHeaderLayer,
        },
        server::HttpServer,
        service::{
            redirect::RedirectHttpToHttps,
            web::{Router, response::Html},
        },
    },
    net::tls::server::SelfSignedData,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::level_filters::LevelFilter,
};

#[cfg(feature = "boring")]
use rama::{
    net::tls::{
        ApplicationProtocol,
        server::{ServerAuth, ServerConfig},
    },
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer};

use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    #[cfg(feature = "boring")]
    let tls_service_data = {
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                organisation_name: Some("Example Server Acceptor".to_owned()),
                ..Default::default()
            }))
        };
        tls_server_config
            .try_into()
            .expect("create tls server config")
    };

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    let tls_service_data = {
        TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self signed acceptor data")
        .with_alpn_protocols_http_auto()
        .with_env_key_logger()
        .expect("with env key logger")
        .build()
    };

    // create http service
    shutdown.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62043")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62043");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                AddRequiredResponseHeadersLayer::default(),
            )
                .into_layer(RedirectHttpToHttps::new().with_overwrite_port(62044)),
        );

        tcp_service.serve_graceful(guard, http_service).await;
    });

    // create https service
    shutdown.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62044")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62044");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                AddRequiredResponseHeadersLayer::default(),
                SetResponseHeaderLayer::if_not_present_typed(
                    StrictTransportSecurity::excluding_subdomains(Duration::from_secs(31536000)),
                ),
            )
                .into_layer(Router::new().get("/", Html(r##"<h1>Hello HSTS</h1>"##.to_owned()))),
        );

        tcp_service
            .serve_graceful(
                guard,
                TlsAcceptorLayer::new(tls_service_data).into_layer(http_service),
            )
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
