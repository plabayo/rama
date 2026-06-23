//! This example demonstrates how to setup a https web service
//! with HTTP Strict Transport Security (HSTS) enabled.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example https_web_service_with_hsts --features=http-full,rustls,aws-lc
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

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    graceful::Shutdown,
    http::{
        headers::StrictTransportSecurity,
        layer::{error_handling::ErrorHandlerLayer, trace::TraceLayer},
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
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

#[cfg(feature = "boring")]
use rama::{
    net::tls::{KeyLogIntent, server::TlsServerConfig},
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::{
    net::tls::{KeyLogIntent, server::TlsServerConfig},
    tls::rustls::server::TlsAcceptorLayer,
};

use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    #[cfg(any(feature = "rustls", feature = "boring"))]
    let tls_service_data = TlsServerConfig::new()
        .try_with_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self-signed")
        .with_alpn_http_auto()
        .with_keylog(KeyLogIntent::Environment);

    // create http service
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard);
        let tcp_service = TcpListener::build(exec.clone())
            .bind_address("127.0.0.1:62043")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62043");

        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                AddRequiredResponseHeadersLayer::default(),
            )
                .into_layer(RedirectHttpToHttps::new().with_overwrite_port(62044)),
        );

        tcp_service.serve(http_service).await;
    });

    // create https service
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard);
        let tcp_service = TcpListener::build(exec.clone())
            .bind_address("127.0.0.1:62044")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62044");

        let http_service = HttpServer::auto(exec).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                AddRequiredResponseHeadersLayer::default(),
                SetResponseHeaderLayer::if_not_present_typed(
                    StrictTransportSecurity::excluding_subdomains_for_max_seconds(31536000),
                ),
                ErrorHandlerLayer::new(),
            )
                .into_layer(
                    Router::new().with_get("/", Html(r##"<h1>Hello HSTS</h1>"##.to_owned())),
                ),
        ));

        tcp_service
            .serve(TlsAcceptorLayer::new(tls_service_data).into_layer(http_service))
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
