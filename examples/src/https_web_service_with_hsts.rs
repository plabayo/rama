//! This example demonstrates how to setup a https web service
//! with HTTP Strict Transport Security (HSTS) enabled.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin https_web_service_with_hsts --features=http-full,rustls,aws-lc
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:12043` (http) and `:12044` (https).
//! You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k -v -L http://127.0.0.1:12043
//! curl -k -v https://127.0.0.1:12044
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
    graceful::Scope,
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
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::server::GeneratedServerAuthConfig,
};

#[cfg(feature = "boring")]
use rama::{
    tls::boring::server::TlsAcceptorLayer,
    tls::{KeyLogIntent, server::TlsServerConfig},
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::{
    tls::rustls::server::TlsAcceptorLayer,
    tls::{KeyLogIntent, server::TlsServerConfig},
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

    let scope = Scope::new()
        .with_default_signal()
        .with_grace(Duration::from_secs(30));

    #[cfg(any(feature = "rustls", feature = "boring"))]
    let tls_service_data = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self-signed")
        .with_alpn_http_auto()
        .with_keylog(KeyLogIntent::Environment);

    // create http service
    let weak_scope = scope.clone_weak();
    scope.spawn_task(async move {
        let tcp_service = TcpListener::build(weak_scope.clone())
            .bind_address("127.0.0.1:12043")
            .await
            .expect("bind tcp proxy to 127.0.0.1:12043");

        let http_service = HttpServer::auto(weak_scope).service(
            (
                TraceLayer::new_for_http(),
                AddRequiredResponseHeadersLayer::default(),
            )
                .into_layer(RedirectHttpToHttps::new().with_overwrite_port(12044)),
        );

        tcp_service.serve(http_service).await;
    });

    // create https service
    let weak_scope = scope.clone_weak();
    scope.spawn_task(async move {
        let tcp_service = TcpListener::build(weak_scope.clone())
            .bind_address("127.0.0.1:12044")
            .await
            .expect("bind tcp proxy to 127.0.0.1:12044");

        let http_service = HttpServer::auto(weak_scope).service(Arc::new(
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

    scope.join().await.expect("graceful shutdown");
}
