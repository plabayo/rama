//! This example demonstrates the use of a ZIP bomb (not ZIP64)
//! resource used as fake data for bad bots and other
//! malicious actors.
//!
//! ```sh
//! cargo run --example http_anti_bot_zip_bomb --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62036`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62036
//! ```
//!
//! Will return a greeting for humans.
//!
//! Here are the other resources:
//!
//! ```sh
//! curl -v http://127.0.0.1:62036/api/rates/2024.csv  # protected resource
//! ```

// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer,
    http::{
        StatusCode,
        body::ZipBomb,
        headers::UserAgent,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{
            Router,
            extract::{Path, TypedHeader},
            response::{Html, IntoResponse},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde::Deserialize;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

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

    let graceful = rama::graceful::Shutdown::default();

    let router = Router::new()
        .get("/", Html(r##"<h1>Rates Catalogue</h1><ul><li><a href="/api/rates/2024.csv">rates for 2024</a></li></ul>"##.to_owned()))
        .get("/api/rates/{year}.csv", api_rates_csv);

    let exec = Executor::graceful(graceful.guard());
    let app = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
        )
            .into_layer(router),
    );

    let address = SocketAddress::local_ipv4(62036);
    tracing::info!("running service at: {address}");
    let tcp_server = TcpListener::bind(address).await.expect("bind tcp server");

    graceful.spawn_task_fn(|guard| tcp_server.serve_graceful(guard, app));

    graceful
        .shutdown_with_limit(Duration::from_secs(8))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Deserialize)]
struct ApiRatesPath {
    year: u16,
}

async fn api_rates_csv(
    TypedHeader(ua): TypedHeader<UserAgent>,
    Path(ApiRatesPath { year }): Path<ApiRatesPath>,
) -> impl IntoResponse {
    if ua.as_str().contains("curl/") {
        // NOTE: in a real product you'll want to do actual Fingerprinting,
        // based on TCP, TLS, HTTP and application+platform signals
        // ... for this example this will do however
        // ... and of course you want to combine this with other measures:
        // - rate limit
        // - hard blocks
        // - other mechanisms
        // ... because zip bombs do use some resources from your server as well,
        // at least when generating them on the fly like this... You could of course
        // cache them based on input, so adding a caching layer in front of this endpoint
        // service specific would do a lot already
        ZipBomb::new(format!("rates_{year}.csv")).into_response()
    } else {
        // assume real user
        if year == 2024 {
            // NOTE: in a real product you would generate this zip on the fly,
            // or serve from cache if possible, based on actual data...
            // or serve a real data from some persistent storage in case it is static in nature
            // ... for this example we'll serve fake data however
            (
                [
                    ("Robots", "none"),
                    ("X-Robots-Tag", "noindex, nofollow"),
                    ("Content-Type", "application/zip"),
                    (
                        "Content-Disposition",
                        "attachment; filename=rates_2024.csv.zip",
                    ),
                ],
                HARDCODED_RATES_ZIP,
            )
                .into_response()
        } else {
            tracing::debug!("received api request for invalid year: {year}");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[rustfmt::skip]
pub const HARDCODED_RATES_ZIP: &[u8] = &[
    0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x00, 0xC9, 0xF1, 0x3C, 0x7A, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00,
    0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x72, 0x61, 0x74, 0x65, 0x73, 0x5F,
    0x32, 0x30, 0x32, 0x34, 0x2E, 0x63, 0x73, 0x76, 0x63, 0x75, 0x72, 0x72,
    0x65, 0x6E, 0x63, 0x79, 0x2C, 0x72, 0x61, 0x74, 0x65, 0x0A, 0x55, 0x53,
    0x44, 0x2C, 0x31, 0x2E, 0x30, 0x30, 0x0A, 0x45, 0x55, 0x52, 0x2C, 0x30,
    0x2E, 0x39, 0x31, 0x0A, 0x42, 0x54, 0x43, 0x2C, 0x33, 0x30, 0x33, 0x34,
    0x32, 0x2E, 0x34, 0x34, 0x0A, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0xC9, 0xF1, 0x3C,
    0x7A, 0x2D, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x72, 0x61, 0x74, 0x65, 0x73, 0x5F, 0x32, 0x30, 0x32,
    0x34, 0x2E, 0x63, 0x73, 0x76, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00,
    0x00, 0x00, 0x00,
];
