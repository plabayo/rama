//! This example demonstrates how to use rama's HTTP + HAR support
//! to be able to replay (previously recorded) log files.
//!
//! This can be useful in function of semi-automated e2e tests,
//! benchmarks, and all kind of other development reasons.
//!
//! ```sh
//! cargo run --example http_har_replay --features=http-full
//! ```
//!
//! # Expected output
//!
//! You should see the responses printed.

// rama provides everything out of the box to build a complete web service.

use rama::{
    Layer, Service,
    http::{
        Body, Request, Response,
        client::EasyHttpWebClient,
        io::{write_http_request, write_http_response},
        layer::{
            compression::CompressionLayer,
            decompression::DecompressionLayer,
            required_header::AddRequiredResponseHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        server::HttpServer,
    },
    net::{address::SocketAddress, user::credentials::basic},
    rt::Executor,
    service::service_fn,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

// Everything else we need is provided by the standard library, community crates or tokio.

use std::{convert::Infallible, time::Duration};

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62048);

#[tokio::main]
async fn main() {
    setup_tracing();
    tokio::spawn(run_server(ADDRESS));

    // TODO by default use example har log file that will be attached here as json
    // but accept a optional pos arg for a file and load from that file instead if given

    let client = (
        TraceLayer::new_for_http(),
        DecompressionLayer::new(),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ),
    )
        .into_layer(EasyHttpWebClient::default());

    let mut stdout = tokio::io::stdout();

    // TODO: replay requests and set header for index, so server can replay
    let req = Request::builder()
        .uri(format!("http://{ADDRESS}/"))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = client.serve(req).await.unwrap();
    let _ = write_http_response(&mut stdout, resp, true, true)
        .await
        .unwrap();
}

fn setup_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();
}

async fn run_server(addr: SocketAddress) {
    tracing::info!(
        network.local.address = %addr.ip_addr,
        network.local.port = %addr.port,
        "running server",
    );
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            addr,
            (
                AddRequiredResponseHeadersLayer::new(),
                CompressionLayer::new(),
            )
                .into_layer(service_fn(async move |req: Request| {
                    let req = write_http_request(&mut tokio::io::stdout(), req, true, true)
                        .await
                        .unwrap();
                    // TODO: replay based on `x-har-req-id` or use random based on hash modulo
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                })),
        )
        .await
        .unwrap();
}
