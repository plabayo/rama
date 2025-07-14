//! An example to showcase how one can build a service using Rama,
//! built with layers to modify and branch the traffic as it goes through the service.
//! And this on Layer 4 (TCP) all the way to Layer 7 (HTTP).
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_service_hello --features=compression,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62010`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62010
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a HTML body containing
//! the peer address, the path of the request and the stats of the bytes read and written.

use rama::{
    Context, Layer,
    bytes::Bytes,
    http::{
        Request, header,
        layer::{
            compression::CompressionLayer,
            sensitive_headers::{
                SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
            },
            trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
        },
        server::HttpServer,
        service::web::response::{Html, IntoResponse},
    },
    layer::{MapResponseLayer, TimeoutLayer, TraceErrLayer},
    net::stream::{
        SocketInfo,
        layer::{BytesRWTrackerHandle, IncomingBytesTrackerLayer},
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    utils::latency::LatencyUnit,
};

use std::{sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());

        let http_service = (
            CompressionLayer::new(),
            SetSensitiveRequestHeadersLayer::from_shared(sensitive_headers.clone()),
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(
                        http.request.body.chunk_size = chunk.len(),
                        http.request.body.chunk_read_ms = latency.as_millis(),
                        "sending body chunk"
                    )
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .latency_unit(LatencyUnit::Micros),
                ),
            SetSensitiveResponseHeadersLayer::from_shared(sensitive_headers),
            MapResponseLayer::new(IntoResponse::into_response),
        )
            .into_layer(service_fn(async |ctx: Context<()>, req: Request| {
                let socket_info = ctx.get::<SocketInfo>().unwrap();
                let tracker = ctx.get::<BytesRWTrackerHandle>().unwrap();
                Ok(Html(format!(
                    r##"
                        <html>
                            <head>
                                <title>Rama — Http Service Hello</title>
                            </head>
                            <body>
                                <h1>Hello</h1>
                                <p>Peer: {}</p>
                                <p>Path: {}</p>
                                <p>Stats (bytes):</p>
                                <ul>
                                    <li>Read: {}</li>
                                    <li>Written: {}</li>
                                </ul>
                            </body>
                        </html>"##,
                    socket_info.peer_addr(),
                    req.uri().path(),
                    tracker.read(),
                    tracker.written(),
                )))
            }));

        let tcp_http_service = HttpServer::auto(exec).service(http_service);

        TcpListener::bind("127.0.0.1:62010")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                (
                    TraceErrLayer::new(),
                    TimeoutLayer::new(Duration::from_secs(8)),
                    IncomingBytesTrackerLayer::new(),
                )
                    .into_layer(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
