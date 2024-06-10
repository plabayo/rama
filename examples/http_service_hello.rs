//! An example to showcase how one can build a service using Rama,
//! built with layers to modify and branch the traffic as it goes through the service.
//! And this on Layer 4 (TCP) all the way to Layer 7 (HTTP).
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_service_hello
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

use bytes::Bytes;
use rama::{
    http::{
        header,
        layer::{
            compression::CompressionLayer,
            sensitive_headers::{
                SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
            },
            trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
        },
        response::Html,
        server::HttpServer,
        IntoResponse, Request,
    },
    net::stream::{
        layer::{BytesRWTrackerHandle, BytesTrackerLayer},
        SocketInfo,
    },
    rt::Executor,
    service::{layer::TimeoutLayer, Context, ServiceBuilder},
    tcp::server::TcpListener,
    utils::latency::LatencyUnit,
};
use std::{sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    let graceful = rama::utils::graceful::Shutdown::default();

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());

        let http_service = ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .layer(SetSensitiveRequestHeadersLayer::from_shared(sensitive_headers.clone()))
            .layer(
                TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
            )
            .layer(SetSensitiveResponseHeadersLayer::from_shared(sensitive_headers))
            .map_response(IntoResponse::into_response)
            .service_fn(
                |ctx: Context<()>, req: Request| async move {
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
                },
            );

        let tcp_http_service = HttpServer::auto(exec).service(http_service);

        TcpListener::bind("127.0.0.1:62010")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                ServiceBuilder::new()
                    .trace_err()
                    .layer(TimeoutLayer::new(Duration::from_secs(8)))
                    .layer(BytesTrackerLayer::new())
                    .service(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
