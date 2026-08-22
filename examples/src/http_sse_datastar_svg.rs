//! Minimal Datastar SVG example using namespaced element patches.
//!
//! Inspired by the namespace example in the
//! [Datastar Clojure SDK](https://github.com/starfederation/datastar-clojure/blob/main/src/dev/examples/namespaces.clj).
//!
//! ```sh
//! cargo run -p rama-examples --bin http_sse_datastar_svg --features=http-full
//! ```
//!
//! Open <http://127.0.0.1:62059> and use the button to cycle through
//! server-rendered SVG shapes.

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    futures::async_stream::stream_fn,
    http::{
        layer::{error_handling::ErrorHandlerLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{
            Router,
            response::{DatastarScript, DatastarSourceMap, Html, IntoResponse, Sse},
        },
        sse::datastar::{Namespace, PatchElements},
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::str::non_empty_str,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

static NEXT_SHAPE: AtomicUsize = AtomicUsize::new(0);

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

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(62059), exec.clone())
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );
    tracing::info!("open http://{bind_address} in your browser");

    graceful.spawn_task(async move {
        let router = Arc::new(
            Router::new()
                .with_get("/", Html(INDEX_CONTENT))
                .with_get("/shape", next_shape)
                .with_get("/assets/datastar.js", DatastarScript::default())
                .with_get("/assets/datastar.js.map", DatastarSourceMap::default()),
        );
        let app = (TraceLayer::new_for_http(), ErrorHandlerLayer::new()).into_layer(router);
        listener.serve(HttpServer::auto(exec).service(app)).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn next_shape() -> impl IntoResponse {
    let elements = match NEXT_SHAPE.fetch_add(1, Ordering::Relaxed) % 3 {
        0 => non_empty_str!(
            r##"<rect id="shape" x="35" y="35" width="130" height="130" rx="16" fill="#0ea5e9" />"##
        ),
        1 => non_empty_str!(
            r##"<polygon id="shape" points="100,20 180,180 20,180" fill="#a855f7" />"##
        ),
        _ => non_empty_str!(r##"<circle id="shape" cx="100" cy="100" r="80" fill="#f97316" />"##),
    };

    let patch = PatchElements::new(elements).with_namespace(Namespace::Svg);
    Sse::new(stream_fn(async move |mut yielder| {
        yielder.yield_item(patch.try_into_sse_event()).await;
    }))
}

const INDEX_CONTENT: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Datastar SVG</title>
  <script type="module" src="/assets/datastar.js"></script>
  <style>
    body { font-family: sans-serif; margin: 4rem auto; max-width: 24rem; text-align: center; }
    svg { display: block; margin: 2rem auto; }
    button { font: inherit; padding: .6rem 1rem; }
  </style>
</head>
<body>
  <h1>Datastar SVG</h1>
  <svg viewBox="0 0 200 200" width="200" height="200">
    <circle id="shape" cx="100" cy="100" r="80" fill="#22c55e" />
  </svg>
  <button data-on:click="@get('/shape')">Next shape</button>
</body>
</html>
"##;
