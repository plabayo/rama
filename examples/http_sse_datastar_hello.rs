//! SSE Example, showcasing a very simple datastar example,
//! which is supported by rama both on the client as well as the server side.
//!
//! Datastar helps you build reactive web applications with the simplicity
//! of server-side rendering and the power of a full-stack SPA framework.
//!
//! It's the combination of a small js library which makes use of SSE among other utilities,
//! this module implements the event data types used from the server-side to send to the client,
//! which makes use of this JS library.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_sse_datastar_hello --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62031`. You open the url in your browser to easily interact:
//!
//! ```sh
//! open http://127.0.0.1:62031
//! ```
//!
//! This will open a web page which will be a simple hello world data app.

use rama::{
    Layer,
    error::OpaqueError,
    http::{
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            response::{Html, IntoResponse, Sse},
        },
        sse::server::{KeepAlive, KeepAliveStream},
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
};

use async_stream::stream;
use rama_http::{service::web::extract::datastar::ReadSignals, sse::datastar::MergeFragments};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
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

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62031))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(%bind_address, "http's tcp listener ready to serve");
    tracing::info!(
        "open http://{} in your browser to see the service in action",
        bind_address
    );

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());
        let app = (TraceLayer::new_for_http()).into_layer(Arc::new(
            Router::new()
                .get("/", index)
                .get("/hello-world", hello_world),
        ));
        listener
            .serve_graceful(guard, HttpServer::auto(exec).service(app))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn index() -> Html<&'static str> {
    Html(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <title>Datastar SDK Demo</title>
    <script src="https://unpkg.com/@tailwindcss/browser@4"></script>
    <script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.0-beta.11/bundles/datastar.js"></script>
</head>
<body class="bg-white dark:bg-gray-900 text-lg max-w-xl mx-auto my-16">
    <div data-signals-delay="400" class="bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 rounded-lg px-6 py-8 ring shadow-xl ring-gray-900/5 space-y-2">
        <div class="flex justify-between items-center">
            <h1 class="text-gray-900 dark:text-white text-3xl font-semibold">
                Datastar SDK Demo
            </h1>
            <img src="https://data-star.dev/static/images/rocket.png" alt="Rocket" width="64" height="64"/>
        </div>
        <p class="mt-2">
            SSE events will be streamed from the backend to the frontend.
        </p>
        <div class="space-x-2">
            <label for="delay">
                Delay in milliseconds
            </label>
            <input data-bind-delay id="delay" type="number" step="100" min="0" class="w-36 rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-sky-500 focus:outline focus:outline-sky-500 dark:disabled:border-gray-700 dark:disabled:bg-gray-800/20" />
        </div>
        <button data-on-click="@get(&#39;/hello-world&#39;)" class="rounded-md bg-sky-500 px-5 py-2.5 leading-5 font-semibold text-white hover:bg-sky-700 hover:text-gray-100 cursor-pointer">
            Start
        </button>
    </div>
    <div class="my-16 text-8xl font-bold text-transparent" style="background: linear-gradient(to right in oklch, red, orange, yellow, green, blue, blue, violet); background-clip: text">
        <div id="message">Hello, world!</div>
    </div>
</body>
</html>"##,
    )
}

#[derive(Deserialize)]
pub struct Signals {
    pub delay: u64,
}

const MESSAGE: &str = "Hello, world!";

async fn hello_world(ReadSignals(signals): ReadSignals<Signals>) -> impl IntoResponse {
    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream! {
            for i in 0..MESSAGE.len() {
                yield Ok::<_, OpaqueError>(MergeFragments::new(format!("<div id='message'>{}</div>", &MESSAGE[0..i + 1])).into_sse_event());
                tokio::time::sleep(Duration::from_millis(signals.delay)).await;
            }
        },
    ))
}
