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

use http::StatusCode;
use rama::{
    Context, Layer,
    error::OpaqueError,
    http::{
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            extract::datastar::ReadSignals,
            response::{Html, IntoResponse, Sse},
        },
        sse::{
            JsonEventData,
            datastar::{EventData, MergeFragments, MergeSignals},
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
};

use async_stream::stream;
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{broadcast, mpsc};
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

    let delay = Arc::new(AtomicU64::new(400));
    let msg_index = Arc::new(AtomicUsize::new(MESSAGE.len()));
    let (data_tx, _data_rx) = broadcast::channel(MESSAGE.len());
    let (reset_tx, mut reset_rx) = mpsc::channel(128);

    let delay_tx = delay.clone();
    let msg_index_tx = msg_index.clone();
    let main_data_tx = data_tx.clone();
    graceful.spawn_task_fn(async move |guard| {
        let mut cancelled = std::pin::pin!(guard.downgrade().into_cancelled());
        loop {
            tokio::select! {
                Some(delay) = reset_rx.recv() => {
                    tracing::info!(%delay, "reset received, continue main once again");
                    delay_tx.store(delay, Ordering::Release);
                    if let Err(err) = main_data_tx.send(Data::Signal(delay)) {
                        tracing::error!(%err, "failed to broadcast signal: exit background task");
                        return;
                    }
                }
                _ = &mut cancelled => {
                    tracing::info!("graceful shutdown: exit background task");
                    return;
                }
            }
            let mut i = 0;
            while i < MESSAGE.len() {
                i += 1;
                msg_index_tx.store(i, Ordering::Release);
                tracing::debug!(%i, "enter message loop iteration");

                tokio::select! {
                    Some(delay) = reset_rx.recv() => {
                        tracing::debug!(%delay, "reset received during msg broadcast, continue main once again");
                        delay_tx.store(delay, Ordering::Release);
                        i = 0;
                        if let Err(err) = main_data_tx.send(Data::Signal(delay)) {
                            tracing::error!(%err, "failed to broadcast signal: exit background task");
                            return;
                        }
                    }
                    _ = &mut cancelled => {
                        tracing::info!("graceful shutdown: exit background task");
                        return;
                    }
                    _ = std::future::ready(()) => {
                        tracing::debug!(%i, "send next message");
                        tokio::select! {
                            Some(delay) = reset_rx.recv() => {
                                tracing::debug!(%delay, "reset received during delay, continue main once again");
                                delay_tx.store(delay, Ordering::Release);
                                i = 0;
                                if let Err(err) = main_data_tx.send(Data::Signal(delay)) {
                                    tracing::error!(%err, "failed to broadcast signal: exit background task");
                                    return;
                                }
                                continue;
                            }
                            _ = tokio::time::sleep(Duration::from_millis(delay_tx.load(Ordering::Acquire))) => ()
                        }
                        if let Err(err) = main_data_tx.send(Data::Fragment(&MESSAGE[..i])) {
                            tracing::error!(%err, "failed to broadcast fragment: exit background task");
                            return;
                        }
                    }
                }
            }
        }
    });

    let state = State {
        delay,
        msg_index,
        reset_tx,
        data_tx,
    };

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());
        let app = (TraceLayer::new_for_http()).into_layer(Arc::new(
            Router::new()
                .get("/", index)
                .get("/reset", reset)
                .get("/hello-world", hello_world),
        ));
        listener
            .with_state(state)
            .serve_graceful(guard, HttpServer::auto(exec).service(app))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
enum Data {
    Fragment(&'static str),
    Signal(u64),
}

#[derive(Debug, Clone)]
pub struct State {
    delay: Arc<AtomicU64>,
    msg_index: Arc<AtomicUsize>,
    reset_tx: mpsc::Sender<u64>,
    data_tx: broadcast::Sender<Data>,
}

async fn index(ctx: Context<State>) -> Html<String> {
    Html(format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <title>Datastar SDK Demo</title>
    <script src="https://unpkg.com/@tailwindcss/browser@4"></script>
    <script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.0-beta.11/bundles/datastar.js"></script>
</head>
<body class="bg-white dark:bg-gray-900 text-lg max-w-xl mx-auto my-16">
    <div data-signals-delay="{}"
            class="bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 rounded-lg px-6 py-8 ring shadow-xl ring-gray-900/5 space-y-2">
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
        <button data-on-click="@get(&#39;/reset&#39;)" class="rounded-md bg-sky-500 px-5 py-2.5 leading-5 font-semibold text-white hover:bg-sky-700 hover:text-gray-100 cursor-pointer">
            Reset
        </button>
    </div>
    <div class="my-16 text-8xl font-bold text-transparent" style="background: linear-gradient(to right in oklch, red, orange, yellow, green, blue, blue, violet); background-clip: text">
        <div
            data-on-load__delay="@get('/hello-world')"
            id="message">
            {}
        </div>
    </div>
    <div class="text-gray-900 dark:text-white text-3xl font-semibold">
        <pre data-text="ctx.signals.JSON()">Signals</pre>
    </div>
</body>
</html>"##,
        ctx.state().delay.load(Ordering::Acquire),
        &MESSAGE[0..ctx.state().msg_index.load(Ordering::Acquire)],
    ))
}

#[derive(Deserialize)]
pub struct Signals {
    pub delay: u64,
}

const MESSAGE: &str = "Hello, world!";

async fn reset(
    ctx: Context<State>,
    ReadSignals(signals): ReadSignals<Signals>,
) -> impl IntoResponse {
    match tokio::time::timeout(
        Duration::from_secs(5),
        ctx.state().reset_tx.send(signals.delay),
    )
    .await
    {
        Ok(_) => StatusCode::OK,
        Err(err) => {
            tracing::error!(%err, "reset animation with new delay");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn hello_world(
    ctx: Context<State>,
    ReadSignals(_): ReadSignals<Signals>,
) -> impl IntoResponse {
    let mut data_rx = ctx.state().data_tx.subscribe();
    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream! {
            while let Ok(value) = data_rx.recv().await {
                let data: EventData<_> = match value {
                    Data::Fragment(msg) => MergeFragments::new(format!("<div id='message'>{}</div>", msg)).into(),
                    Data::Signal(delay) => MergeSignals::new(JsonEventData(json!({
                        "delay": delay,
                    }))).into(),
                };
                yield Ok::<_, OpaqueError>(data.into_sse_event());
            }
        },
    ))
}
