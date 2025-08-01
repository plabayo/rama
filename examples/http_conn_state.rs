//! An example to show how to wrap states as a way
//! to prepare typed state for inner layers, while keeping the
//! typed state of the outer layer.
//!
//! Examples where this can be useful is for caches that middlewares
//! might require for the life cycle of a connection, without it leaking
//! into the entire app (service) lifecycle.
//!
//! This example will create a server that listens on `127.0.0.1:62000`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_conn_state --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62000`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -v http://127.0.0.1:62000
//! ```
//!
//! You should see an HTTP Status 200 OK with a HTML payload containing the
//! connection index and count of requests within that connection.

use rama::{
    Context, Layer,
    http::service::web::response::Html,
    http::{Request, server::HttpServer},
    layer::MapStateLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Duration,
};

use derive_more::AsRef;

#[derive(Debug, Default)]
struct AppMetrics {
    connections: AtomicUsize,
}

#[derive(Debug)]
struct ConnMetrics {
    /// connection index
    pub index: usize,
    /// amount of requests seen on this connection
    pub requests: AtomicUsize,
}

#[derive(Debug, Clone, AsRef, Default)]
struct AppState {
    /// metrics with the scope of the life cycle
    pub app_metrics: Arc<AppMetrics>,
}

#[derive(Debug, Clone, AsRef)]
struct ConnState {
    /// reference to app life cycle app state
    #[as_ref(AppMetrics)]
    app_metrics: Arc<AppMetrics>,
    /// global state injected directly into the connection state, true if app is alive
    #[as_ref(AtomicBool)]
    alive: Arc<AtomicBool>,
    /// metrics with the scope of the connection
    #[as_ref(ConnMetrics)]
    conn_metrics: Arc<ConnMetrics>,
}

async fn handle_index<S>(ctx: Context<S>, _: Request) -> Result<Html<String>, Infallible>
where
    // NOTE: This example is a bit silly, and only serves to show how one can use `AsRef`
    // trait bounds regardless of how deep the state properties are "nested". In a production
    // codebase however it probably makes more sense to work with the actual type
    // for any non-generic middleware / service.
    S: AsRef<AppMetrics> + AsRef<ConnMetrics> + AsRef<AtomicBool> + Send + Sync + 'static,
{
    let app_metrics: &AppMetrics = ctx.state().as_ref();
    let conn_metrics: &ConnMetrics = ctx.state().as_ref();
    let alive: &AtomicBool = ctx.state().as_ref();

    let conn_count = app_metrics
        .connections
        .load(std::sync::atomic::Ordering::Acquire);
    let request_count = conn_metrics
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        + 1;
    let is_alive = if alive.load(std::sync::atomic::Ordering::Acquire) {
        "yes"
    } else {
        "no"
    };
    let conn_index = conn_metrics.index;

    Ok(Html(format!(
        r##"
            <html>
                <head>
                    <title>Rama — Http Conn State</title>
                </head>
                <body>
                    <h1>Metrics</h1>
                    <p>Alive: {is_alive}
                    <p>Connection <code>{conn_index}</code> of <code>{conn_count}</code></p>
                    <p>Request Count: <code>{request_count}</code></p>
                </body>
            </html>"##
    )))
}

#[tokio::main]
async fn main() {
    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());

        let tcp_http_service = HttpServer::auto(exec).service(service_fn(handle_index));

        // example of data that can be stored as part of the state mapping closure
        let alive = Arc::new(AtomicBool::new(true));

        TcpListener::build_with_state(AppState::default())
            .bind("127.0.0.1:62000")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                MapStateLayer::new(move |app: AppState| {
                    let alive = alive.clone();

                    let index = app
                        .app_metrics
                        .connections
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                        + 1;
                    ConnState {
                        app_metrics: app.app_metrics,
                        alive,
                        conn_metrics: Arc::new(ConnMetrics {
                            index,
                            requests: AtomicUsize::new(0),
                        }),
                    }
                })
                .into_layer(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
