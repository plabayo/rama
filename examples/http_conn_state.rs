//! An example to show how to wrap states as a way
//! to prepare typed state for inner layers, while keeping the
//! typed state of the outer layer.
//!
//! Examples where this can be useful is for caches that middlewares
//! might require for the life cycle of a connection, without it leaking
//! into the entire app (service) lifecycle.
//!
//! This example will create a server that listens on `127.0.0.1:8080`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_conn_state
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080
//! ```
//!
//! You should see an HTTP Status 200 OK with a HTML payload containing the
//! connection index and count of requests within that connection.

use rama::{
    http::{response::Html, server::HttpServer, Request},
    rt::Executor,
    service::{context::AsRef, layer::StateWrapperLayer, service_fn, Context, ServiceBuilder},
    tcp::server::TcpListener,
};
use std::{
    convert::Infallible,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

#[derive(Debug, Default)]
struct AppMetrics {
    connections: AtomicUsize,
}

#[derive(Debug, Default)]
struct ConnMetrics {
    requests: AtomicUsize,
}

#[derive(Debug, AsRef, Default)]
struct AppState {
    app_metrics: AppMetrics,
}

#[derive(Debug, AsRef, Default)]
struct ConnState {
    #[as_ref(wrap)]
    app: Arc<AppState>,
    conn_metrics: ConnMetrics,
}

impl From<Arc<AppState>> for ConnState {
    fn from(app: Arc<AppState>) -> Self {
        app.app_metrics
            .connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self {
            app,
            ..Default::default()
        }
    }
}

async fn handle_index<S>(ctx: Context<S>, _: Request) -> Result<Html<String>, Infallible>
where
    S: AsRef<AppMetrics> + AsRef<ConnMetrics> + Send + Sync + 'static,
{
    let app_metrics: &AppMetrics = ctx.state().as_ref();
    let conn_metrics: &ConnMetrics = ctx.state().as_ref();

    let conn_count = app_metrics
        .connections
        .load(std::sync::atomic::Ordering::SeqCst);
    let request_count = conn_metrics
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;

    Ok(Html(format!(
        r##"
            <html>
                <head>
                    <title>Rama — Http Conn State</title>
                </head>
                <body>
                    <h1>Metrics</h1>
                    <p>Connection Count: <code>{conn_count}</code></p>
                    <p>Request Count: <code>{request_count}</code></p>
                </body>
            </html>"##
    )))
}

#[tokio::main]
async fn main() {
    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());

        let tcp_http_service = HttpServer::auto(exec).service(service_fn(handle_index));

        TcpListener::build_with_state(AppState::default())
            .bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                ServiceBuilder::new()
                    .layer(StateWrapperLayer::<ConnState>::new())
                    .service(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
