//! TODO TODO TODO An example to show how to listen on a Unix (domain) socket,
//! for incoming connections. This can be useful for "local" interactions
//! with your public service or for a local-first service.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example unix_socket_http --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `/tmp/rama_example_unix_http.socket`.
//! You can use `socat` to interact with the service:
//!
//! ```sh
//! curl --unix-socket /tmp/rama_example_unix_http.socket http://localhost/ping
//! ```
//!
//! You should receive `pong` back as the payload of a 200 OK response.
//! The host here is ignored and is just to make the uri valid.

#[cfg(unix)]
mod unix_example {
    use rama::{http::server::HttpServer, http::service::web::Router, unix::server::UnixListener};

    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    pub(super) async fn run() {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::DEBUG.into())
                    .from_env_lossy(),
            )
            .init();

        let graceful = rama::graceful::Shutdown::default();

        const PATH: &str = "/tmp/rama_example_unix_http.socket";

        let listener = UnixListener::bind_path(PATH).expect("bind Unix socket");

        graceful.spawn_task_fn(async |guard| {
            tracing::info!(%PATH, "ready to unix-serve");
            listener
                .serve_graceful(
                    guard,
                    HttpServer::http1().service(Router::new().get("/ping", "pong")),
                )
                .await;
        });

        let duration = graceful.shutdown().await;
        tracing::info!(shutdown_after = ?duration, "bye!");
    }
}

#[cfg(unix)]
use unix_example::run;

#[cfg(not(unix))]
async fn run() {
    println!("unix_socket example is a unix-only example, bye now!");
}

#[tokio::main]
async fn main() {
    run().await
}
