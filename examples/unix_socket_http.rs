//! An example to show how to listen on a Unix (domain) socket,
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
//! You can use `curl` to interact with the service:
//!
//! ```sh
//! curl --unix-socket /tmp/rama_example_unix_http.socket http://localhost/ping
//! ```
//!
//! You should receive `pong` back as the payload of a 200 OK response.
//! The host here is ignored and is just to make the uri valid.

#[cfg(target_family = "unix")]
mod unix_example {
    use rama::{
        http::server::HttpServer,
        http::service::web::Router,
        telemetry::tracing::{self, level_filters::LevelFilter},
        unix::server::UnixListener,
    };

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

        let listener = UnixListener::bind_path(PATH)
            .await
            .expect("bind Unix socket");

        graceful.spawn_task_fn(async |guard| {
            tracing::info!(
                file.path = %PATH,
                "ready to unix-serve",
            );
            listener
                .serve_graceful(
                    guard,
                    HttpServer::http1().service(Router::new().get("/ping", "pong")),
                )
                .await;
        });

        let duration = graceful.shutdown().await;
        tracing::info!(
           shutdown.duration_ms = %duration.as_millis(),
           "bye!",
        );
    }
}

#[cfg(target_family = "unix")]
use unix_example::run;

#[cfg(not(target_family = "unix"))]
async fn run() {
    println!("unix_socket example is a unix-only example, bye now!");
}

#[tokio::main]
async fn main() {
    run().await
}
