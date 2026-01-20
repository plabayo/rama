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
    use std::sync::Arc;

    use rama::{
        http::{server::HttpServer, service::web::Router},
        rt::Executor,
        telemetry::tracing::{
            self,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
        unix::server::UnixListener,
    };

    pub(super) async fn run() {
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

        const PATH: &str = "/tmp/rama_example_unix_http.socket";

        let listener = UnixListener::bind_path(PATH, exec.clone())
            .await
            .expect("bind Unix socket");

        graceful.spawn_task(async move {
            tracing::info!(
                file.path = %PATH,
                "ready to unix-serve",
            );
            listener
                .serve(
                    HttpServer::http1(exec)
                        .service(Arc::new(Router::new().with_get("/ping", "pong"))),
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
