//! An example to show how to listen on a Unix (domain) socket,
//! for incoming connections. This can be useful for "local" interactions
//! with your public service or for a local-first service.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example unix_socket --features=net
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `/tmp/rama_example_unix.socket`.
//! You can use `socat` to interact with the service:
//!
//! ```sh
//! echo -e "hello" | socat - UNIX-CONNECT:/tmp/rama_example_unix.socket
//! ```
//!
//! You should receive `olleh` back, which is "hello" reversed.

#[cfg(unix)]
mod unix_example {
    use rama::{
        error::BoxError, net::stream::Stream, service::service_fn, unix::server::UnixListener,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        const PATH: &str = "/tmp/rama_example_unix.socket";

        let listener = UnixListener::bind_path(PATH).expect("bind Unix socket");

        graceful.spawn_task_fn(async |guard| {
            async fn handle(mut stream: impl Stream + Unpin) -> Result<(), BoxError> {
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await?;
                tracing::debug!(
                    data = %String::from_utf8_lossy(&buf).trim(),
                    "reverse received data and exist",
                );
                buf.reverse();
                stream.write_all(&buf).await?;
                Ok(())
            }

            tracing::info!(%PATH, "ready to unix-serve");
            listener.serve_graceful(guard, service_fn(handle)).await;
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
