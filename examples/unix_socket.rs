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

#[cfg(target_family = "unix")]
mod unix_example {
    use rama::{
        Layer,
        error::BoxError,
        extensions::ExtensionsRef,
        graceful::ShutdownGuard,
        layer::AddExtensionLayer,
        service::service_fn,
        stream::Stream,
        telemetry::tracing::{self, level_filters::LevelFilter},
        unix::server::UnixListener,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        let listener = UnixListener::build()
            .bind_path(PATH)
            .await
            .expect("bind Unix socket");

        graceful.spawn_task_fn(async |guard| {
            async fn handle(
                mut stream: impl Stream + Unpin + ExtensionsRef,
            ) -> Result<(), BoxError> {
                let mut buf = [0u8; 1024];
                // TODO instead of having to do this manually, make this a lot easier by having this
                // inserted in extensions automatically (part of executor/graceful server)
                // Should be done when https://github.com/plabayo/rama/issues/462 is finished
                let guard = stream.extensions().get::<ShutdownGuard>().unwrap().clone();

                loop {
                    let n = tokio::select! {
                        _ = guard.cancelled() => {
                            tracing::info!("stop read loop, shutdown complete");
                            return Ok(());
                        }
                        result = stream.read(&mut buf) => {
                            result.expect("foo")
                        }
                    };

                    if n == 0 {
                        tracing::info!("stream read empty, exit!");
                        return Ok(());
                    }

                    let read_buf = &mut buf[..n];
                    read_buf.trim_ascii();
                    if read_buf.is_empty() {
                        tracing::info!("ignore space-only read");
                        continue;
                    }

                    tracing::debug!(
                        data = %String::from_utf8_lossy(read_buf).trim(),
                        "reverse received data and exist",
                    );
                    read_buf.reverse();
                    stream.write_all(read_buf).await?;
                }
            }

            tracing::info!(
                file.path = %PATH,
                "ready to unix-serve",
            );
            listener
                .serve_graceful(
                    guard.clone(),
                    AddExtensionLayer::new(guard).into_layer(service_fn(handle)),
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
