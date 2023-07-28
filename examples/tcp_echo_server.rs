use rama::transport::{bytes::service::EchoService, tcp::server::TcpListener};

use anyhow::{Context, Result};
use tower_async::make::Shared;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let service = Shared::new(EchoService::new());
    TcpListener::new()
        .context("create TCP listener")?
        .shutdown_timeout(std::time::Duration::from_secs(5)) // set to '0' to disable shutdown
        // use "graceful_without_signal" to not listen to any signal
        // .graceful_without_signal()
        // for some environments you might wish to trigger a shutdown based on the "SIGTERM" signal
        // instead of CTRL+C (SIGINT), available on UNIX platforms only.
        // .graceful_sigterm()
        .serve::<Shared<EchoService>>(service)
        .await
        .context("serve incoming TCP connections")?;

    // instead of a random local port, you can also bind to a specific address
    // using the `bind` method as follows:
    // TcpListener::bind("127.0.0.1:8080")

    Ok(())
}
