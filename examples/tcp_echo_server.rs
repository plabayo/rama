use rama::transport::{bytes::service::EchoService, tcp::server::TcpListener};

use anyhow::{Context, Result};
use tower_async::make::Shared;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let service = Shared::new(EchoService::new());
    TcpListener::new()
        .context("create TCP listener")?
        .shutdown_timeout(std::time::Duration::from_secs(5))
        .serve::<Shared<EchoService>>(service)
        .await
        .context("serve incoming TCP connections")?;
    Ok(())
}
