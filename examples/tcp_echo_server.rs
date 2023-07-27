use rama::transport::{bytes::service::EchoService, tcp::server::TcpListener};

use tower_async::{make::Shared, BoxError};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let service = Shared::new(EchoService::new());
    TcpListener::new()?.serve(service).await?;
    Ok(())
}
