use anyhow::Context;
use tokio::net::TcpStream;
use tracing::Level;

use rama::core::transport::tcp::server::{Listener, Result};

async fn hello(stream: TcpStream) -> Result<()> {
    tracing::info!("Hello {:?}!", stream.peer_addr());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).context("set global tracing subscriber")?;

    Listener::bind("127.0.0.1:20018").serve(hello).await
}
