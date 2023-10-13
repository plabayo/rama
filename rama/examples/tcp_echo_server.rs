use rama::transport::{bytes::service::EchoService, tcp::server::TcpListener};

use anyhow::{Context, Result};
use clap::Parser;
use tower_async::make::Shared;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Simple Tcp echo server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// an optional network interface to bind to
    #[arg(short, long)]
    interface: Option<String>,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

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

    let args = Args::parse();

    let service = Shared::new(EchoService::new());

    let builder = match args.interface {
        Some(interface) => TcpListener::bind(interface).context("bind TCP listener"),
        None => TcpListener::new().context("create TCP listener"),
    }?;

    builder
        .serve_graceful::<Shared<EchoService>>(service)
        .await
        .context("serve incoming TCP connections")?;

    // instead of a random local port, you can also bind to a specific address
    // using the `bind` method as follows:
    // TcpListener::bind("127.0.0.1:8080")

    Ok(())
}
