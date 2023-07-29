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
    /// Optional timeout to wait until forcing a shutdown
    #[arg(short, long, value_parser = parse_duration)]
    timeout: Option<std::time::Duration>,

    /// the graceful kind of service to use
    #[arg(short, long, value_parser = parse_graceful, default_value_t = Graceful::SigInt)]
    graceful: Graceful,

    /// an optional network interface to bind to
    #[arg(short, long)]
    interface: Option<String>,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

fn parse_graceful(arg: &str) -> Result<Graceful, &'static str> {
    match arg {
        "pending" => Ok(Graceful::Pending),
        "sigint" => Ok(Graceful::SigInt),
        "sigterm" => Ok(Graceful::SigTerm),
        _ => Err("invalid graceful kind"),
    }
}

#[derive(Debug, Clone)]
enum Graceful {
    Pending,
    SigInt,
    SigTerm,
}

impl std::fmt::Display for Graceful {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Graceful::Pending => write!(f, "pending"),
            Graceful::SigInt => write!(f, "sigint"),
            Graceful::SigTerm => write!(f, "sigterm"),
        }
    }
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

    let mut builder = match args.interface {
        Some(interface) => TcpListener::bind(interface).context("bind TCP listener"),
        None => TcpListener::new().context("create TCP listener"),
    }?;

    if let Some(timeout) = args.timeout {
        builder.shutdown_timeout(timeout);
    }

    match args.graceful {
        Graceful::Pending => {
            builder.graceful_without_signal();
        }
        Graceful::SigInt => (),
        Graceful::SigTerm => {
            builder.graceful_sigterm();
        }
    };

    builder
        .serve::<Shared<EchoService>>(service)
        .await
        .context("serve incoming TCP connections")?;

    // instead of a random local port, you can also bind to a specific address
    // using the `bind` method as follows:
    // TcpListener::bind("127.0.0.1:8080")

    Ok(())
}
