use rama::error::BoxError;

use clap::{Args, Subcommand};
use tracing_subscriber::filter::LevelFilter;

pub mod tls;

// TOOD: tcp / udp

pub async fn run(cfg: ProbeCommand) -> Result<(), BoxError> {
    crate::trace::init_tracing(if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    });

    match cfg.commands {
        ProbeSubcommand::Tls(cfg) => tls::run(cfg).await,
    }
}

#[derive(Debug, Args)]
/// probe network services
pub struct ProbeCommand {
    #[command(subcommand)]
    pub commands: ProbeSubcommand,

    /// enable debug logs for tracing (possible via RUST_LOG env as well)
    #[arg(long, short = 'v', global = true, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum ProbeSubcommand {
    /// probe a server for its Tls capabilities
    Tls(tls::CliCommandTls),
}
