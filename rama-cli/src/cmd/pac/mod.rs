//! PAC evaluation and generation commands.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI: PAC results and interactive prompts are terminal output"
)]

use clap::{Args, Subcommand};
use rama::{error::BoxError, telemetry::tracing::subscriber::filter::LevelFilter};

mod eval;
mod generate;
mod source;

/// Evaluate and generate Proxy Auto-Configuration scripts.
#[derive(Debug, Args)]
pub struct PacCommand {
    #[command(subcommand)]
    command: PacSubcommand,

    /// Enable debug logs (also configurable through `RUST_LOG`).
    #[arg(long, short = 'v', global = true, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum PacSubcommand {
    /// Evaluate a PAC script for one or more URIs.
    Eval(eval::EvalCommand),
    /// Generate a PAC script from ordered domain routes.
    Generate(generate::GenerateCommand),
}

pub async fn run(command: PacCommand) -> Result<(), BoxError> {
    match command.command {
        PacSubcommand::Eval(config) => {
            crate::trace::init_tracing(if command.verbose {
                LevelFilter::DEBUG
            } else {
                LevelFilter::WARN
            })?;
            eval::run(config).await
        }
        PacSubcommand::Generate(config) => generate::run(config),
    }
}
