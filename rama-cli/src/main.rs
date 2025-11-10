//! entrypoint for rama-cli

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use clap::{Parser, Subcommand};

use crate::utils::error::ErrorWithExitCode;

pub mod cmd;
pub mod trace;
pub mod utils;

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "rama")]
#[command(bin_name = "rama")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmds: CliCommands,
}

#[derive(Debug, Parser)]
#[command(name = "rama")]
#[command(bin_name = "rama")]
#[command(version, about, long_about = None)]
struct CliDefault {
    #[command(flatten)]
    cmd: cmd::send::SendCommand,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum CliCommands {
    Send(cmd::send::SendCommand),
    Serve(cmd::serve::ServeCommand),
    Probe(cmd::probe::ProbeCommand),
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse().or_else(|err| match err.kind() {
        clap::error::ErrorKind::DisplayHelp => Err(err),
        _ => CliDefault::try_parse().map(|cli_default| Cli {
            cmds: CliCommands::Send(cli_default.cmd),
        }),
    }) {
        Err(e) => e.exit(),
        Ok(cli) => cli,
    };

    #[allow(clippy::exit)]
    if let Err(err) = match cli.cmds {
        CliCommands::Send(cfg) => cmd::send::run(cfg).await,
        CliCommands::Serve(cfg) => cmd::serve::run(cfg).await,
        CliCommands::Probe(cfg) => cmd::probe::run(cfg).await,
    } {
        eprintln!("🚩 exit with error: {err}");
        let exit_code = err
            .downcast_ref::<ErrorWithExitCode>()
            .map(|err| err.code)
            .unwrap_or(1);
        std::process::exit(exit_code);
    }
}
