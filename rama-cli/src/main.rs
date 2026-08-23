//! entrypoint for rama-cli

// the send client and deeply layered services (e.g. fp with rate limiting)
// have nested generic types that exceed the default query depth
#![recursion_limit = "256"]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

use clap::{Parser, Subcommand};
use std::process::ExitCode;

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
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    cmds: Option<CliCommands>,

    #[command(flatten)]
    send: Option<cmd::send::SendCommand>,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "Subcommand variants vary in size; boxing would complicate CLI dispatch"
)]
enum CliCommands {
    Pac(cmd::pac::PacCommand),
    Resolve(cmd::resolve::ResolveCommand),
    Send(cmd::send::SendCommand),
    Serve(cmd::serve::ServeCommand),
    Probe(cmd::probe::ProbeCommand),
}

/// re-parse argv against the subcommands alone: a typo'd subcommand is
/// otherwise swallowed as `<URI>`, hiding clap's "did you mean" tip
fn with_subcommand_typo_tip(err: clap::Error) -> clap::Error {
    let probe = CliCommands::augment_subcommands(
        clap::Command::new("rama")
            .bin_name("rama")
            .subcommand_required(true),
    );
    match probe.try_get_matches() {
        Err(sub_err)
            if sub_err
                .get(clap::error::ContextKind::SuggestedSubcommand)
                .is_some() =>
        {
            sub_err
        }
        _ => err,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => match err.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                err.exit()
            }
            _ => with_subcommand_typo_tip(err).exit(),
        },
    };
    let cmds = match (cli.cmds, cli.send) {
        (Some(cmds), _) => cmds,
        (None, Some(send)) => CliCommands::Send(send),
        // defensive: clap already rejects bare invocations (<URI> is required)
        (None, None) => {
            use clap::CommandFactory;
            _ = Cli::command().print_help();
            return ExitCode::from(2);
        }
    };

    match match cmds {
        CliCommands::Pac(cfg) => Box::pin(cmd::pac::run(cfg)).await,
        CliCommands::Resolve(cfg) => Box::pin(cmd::resolve::run(cfg)).await,
        CliCommands::Send(cfg) => Box::pin(cmd::send::run(cfg)).await,
        CliCommands::Serve(cfg) => Box::pin(cmd::serve::run(cfg)).await,
        CliCommands::Probe(cfg) => Box::pin(cmd::probe::run(cfg)).await,
    } {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("🚩 exit with error: {err}");
            let exit_code = err
                .downcast_ref::<ErrorWithExitCode>()
                .and_then(|err| u8::try_from(err.code).ok())
                .unwrap_or(1);
            ExitCode::from(exit_code)
        }
    }
}
