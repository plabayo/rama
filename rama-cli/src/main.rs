//! entrypoint for rama-cli

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![expect(
    clippy::allow_attributes,
    reason = "CLI: a few `#[allow]` annotations stay because their underlying lints (e.g. clippy::exit) only fire on some cfgs"
)]

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
#[command(version = None, about = None, long_about = None)]
struct CliDefault {
    #[command(flatten)]
    cmd: cmd::send::SendCommand,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "Subcommand variants vary in size; reordering would change CLI semantics"
)]
enum CliCommands {
    Resolve(cmd::resolve::ResolveCommand),
    Send(cmd::send::SendCommand),
    Serve(cmd::serve::ServeCommand),
    Probe(cmd::probe::ProbeCommand),
}

#[tokio::main]
async fn main() {
    #[expect(
        clippy::print_stdout,
        reason = "CLI: stdout is part of the user-facing output contract"
    )]
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => match err.kind() {
            clap::error::ErrorKind::DisplayHelp => {
                if err.render().to_string().contains("rama <COMMAND>") {
                    _ = err.print();
                    println!();
                    println!(
                        "When invoked without a subcommand, `rama` executes the `send` command."
                    );
                    println!("Refer to the `send` command section below.");
                    println!();
                    CliDefault::parse_from(["rama", "--help"]);
                    #[expect(
                        clippy::unreachable,
                        reason = "CliDefault::parse_from(...--help...) calls process::exit before returning"
                    )]
                    {
                        unreachable!("previous statement should exit")
                    }
                } else {
                    err.exit()
                }
            }
            clap::error::ErrorKind::DisplayVersion => err.exit(),
            _ => {
                if std::env::args()
                    .nth(1)
                    .map(|s| {
                        ["-V", "--version", "-h", "--help", "send", "serve", "probe"]
                            .contains(&s.trim())
                    })
                    .unwrap_or_default()
                {
                    err.exit()
                } else {
                    Cli {
                        cmds: CliCommands::Send(CliDefault::parse().cmd),
                    }
                }
            }
        },
    };

    #[allow(clippy::exit, reason = "CLI: explicit exit code propagation")]
    if let Err(err) = match cli.cmds {
        CliCommands::Resolve(cfg) => Box::pin(cmd::resolve::run(cfg)).await,
        CliCommands::Send(cfg) => Box::pin(cmd::send::run(cfg)).await,
        CliCommands::Serve(cfg) => Box::pin(cmd::serve::run(cfg)).await,
        CliCommands::Probe(cfg) => Box::pin(cmd::probe::run(cfg)).await,
    } {
        eprintln!("🚩 exit with error: {err}");
        let exit_code = err
            .downcast_ref::<ErrorWithExitCode>()
            .map(|err| err.code)
            .unwrap_or(1);
        std::process::exit(exit_code);
    }
}
