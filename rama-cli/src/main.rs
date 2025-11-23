//! entrypoint for rama-cli

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
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
#[allow(clippy::large_enum_variant)]
enum CliCommands {
    Send(cmd::send::SendCommand),
    Serve(cmd::serve::ServeCommand),
    Probe(cmd::probe::ProbeCommand),
}

#[tokio::main]
async fn main() {
    #[allow(clippy::print_stdout)]
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => match err.kind() {
            clap::error::ErrorKind::DisplayHelp => {
                if err.render().to_string().contains("rama <COMMAND>") {
                    let _ = err.print();
                    println!();
                    println!(
                        "When invoked without a subcommand, `rama` executes the `send` command."
                    );
                    println!("Refer to the `send` command section below.");
                    println!();
                    CliDefault::parse_from(["rama", "--help"]);
                    unreachable!("previous statement should exit");
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
