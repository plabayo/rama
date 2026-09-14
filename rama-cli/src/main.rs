//! entrypoint for rama-cli

// the send client and deeply layered services (e.g. fp with rate limiting)
// have nested generic types that exceed the default query depth
#![recursion_limit = "256"]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![expect(
    clippy::allow_attributes,
    reason = "CLI: a few `#[allow]` annotations stay because their underlying lints (e.g. clippy::exit) only fire on some cfgs"
)]

use clap::{Parser, Subcommand};
use rama::{
    error::{BoxError, ErrorContext as _},
    rt::OwnedRuntime,
};

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
    reason = "Subcommand variants vary in size; reordering would change CLI semantics"
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

const WORKER_THREAD_NAME: &str = "rama-worker";

/// The CLI's runtime: a multi-thread scheduler built explicitly so its workers
/// are recognisable in process listings and, with the `dial9` feature and
/// `DIAL9_ENABLED` set, a recorder is attached for runtime telemetry.
fn build_runtime() -> std::io::Result<OwnedRuntime> {
    #[cfg(feature = "dial9")]
    if dial9_enabled_from_env() {
        let (recorder, runtime) = dial9::recorder_from_env_with(|builder| {
            builder.enable_all().thread_name(WORKER_THREAD_NAME);
        })?;
        if recorder.handle().is_enabled() {
            return Ok(OwnedRuntime::from_dial9((recorder, runtime)));
        }
        // the environment resolved to telemetry-off after all
        drop((recorder, runtime));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(WORKER_THREAD_NAME)
        .build()?;
    Ok(OwnedRuntime::from_tokio(runtime))
}

#[cfg(feature = "dial9")]
fn dial9_enabled_from_env() -> bool {
    std::env::var("DIAL9_ENABLED").is_ok_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "f" | "false" | "0" | "n" | "no" | "off"
        )
    })
}

fn main() -> Result<(), BoxError> {
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
            #[allow(clippy::exit, reason = "CLI: bare invocation shows help")]
            std::process::exit(2);
        }
    };

    let runtime = build_runtime().context("build tokio runtime")?;
    // Keep command futures off Windows' smaller process-main stack.
    let result = runtime
        .block_on(async { rama::rt::spawn(run(cmds)).await })
        .context("join CLI command task")?;

    #[allow(clippy::exit, reason = "CLI: explicit exit code propagation")]
    if let Err(err) = result {
        eprintln!("🚩 exit with error: {err}");
        let exit_code = err
            .downcast_ref::<ErrorWithExitCode>()
            .map(|err| err.code)
            .unwrap_or(1);
        std::process::exit(exit_code);
    }

    Ok(())
}

async fn run(cmds: CliCommands) -> Result<(), BoxError> {
    match cmds {
        CliCommands::Pac(cfg) => Box::pin(cmd::pac::run(cfg)).await,
        CliCommands::Resolve(cfg) => Box::pin(cmd::resolve::run(cfg)).await,
        CliCommands::Send(cfg) => Box::pin(cmd::send::run(cfg)).await,
        CliCommands::Serve(cfg) => Box::pin(cmd::serve::run(cfg)).await,
        CliCommands::Probe(cfg) => Box::pin(cmd::probe::run(cfg)).await,
    }
}
