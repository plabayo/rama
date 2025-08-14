//! entrypoint for rama-cli

#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use clap::{Parser, Subcommand};
use rama::error::BoxError;

pub mod cmd;
use cmd::{echo, fp, http, ip, proxy, serve, tls, ws};

pub mod error;

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

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum CliCommands {
    Http(http::CliCommandHttp),
    Ws(ws::CliCommandWs),
    Tls(tls::CliCommandTls),
    Proxy(proxy::CliCommandProxy),
    Echo(echo::CliCommandEcho),
    Ip(ip::CliCommandIp),
    Fp(fp::CliCommandFingerprint),
    Serve(serve::CliCommandServe),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    #[allow(clippy::exit)]
    match match cli.cmds {
        CliCommands::Http(cfg) => http::run(cfg).await,
        CliCommands::Ws(cfg) => ws::run(cfg).await,
        CliCommands::Tls(cfg) => tls::run(cfg).await,
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
        CliCommands::Echo(cfg) => echo::run(cfg).await,
        CliCommands::Ip(cfg) => ip::run(cfg).await,
        CliCommands::Fp(cfg) => fp::run(cfg).await,
        CliCommands::Serve(cfg) => serve::run(cfg).await,
    } {
        Ok(()) => Ok(()),
        Err(err) => {
            if let Some(err) = err.downcast_ref::<error::ErrorWithExitCode>() {
                eprintln!("🚩 exit with error ({}): {err}", err.exit_code());
                std::process::exit(err.exit_code());
            } else {
                eprintln!("🚩 exit with error: {err}");
                std::process::exit(1);
            }
        }
    }
}
