//! entrypoint for rama-cli

#![warn(
    clippy::all,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use clap::{Parser, Subcommand};
use rama::error::BoxError;

pub mod cmd;
use cmd::{echo, http, ip, proxy};

pub mod error;

#[derive(Debug, Parser)]
#[command(name = "rama")]
#[command(bin_name = "rama")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmds: CliCommands,
}

#[derive(Debug, Subcommand)]
enum CliCommands {
    Echo(echo::CliCommandEcho),
    Http(http::CliCommandHttp),
    Proxy(proxy::CliCommandProxy),
    Ip(ip::CliCommandIp),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    #[allow(clippy::exit)]
    match match cli.cmds {
        CliCommands::Echo(cfg) => echo::run(cfg).await,
        CliCommands::Http(cfg) => http::run(cfg).await,
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
        CliCommands::Ip(cfg) => ip::run(cfg).await,
    } {
        Ok(()) => Ok(()),
        Err(err) => {
            if let Some(err) = err.downcast_ref::<error::ErrorWithExitCode>() {
                tracing::error!(err = %err, "exit with error ({})", err.exit_code());
                std::process::exit(err.exit_code());
            } else {
                tracing::error!(err = %err, "exit with error");
                std::process::exit(1);
            }
        }
    }
}
