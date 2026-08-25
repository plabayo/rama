//! PAC evaluation and generation commands.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI: PAC results and interactive prompts are terminal output"
)]

use std::{
    env::home_dir,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Subcommand};
use rama::{
    Layer,
    error::{BoxError, ErrorContext as _},
    http::{
        client::EasyHttpWebClient,
        layer::{
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            uri::{DataUriLayer, FileUriLayer},
        },
    },
    js::{
        JsRuntime,
        pac::{FetchPacScript, PacResolver, PacScriptCacheLayer, SystemPacProxy},
    },
    layer::TimeoutLayer,
    net::client::{SystemProxyLayer, SystemProxyPacService},
    telemetry::tracing,
    telemetry::tracing::subscriber::filter::{Directive, LevelFilter},
};

pub(crate) const JS_CACHE_DIR: &str = ".rama/wasm";
const SYSTEM_PAC_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

mod eval;
mod generate;
mod source;

pub(super) fn system_proxy_layer() -> SystemProxyLayer<impl SystemProxyPacService + Clone> {
    // PAC fetches are bounded and deliberately direct: consulting the
    // unresolved system proxy while fetching its own policy can recurse.
    let fetch_client = (
        TimeoutLayer::new(SYSTEM_PAC_FETCH_TIMEOUT),
        FileUriLayer::new(),
        DataUriLayer::new(),
        FollowRedirectLayer::with_policy(Limited::new(10)),
    )
        .into_layer(EasyHttpWebClient::default());
    let provider = PacScriptCacheLayer::new().into_layer(FetchPacScript::new(fetch_client));
    let resolver = home_dir().map_or_else(PacResolver::builder, |home| {
        PacResolver::builder().with_javascript_disk_cache(home, JS_CACHE_DIR)
    });
    SystemProxyLayer::new()
        .with_pac_service(SystemPacProxy::new(provider).with_resolver_builder(resolver))
}

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
            let default_level = if command.verbose {
                LevelFilter::DEBUG
            } else {
                LevelFilter::WARN
            };
            let cache_worker_override = (!command.verbose
                && std::env::var_os("RUST_LOG").is_none())
            .then(|| {
                "wasmtime_internal_cache::worker=error"
                    .parse::<Directive>()
                    .context("parse static javascript cache log filter")
            })
            .transpose()?;
            crate::trace::init_tracing_with_overrides(default_level, cache_worker_override)?;
            eval::run(config, command.verbose).await
        }
        PacSubcommand::Generate(config) => generate::run(config),
    }
}

pub(super) fn warm_up_javascript_engine() -> Result<(), BoxError> {
    let Some(home) = home_dir() else {
        tracing::debug!("home directory unavailable; javascript disk cache disabled");
        return JsRuntime::warm_up().context("warm up javascript engine");
    };
    let cache_dir = js_cache_dir(&home);
    match JsRuntime::warm_up_with_disk_cache(&home, JS_CACHE_DIR) {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::debug!(
                ?error,
                cache_dir = %cache_dir.display(),
                "javascript disk cache unavailable; continuing without it"
            );
            JsRuntime::warm_up().context("warm up javascript engine")
        }
    }
}

fn js_cache_dir(home: &Path) -> PathBuf {
    home.join(JS_CACHE_DIR)
}
