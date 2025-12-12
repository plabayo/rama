use rama::{
    error::{BoxError, OpaqueError},
    graceful,
    telemetry::tracing::{self, subscriber::filter::LevelFilter},
};

use clap::{Args, Subcommand};
use std::time::Duration;

pub mod discard;
pub mod echo;
pub mod fp;
pub mod fs;
pub mod httptest;
pub mod ip;
pub mod proxy;
pub mod stunnel;

pub async fn run(cfg: ServeCommand) -> Result<(), BoxError> {
    crate::trace::init_tracing(if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    })?;

    let graceful_timeout = (cfg.graceful > 0.).then(|| Duration::from_secs_f64(cfg.graceful));

    let (etx, mut erx) = tokio::sync::mpsc::channel::<OpaqueError>(1);
    let graceful = graceful::Shutdown::new(async move {
        let mut signal = Box::pin(graceful::default_signal());
        tokio::select! {
            _ = signal.as_mut() => {
                tracing::debug!("default signal triggered: init graceful shutdown");
            }
            err = erx.recv() => {
                if let Some(err) = err {
                    tracing::error!("fatal err received: {err}; abort");
                } else {
                    signal.await;
                    tracing::debug!("default signal triggered: init graceful shutdown");
                }
            }
        }
    });

    match cfg.commands {
        ServeSubcommand::Discard(cfg) => discard::run(graceful.guard(), cfg).await?,
        ServeSubcommand::Echo(cfg) => echo::run(graceful.guard(), etx, cfg).await?,
        ServeSubcommand::Fp(cfg) => fp::run(graceful.guard(), cfg).await?,
        ServeSubcommand::HttpTest(cfg) => httptest::run(graceful.guard(), cfg).await?,
        ServeSubcommand::Fs(cfg) => fs::run(graceful.guard(), cfg).await?,
        ServeSubcommand::Ip(cfg) => ip::run(graceful.guard(), cfg).await?,
        ServeSubcommand::Proxy(cfg) => proxy::run(graceful.guard(), cfg).await?,
        ServeSubcommand::Stunnel(cfg) => stunnel::run(graceful.guard(), cfg).await?,
    }

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}

#[derive(Debug, Args)]
/// run server(s) with rama
pub struct ServeCommand {
    #[command(subcommand)]
    // rama serve subcommands
    pub commands: ServeSubcommand,

    #[arg(long, global = true, default_value_t = 1.)]
    /// the graceful shutdown timeout in seconds (<= 0.0 = no timeout)
    pub graceful: f64,

    /// enable debug logs for tracing (possible via RUST_LOG env as well)
    #[arg(long, short = 'v', global = true, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum ServeSubcommand {
    Discard(discard::CliCommandDiscard),
    Echo(echo::CliCommandEcho),
    Fp(fp::CliCommandFingerprint),
    HttpTest(httptest::CliCommandHttpTest),
    Fs(fs::CliCommandFs),
    Ip(ip::CliCommandIp),
    Proxy(proxy::CliCommandProxy),
    Stunnel(stunnel::StunnelCommand),
}
