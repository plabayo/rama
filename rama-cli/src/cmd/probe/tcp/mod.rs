#![allow(clippy::print_stdout)]

use rama::{
    error::{BoxError, ErrorContext},
    extensions::Extensions,
    net::address::Authority,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
};

use clap::Args;

#[derive(Args, Debug, Clone)]
/// rama tcp probe command
pub struct CliCommandTcp {
    /// The authority to connect to
    ///
    /// e.g. "127.0.0.1:443" or "example.com:8443"
    authority: Authority,
}

/// Run the tcp command
pub async fn run(cfg: CliCommandTcp) -> Result<(), BoxError> {
    tracing::info!(
        server.address = %cfg.authority.host(),
        server.port = %cfg.authority.port(),
        "connecting to server",
    );

    let (_, addr) = default_tcp_connect(&Extensions::default(), cfg.authority)
        .await
        .context("tcp connect")?;

    tracing::info!("connected to: {addr}");

    Ok(())
}
