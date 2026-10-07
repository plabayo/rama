#![allow(clippy::print_stdout)]

use clap::Args;
use rama::{
    dns::client::DnsConnector,
    error::{BoxError, ErrorContext},
    net::{
        address::HostWithPort,
        client::{ConnectRequest, ConnectorService, EstablishedClientConnection},
        stream::Socket,
    },
    tcp::{TcpStream, client::service::TcpConnector},
    telemetry::tracing,
};

#[derive(Args, Debug, Clone)]
/// rama tcp probe command
pub struct CliCommandTcp {
    /// The authority to connect to
    ///
    /// e.g. "127.0.0.1:443" or "example.com:8443"
    authority: HostWithPort,
}

/// Run the tcp command
pub async fn run(cfg: CliCommandTcp) -> Result<(), BoxError> {
    tracing::info!(
        server.address = %cfg.authority.host,
        server.port = cfg.authority.port,
        "connecting to server",
    );

    let EstablishedClientConnection { conn, .. }: EstablishedClientConnection<TcpStream, _> =
        DnsConnector::new(TcpConnector::new())
            .connect(ConnectRequest::new(cfg.authority))
            .await
            .context("tcp connect")?;

    let addr = conn.peer_addr().context("get connected peer address")?;

    // The probe's result, as `probe tls` prints its own: no log level hides it.
    println!("connected to: {addr}");

    Ok(())
}
