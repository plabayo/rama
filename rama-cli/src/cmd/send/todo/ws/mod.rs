//! rama ws client

// e.g. can be used with <wss://echo.websocket.org>

use std::time::Duration;

use clap::Args;
use rama::{
    error::{BoxError, ErrorContext},
    graceful::{self, Shutdown},
};
use tokio::sync::oneshot;

use crate::utils::http::HttpVersion;

mod client;
mod log;
mod tui;

#[derive(Args, Debug, Clone)]
/// rama ws client
pub struct CliCommandWs {
    #[arg(short = 'F', long)]
    /// follow Location redirects
    follow: bool,

    #[arg(long, default_value_t = 30)]
    /// the maximum number of redirects to follow
    max_redirects: usize,

    #[arg(long, short = 'P')]
    /// upstream proxy to use (can also be specified using PROXY env variable)
    proxy: Option<String>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<String>,

    #[arg(long, short = 'a')]
    /// client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    auth: Option<String>,

    #[arg(long, short = 'A', default_value = "basic")]
    /// the type of authentication to use (basic, bearer)
    auth_type: String,

    #[arg(short = 'k', long)]
    /// skip Tls certificate verification
    insecure: bool,

    #[arg(long)]
    /// the desired tls version to use (automatically defined by default, choices are: 1.2, 1.3)
    tls: Option<String>,

    #[arg(long)]
    /// the client tls key file path to use
    cert_key: Option<String>,

    #[arg(long, short = 't', default_value = "0")]
    /// the timeout in seconds for each connection (0 = default timeout of 180s)
    timeout: u64,

    #[arg(long, short = 'E')]
    /// emulate user agent
    emulate: bool,

    #[arg(long, short = 'p', value_delimiter = ',')]
    /// WebSocket sub protocols to use
    protocols: Option<Vec<String>>,

    /// http version to use for the WebSocket handshake
    #[arg(long, default_value = "http/1.1")]
    http_version: HttpVersion,

    #[arg()]
    /// Uri to establish a WebSocket connection with
    uri: String,
}

/// Run the HTTP client command.
pub async fn run(cfg: CliCommandWs) -> Result<(), BoxError> {
    eprintln!("connecting to {}...", cfg.uri);

    let app = tui::App::new(cfg).await.context("create tui app")?;

    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                let _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        let _ = tx_final.send(result);
                    }
                    Err(_) => {
                        let _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });

    shutdown.spawn_task_fn(async move |guard| {
        let mut app = app;
        let result = app.run(guard).await.map_err(|err| err.into_boxed());
        let _ = tx.send(result);
    });

    let _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}
