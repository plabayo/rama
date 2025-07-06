use rama_core::{
    Context,
    error::{BoxError, ErrorContext},
    futures::{SinkExt, StreamExt},
    telemetry::tracing::{error, info},
};
use rama_http_backend::client::EasyHttpWebClient;
use rama_ws::{ProtocolError, handshake::client::HttpClientWebSocketExt};
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

const AGENT: &str = "Rama";

async fn get_case_count() -> Result<u32, BoxError> {
    let client = EasyHttpWebClient::default();
    let mut socket = client
        .websocket("ws://localhost:9001/getCaseCount")
        .handshake(Context::default())
        .await
        .context("get case count")?;

    let msg = socket.next().await.expect("Can't fetch case count")?;
    socket.close(None).await.context("close ws socket")?;
    Ok(msg
        .to_text()?
        .parse::<u32>()
        .expect("Can't parse case count"))
}

async fn update_reports() -> Result<(), BoxError> {
    let client = EasyHttpWebClient::default();

    let mut socket = client
        .websocket(format!("ws://localhost:9001/updateReports?agent={AGENT}"))
        .handshake(Context::default())
        .await
        .context("update reports")?;

    socket.close(None).await?;
    Ok(())
}

async fn run_test(case: u32) -> Result<(), BoxError> {
    info!("Running test case {}", case);

    let client = EasyHttpWebClient::default();

    let mut socket = client
        .websocket(format!(
            "ws://localhost:9001/runCase?case={case}&agent={AGENT}"
        ))
        .handshake(Context::default())
        .await
        .context("get case socket")?;

    while let Some(msg) = socket.next().await {
        let msg = msg?;
        if msg.is_text() || msg.is_binary() {
            socket.send(msg).await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let total = get_case_count().await.expect("Error getting case count");

    for case in 1..=total {
        if let Err(err) = run_test(case).await {
            if err.downcast_ref::<ProtocolError>().is_none() {
                error!("Testcase failed: {err}")
            }
        }
    }

    update_reports().await.expect("Error updating reports");
}
