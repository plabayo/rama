//! An example demonstrating how to run the Autobahn WebSocket Test Suite using Rama.
//!
//! This connects to a locally running instance of the [Autobahn TestSuite](https://github.com/crossbario/autobahn-testsuite)
//! via WebSocket to run and report test cases for validating WebSocket protocol conformance.
//! # Prerequisites
//! ## Using provided script
//! - Run script `rama-ws/autobahn/client.sh`
//!
//! # Manually
//!
//! - Run the Autobahn WebSocket TestSuite server locally :
//!   ```sh
//!   docker run -it --rm -p 9001:9001 crossbario/autobahn-testsuite
//!   ```
//! - Make sure the server is listening on `ws://localhost:9001`
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example autobahn_test_client --features=http-full,ws
//! ```
//!
//! # Expected Output
//!
//! The example will:
//! - Fetch the number of test cases
//! - Run each case by echoing back text or binary WebSocket frames
//! - Skip logging expected protocol errors
//! - Submit the final report under the agent name "Rama"
//!
//! You’ll see output for each test case and potential errors (if any).
use rama::{
    Context,
    error::{BoxError, ErrorContext},
    futures::{SinkExt, StreamExt},
    http::{
        client::EasyHttpWebClient,
        ws::{ProtocolError, handshake::client::HttpClientWebSocketExt},
    },
    telemetry::tracing::{error, info},
};
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

const AGENT: &str = "Rama";

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
        if let Err(err) = run_test(case).await
            && err.downcast_ref::<ProtocolError>().is_none()
        {
            error!("Testcase failed: {err}")
        }
    }

    update_reports().await.expect("Error updating reports");
}

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
