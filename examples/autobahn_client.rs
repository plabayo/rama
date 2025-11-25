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
    error::{BoxError, ErrorContext},
    extensions::Extensions,
    futures::{SinkExt, StreamExt},
    http::{
        client::EasyHttpWebClient,
        ws::{
            ProtocolError, handshake::client::HttpClientWebSocketExt,
            protocol::PerMessageDeflateConfig,
        },
    },
    telemetry::tracing::{
        self, error, info,
        subscriber::{
            EnvFilter, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
        },
    },
};

use serde::Deserialize;

const AGENT: &str = "Rama";

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
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
        .handshake(Extensions::default())
        .await
        .context("get case count")?;

    let msg = socket.next().await.expect("Can't fetch case count")?;
    socket.close(None).await.context("close ws socket")?;
    Ok(msg
        .to_text()?
        .parse::<u32>()
        .expect("Can't parse case count"))
}

#[derive(Debug, Deserialize)]
struct CaseInfo {
    description: String,
}

async fn get_case_info(case: u32) -> Result<CaseInfo, BoxError> {
    let client = EasyHttpWebClient::default();
    let mut socket = client
        .websocket(format!("ws://localhost:9001/getCaseInfo?case={case}"))
        .handshake(Extensions::default())
        .await
        .context("get case count")?;

    let msg = socket.next().await.expect("Can't fetch case count")?;
    socket.close(None).await.context("close ws socket")?;
    Ok(serde_json::from_str(msg.to_text()?).expect("Can't parse case count"))
}

async fn update_reports() -> Result<(), BoxError> {
    let client = EasyHttpWebClient::default();

    let mut socket = client
        .websocket(format!("ws://localhost:9001/updateReports?agent={AGENT}"))
        .handshake(Extensions::default())
        .await
        .context("update reports")?;

    socket.close(None).await?;
    Ok(())
}

async fn run_test(case: u32) -> Result<(), BoxError> {
    info!("Running test case {}", case);

    let case_info = get_case_info(case).await?;
    info!("case info: {case_info:?}");

    let client_info_vec = parse_client_offers_no_regex(&case_info.description);
    let mut configs = offers_to_configs(&client_info_vec);

    if configs.is_empty()
        && case_info
            .description
            .contains("Use default permessage-deflate offer")
    {
        configs.push(PerMessageDeflateConfig::default());
    }

    let client = EasyHttpWebClient::default();

    let mut ws_builder = client.websocket(format!(
        "ws://localhost:9001/runCase?case={case}&agent={AGENT}"
    ));

    for config in configs {
        info!("set config to builder: {config:?}");
        let _ = ws_builder.set_per_message_deflate_with_config(config);
    }

    let mut socket = ws_builder
        .handshake(Extensions::default())
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

#[derive(Debug, Clone, Copy)]
struct ClientOffer {
    request_no_context_takeover: bool,
    request_max_window_bits: u8, // 0 means token without a value
}

fn parse_client_offers_no_regex(line: &str) -> Vec<ClientOffer> {
    // Extract the list inside [ ... ]
    let start = match line.find('[') {
        Some(i) => i + 1,
        None => return Vec::new(),
    };
    let Some(end) = line.rfind(']') else {
        return Vec::new();
    };
    let list = &line[start..end];

    let mut i = 0usize;
    let b = list.as_bytes();
    let len = b.len();
    let mut out = Vec::new();

    fn skip_ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }

    while i < len {
        skip_ws(b, &mut i);
        if i >= len {
            break;
        }
        if b[i] != b'(' {
            // skip until next tuple
            i += 1;
            continue;
        }
        i += 1; // past '('
        skip_ws(b, &mut i);

        // parse True or False until comma
        let bool_start = i;
        while i < len && b[i] != b',' && b[i] != b')' {
            i += 1;
        }
        let bool_tok = list[bool_start..i].trim();
        let noc = matches!(bool_tok, "True" | "true");

        // expect comma then parse number until ')'
        if i < len && b[i] == b',' {
            i += 1;
        }
        skip_ws(b, &mut i);

        let num_start = i;
        while i < len && b[i] != b')' {
            i += 1;
        }
        let num_tok = list[num_start..i].trim();
        let bits = num_tok.parse::<u8>().unwrap_or(0);

        // consume ')'
        if i < len && b[i] == b')' {
            i += 1;
        }

        out.push(ClientOffer {
            request_no_context_takeover: noc,
            request_max_window_bits: bits,
        });

        // optional trailing comma and spaces before next tuple
        skip_ws(b, &mut i);
        if i < len && b[i] == b',' {
            i += 1;
        }
    }

    out
}

fn offers_to_configs(offers: &[ClientOffer]) -> Vec<PerMessageDeflateConfig> {
    offers
        .iter()
        .map(|o| PerMessageDeflateConfig {
            server_no_context_takeover: true,
            server_max_window_bits: Some(15),
            client_no_context_takeover: o.request_no_context_takeover,
            // Some(0) means advertise client_max_window_bits without a value
            client_max_window_bits: Some(o.request_max_window_bits),
        })
        .collect()
}
