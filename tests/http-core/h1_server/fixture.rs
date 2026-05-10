use rama::ServiceInput;
use rama::bytes::Bytes;
use rama::futures::stream;
use rama::http::body::util::StreamBody;
use rama::http::core::body::Frame;
use rama::http::core::service::RamaHttpService;
use rama::http::{Request, Response, StatusCode};
use rama::service::service_fn;
use rama::telemetry::tracing::{error, info};
use rama_http_core::server::conn::http1;
use std::convert::Infallible;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::timeout;

pub(crate) struct TestConfig {
    pub total_chunks: usize,
    pub chunk_size: usize,
    pub chunk_timeout: Duration,
}

impl TestConfig {
    pub(crate) fn with_timeout(chunk_timeout: Duration) -> Self {
        Self {
            total_chunks: 16,
            chunk_size: 64 * 1024,
            chunk_timeout,
        }
    }
}

pub(crate) struct Client {
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
}

pub(crate) async fn run<S>(server: S, mut client: Client, config: TestConfig)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut http_builder = http1::Builder::new();
    http_builder
        .try_set_max_buf_size(config.chunk_size)
        .unwrap();

    let total_chunks = config.total_chunks;
    let chunk_size = config.chunk_size;

    let service = service_fn(move |_req: Request| {
        let total_chunks = total_chunks;
        let chunk_size = chunk_size;
        async move {
            info!(
                "Creating payload of {} chunks of {} KiB each ({} MiB total)...",
                total_chunks,
                chunk_size / 1024,
                total_chunks * chunk_size / (1024 * 1024)
            );
            let data = vec![Bytes::from(vec![0; chunk_size]); total_chunks];
            let stream = stream::iter(
                data.into_iter()
                    .map(|b| Ok::<_, Infallible>(Frame::data(b))),
            );
            let body = StreamBody::new(stream);
            info!("Server: Sending data response...");
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/octet-stream")
                    .header("content-length", (total_chunks * chunk_size).to_string())
                    .body(body)
                    .unwrap(),
            )
        }
    });

    let server_task = tokio::spawn(async move {
        let conn =
            http_builder.serve_connection(ServiceInput::new(server), RamaHttpService::new(service));
        let conn_result = conn.await;
        if let Err(e) = &conn_result {
            error!("Server connection error: {}", e);
        }
        conn_result
    });

    let get_request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    client
        .tx
        .send(get_request.as_bytes().to_vec())
        .map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "Failed to send request: {e}",
            )))
        })
        .unwrap();

    info!("Client is reading response...");
    let mut bytes_received = 0;
    let mut all_data = Vec::new();
    loop {
        match timeout(config.chunk_timeout, client.rx.recv()).await {
            Ok(Some(chunk)) => {
                bytes_received += chunk.len();
                all_data.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                panic!(
                    "Chunk timeout: chunk took longer than {:?}",
                    config.chunk_timeout
                );
            }
        }
    }

    // Clean up
    let result = server_task.await.unwrap();
    result.unwrap();

    // Parse HTTP response to find body start
    // HTTP response format: "HTTP/1.1 200 OK\r\n...headers...\r\n\r\n<body>"
    let body_start = all_data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(0);

    let body_bytes = bytes_received - body_start;
    assert_eq!(
        body_bytes,
        config.total_chunks * config.chunk_size,
        "Expected {} body bytes, got {} (total received: {}, headers: {})",
        config.total_chunks * config.chunk_size,
        body_bytes,
        bytes_received,
        body_start
    );
    info!(bytes_received, body_bytes, "Client done receiving bytes");
}
