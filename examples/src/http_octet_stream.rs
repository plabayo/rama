//! A simple example demonstrating `OctetStream` responses for binary data.
//!
//! This example will create a server that listens on `127.0.0.1:12056`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_octet_stream --features=http-full
//! ```
//!
//! # Test the endpoints
//!
//! ```sh
//! # Simple binary data
//! curl http://127.0.0.1:12056/data -o output.bin
//!
//! # Download with filename
//! curl -O -J http://127.0.0.1:12056/download
//! ```

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::http::layer::{error_handling::ErrorHandlerLayer, trace::TraceLayer};
use rama::http::service::web::Router;
use rama::http::service::web::response::{IntoResponse, OctetStream};
use rama::stream::io::ReaderStream;
use rama::{Layer, http::server::HttpServer, layer::ArcLayer};

#[tokio::main]
async fn main() {
    HttpServer::default()
        .listen(
            "127.0.0.1:12056",
            (
                TraceLayer::new_for_http(),
                ArcLayer::new(),
                ErrorHandlerLayer::new(),
            )
                .into_layer(
                    Router::new()
                        .with_get("/data", serve_binary_data)
                        .with_get("/download", serve_download),
                ),
        )
        .await
        .expect("failed to run service");
}

/// Example 1: Simple binary response
async fn serve_binary_data() -> impl IntoResponse {
    let data = b"Hello";
    let cursor = std::io::Cursor::new(data);
    let stream = ReaderStream::new(cursor);
    OctetStream::new(stream)
}

/// Example 2: Binary download with Content-Disposition
async fn serve_download() -> impl IntoResponse {
    let data = b"Binary file content";
    let cursor = std::io::Cursor::new(data);
    let stream = ReaderStream::new(cursor);
    OctetStream::new(stream).with_file_name("file.bin".to_owned())
}
