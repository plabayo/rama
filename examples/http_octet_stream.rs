//! A simple example demonstrating `OctetStream` responses for binary data.
//!
//! This example will create a server that listens on `127.0.0.1:62003`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_octet_stream --features=http-full
//! ```
//!
//! # Test the endpoints
//!
//! ```sh
//! # Simple binary data
//! curl http://127.0.0.1:62003/data -o output.bin
//!
//! # Download with filename
//! curl -O -J http://127.0.0.1:62003/download
//! ```

use rama::http::layer::trace::TraceLayer;
use rama::http::service::web::WebService;
use rama::http::service::web::response::{IntoResponse, OctetStream};
use rama::rt::Executor;
use rama::stream::io::ReaderStream;
use rama::{Layer, http::server::HttpServer};

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:62003",
            TraceLayer::new_for_http().layer(
                WebService::default()
                    .get("/data", serve_binary_data)
                    .get("/download", serve_download),
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
