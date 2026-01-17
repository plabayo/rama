//! This example demonstrates how to serve embedded files from the file system over HTTP.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_service_include_dir --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62037`.
//! You can use your browser to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62037
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and the content of the `index.html` file.

use rama::{
    Layer,
    http::{
        server::HttpServer,
        service::{fs::DirectoryServeMode, web::WebService},
    },
    layer::TraceErrLayer,
    rt::Executor,
    tcp::server::TcpListener,
    utils::include_dir::{Dir, include_dir},
};

const ASSETS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/test-files");

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:62037", Executor::default())
        .await
        .expect("bind TCP Listener");

    let http_fs_server =
        HttpServer::default().service(WebService::default().with_dir_embed_with_serve_mode(
            "",
            ASSETS,
            DirectoryServeMode::AppendIndexHtml,
        ));

    // Serve the HTTP server over TCP,
    // ...once running you can go in browser for example to:
    println!("open: http://127.0.0.1:62037");
    listener
        .serve(TraceErrLayer::new().into_layer(http_fs_server))
        .await;
}
