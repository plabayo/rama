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
//! The server will start and listen on `:62037`. You can use your browser to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62037/test-files/index.html
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and the content of the `index.html` file.

use http::StatusCode;
use rama::{
    Layer,
    http::server::HttpServer,
    http::service::web::WebService,
    layer::TraceErrLayer,
    rt::Executor,
    tcp::server::TcpListener,
    utils::include_dir::{Dir, include_dir},
};
use rama_http::service::web::{extract::Path, response::IntoResponse};
use serde::Deserialize;

// TODO: ensure we do not need to import `include_dir` module ourselves
const ASSETS: Dir<'static> = include_dir!("../test-files");

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    let listener = TcpListener::bind("127.0.0.1:62037")
        .await
        .expect("bind TCP Listener");

    // TODO: use ServeDir::new_embedded once available :)
    // let http_fs_server = HttpServer::auto(exec).service(ServeDir::new_embedded(ASSETS));

    // TODO: remove once no longer needed
    #[derive(Debug, Deserialize)]
    struct Params {
        path: String,
    }
    let http_fs_server = HttpServer::auto(exec).service(WebService::default().get(
        "/test-files/{path}",
        async |Path(Params { path }): Path<Params>| match ASSETS.get_file(path) {
            Some(entry) => String::from_utf8_lossy(entry.contents()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    ));

    // Serve the HTTP server over TCP,
    // ...once running you can go in browser for example to:
    println!("open: http://127.0.0.1:62037/test-files/index.html");
    listener
        .serve(TraceErrLayer::new().into_layer(http_fs_server))
        .await;
}
