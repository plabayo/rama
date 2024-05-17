//! This example demonstrates how to serve files from the file system over HTTP.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_service_fs
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62009`. You can use your browser to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62009/test-files/index.html
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and the content of the `index.html` file.

use rama::{
    http::{server::HttpServer, service::fs::ServeDir},
    rt::Executor,
    service::ServiceBuilder,
    tcp::server::TcpListener,
};

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    let listener = TcpListener::bind("127.0.0.1:62009")
        .await
        .expect("bind TCP Listener");

    // This will serve files in the current working dir
    let cwd = std::env::current_dir().expect("current working dir");
    println!("Serving files from: {:?}", cwd);
    let http_fs_server = HttpServer::auto(exec).service(ServeDir::new(cwd));

    // Serve the HTTP server over TCP,
    // ...once running you can go in browser for example to:
    println!("open: http://127.0.0.1:62009/test-files/index.html");
    listener
        .serve(ServiceBuilder::new().trace_err().service(http_fs_server))
        .await;
}
