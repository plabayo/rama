//! An example to showcase how to build directly a HTTP server that listens on `127.0.0.1:8080`
//! and returns a JSON response with the method and path of the request.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_listener_hello
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a JSON body with the method and path of the request.

use rama::{
    http::{response::Json, server::HttpServer, Request},
    rt::Executor,
    service::service_fn,
};
use serde_json::json;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let port = match args.get(1){
        Some(port) => port,
        None => "8080",
    };
    let addr = format!("127.0.0.1:{}", port);

    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            addr ,
            service_fn(|req: Request| async move {
                Ok(Json(json!({
                    "method": req.method().as_str(),
                    "path": req.uri().path(),
                })))
            }),
        )
        .await
        .unwrap();
}
