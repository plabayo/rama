//! An example to showcase how to build directly a HTTP server that listens on `127.0.0.1:62007`
//! and returns a JSON response with the method and path of the request.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_listener_hello --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62007`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62007
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a JSON body with the method and path of the request.

use rama::{
    http::service::web::response::Json,
    http::{Request, server::HttpServer},
    net::address::SocketAddress,
    rt::Executor,
    service::service_fn,
};

use serde_json::json;

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            // The below string type will also work
            // "127.0.0.1:62007",
            SocketAddress::local_ipv4(62007),
            service_fn(async |req: Request| {
                Ok(Json(json!({
                    "method": req.method().as_str(),
                    "path": req.uri().path(),
                })))
            }),
        )
        .await
        .unwrap();
}
