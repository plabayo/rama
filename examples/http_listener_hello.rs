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

use std::net::{IpAddr, Ipv4Addr};

use rama::{
    http::{response::Json, server::HttpServer, Request},
    rt::Executor,
    service::service_fn,
};
use rama_net::address::SocketAddress;
use serde_json::json;

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            // The below string type will also work
            // "127.0.0.1:62007",
            SocketAddress::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 62007),
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
