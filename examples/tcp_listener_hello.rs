//! A Hello World example of a TCP listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tcp_listener_hello
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62500`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62500
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a body with the source code of this example.

use std::convert::Infallible;

use rama::{
    net::stream::{Socket, Stream},
    tcp::server::TcpListener,
};
use tokio::io::AsyncWriteExt;

const SRC: &str = include_str!("./tcp_listener_hello.rs");
const ADDR: &str = "127.0.0.1:62500";

#[tokio::main]
async fn main() {
    println!("Listening on: {ADDR}");
    TcpListener::bind(ADDR)
        .await
        .expect("bind TCP Listener")
        .serve_fn(handle)
        .await;
}

async fn handle(mut stream: impl Socket + Stream + Unpin) -> Result<(), Infallible> {
    println!(
        "Incoming connection from: {}",
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "???".to_owned())
    );

    let resp = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        format!("Content-Length: {}", SRC.len()).as_str(),
        "",
        SRC,
        "",
    ]
    .join("\r\n");

    stream
        .write_all(resp.as_bytes())
        .await
        .expect("write to stream");

    Ok::<_, std::convert::Infallible>(())
}
