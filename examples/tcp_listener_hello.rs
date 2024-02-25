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
//! The server will start and listen on `:9000`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:9000
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a body with the source code of this example.

use rama::tcp::server::TcpListener;
use tokio::{io::AsyncWriteExt, net::TcpStream};

const SRC: &str = include_str!("./tcp_listener_hello.rs");

#[tokio::main]
async fn main() {
    TcpListener::bind("127.0.0.1:9000")
        .await
        .expect("bind TCP Listener")
        .serve_fn(|mut stream: TcpStream| async move {
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
        })
        .await;
}
