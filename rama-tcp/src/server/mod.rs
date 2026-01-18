//! TCP server module for Rama.
//!
//! The TCP server is used to create a [`TcpListener`] and accept incoming connections.
//!
//! # Example
//!
//! ```no_run
//! use rama_tcp::{TcpStream, server::TcpListener};
//! use rama_core::service::service_fn;
//! use rama_core::rt::Executor;
//! use tokio::io::AsyncWriteExt;
//!
//! const SRC: &str = include_str!("../../../examples/tcp_listener_hello.rs");
//!
//! #[tokio::main]
//! async fn main() {
//!     TcpListener::bind("127.0.0.1:9000", Executor::default())
//!         .await
//!         .expect("bind TCP Listener")
//!         .serve(service_fn(async |mut stream: TcpStream| {
//!             let resp = [
//!                 "HTTP/1.1 200 OK",
//!                 "Content-Type: text/plain",
//!                 format!("Content-Length: {}", SRC.len()).as_str(),
//!                 "",
//!                 SRC,
//!                 "",
//!             ]
//!             .join("\r\n");
//!
//!             stream
//!                 .write_all(resp.as_bytes())
//!                 .await
//!                 .expect("write to stream");
//!
//!             Ok::<_, std::convert::Infallible>(())
//!         }))
//!         .await;
//! }
//! ```

mod listener;
#[doc(inline)]
pub use listener::{TcpListener, TcpListenerBuilder};
