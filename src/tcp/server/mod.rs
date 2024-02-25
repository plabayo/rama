//! TCP server module for Rama.
//!
//! The TCP server is used to create a [`TcpListener`] and accept incoming connections.
//!
//! # Example
//!
//! ```no_run
//! use rama::tcp::server::TcpListener;
//! use tokio::{io::AsyncWriteExt, net::TcpStream};
//!
//! const SRC: &str = include_str!("../../../examples/tcp_listener_hello.rs");
//!
//! #[tokio::main]
//! async fn main() {
//!     TcpListener::bind("127.0.0.1:9000")
//!         .await
//!         .expect("bind TCP Listener")
//!         .serve_fn(|mut stream: TcpStream| async move {
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
//!         })
//!         .await;
//! }
//! ```

use std::net::SocketAddr;

mod listener;
pub use listener::{TcpListener, TcpListenerBuilder};

#[derive(Debug, Clone)]
/// TCP socket information of an incoming Tcp connection.
pub struct TcpSocketInfo {
    local_addr: Option<SocketAddr>,
    peer_addr: SocketAddr,
}

impl TcpSocketInfo {
    /// Create a new `TcpSocketInfo`.
    pub(crate) fn new(local_addr: Option<SocketAddr>, peer_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    /// Get the local address of the socket.
    pub fn local_addr(&self) -> Option<&SocketAddr> {
        self.local_addr.as_ref()
    }

    /// Get the peer address of the socket.
    pub fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }
}
