use std::net::SocketAddr;

mod listener;
pub use listener::{TcpListener, TcpServeError, TcpServeResult};

#[derive(Debug, Clone)]
pub struct TcpSocketInfo {
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: SocketAddr,
}
