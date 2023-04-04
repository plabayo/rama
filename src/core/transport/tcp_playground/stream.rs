use tokio::net::TcpStream;

use crate::core::transport::shutdown::Shutdown;

pub struct Stream {
    pub tcp: TcpStream,
    pub shutdown: Shutdown,
}

impl Stream {
    pub fn new(tcp: TcpStream, shutdown: Shutdown) -> Self {
        Self { tcp, shutdown }
    }
}
