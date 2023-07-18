use tokio::{net::TcpStream, pin};

use crate::transport::bytes::ByteStream;
use crate::{service::Service, transport::connection::Connection};

#[derive(Debug)]
pub struct Forwarder {
    target: TcpStream,
}

impl<B, T> Service<Connection<B, T>> for Forwarder
where
    B: ByteStream,
{
    type Error = std::io::Error;
    type Response = ();

    async fn call(&mut self, conn: Connection<B, T>) -> Result<Self::Response, Self::Error> {
        let (socket, token, _) = conn.into_parts();
        pin!(socket);

        tokio::select! {
            _ = token.shutdown() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "graceful shutdown requested")),
            res = tokio::io::copy(&mut socket, &mut self.target) => res.map(|_| ()),
        }
    }
}
