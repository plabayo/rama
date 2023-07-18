use crate::transport::bytes::ByteStream;
use crate::{service::Service, transport::connection::Connection};

#[derive(Debug)]
pub struct Forwarder<B> {
    target: B,
}

impl<B1, B2, T> Service<Connection<B1, T>> for Forwarder<B2>
where
    B1: ByteStream,
    B2: ByteStream + Unpin,
{
    type Error = std::io::Error;
    type Response = ();

    async fn call(&mut self, conn: Connection<B1, T>) -> Result<Self::Response, Self::Error> {
        let (socket, token, _) = conn.into_parts();
        tokio::pin!(socket);

        tokio::select! {
            _ = token.shutdown() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "graceful shutdown requested")),
            res = tokio::io::copy(&mut socket, &mut self.target) => res.map(|_| ()),
        }
    }
}
