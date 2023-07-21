use std::{
    io::{Error, ErrorKind},
    pin::Pin,
};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

/// Crates an async service which forwards the incoming connection bytes to the given destination,
/// and forwards the response back from the destination to the incoming connection.
#[derive(Debug)]
pub struct ForwardService<D> {
    destination: Pin<Box<D>>,
}

impl<D> ForwardService<D> {
    pub fn new(destination: D) -> Self {
        ForwardService {
            destination: Box::pin(destination),
        }
    }
}

impl<T, S, D> Service<Connection<S, T>> for ForwardService<D>
where
    S: ByteStream,
    D: ByteStream,
{
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&mut self, conn: Connection<S, T>) -> Result<Self::Response, Self::Error> {
        let (source, token, _) = conn.into_parts();
        tokio::pin!(source);
        tokio::select! {
            _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "forward: graceful shutdown requested")),
            res = tokio::io::copy_bidirectional(&mut source, &mut self.destination) => res,
        }
    }
}
