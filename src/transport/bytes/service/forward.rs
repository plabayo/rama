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
    respect_shutdown: bool,
    shutdown_delay: Option<std::time::Duration>,
}

impl<D> ForwardService<D> {
    /// Creates a new [`ForwardService`],
    pub fn new(destination: D) -> Self {
        Self {
            destination: Box::pin(destination),
            respect_shutdown: false,
            shutdown_delay: None,
        }
    }

    /// Enable the option that this service will stop its work
    /// as soon as the graceful shutdown is requested, optionally with
    /// a a delay to give the actual work some time to finish.
    pub fn respect_shutdown(mut self, delay: Option<std::time::Duration>) -> Self {
        self.respect_shutdown = true;
        self.shutdown_delay = delay;
        self
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
        if self.respect_shutdown {
            if let Some(delay) = self.shutdown_delay {
                let wait_for_shutdown = async {
                    token.shutdown().await;
                    tokio::time::sleep(delay).await;
                };
                tokio::select! {
                    _ = wait_for_shutdown => Err(Error::new(ErrorKind::Interrupted, "forward: graceful shutdown requested and delay expired")),
                    res = tokio::io::copy_bidirectional(&mut source, &mut self.destination) => res,
                }
            } else {
                tokio::select! {
                    _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "forward: graceful shutdown requested")),
                    res = tokio::io::copy_bidirectional(&mut source, &mut self.destination) => res,
                }
            }
        } else {
            tokio::io::copy_bidirectional(&mut source, &mut self.destination).await
        }
    }
}
