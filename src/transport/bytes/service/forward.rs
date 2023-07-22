use std::{
    io::{Error, ErrorKind},
    pin::Pin,
};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

/// Async service which forwards the incoming connection bytes to the given destination,
/// and forwards the response back from the destination to the incoming connection.
///
/// # Example
///
/// ```rust
/// use tower_async::Service;
/// use rama::transport::bytes::service::ForwardService;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let destination = tokio_test::io::Builder::new().write(b"hello world").read(b"hello world").build();
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// # let conn = rama::transport::connection::Connection::new(stream, rama::transport::graceful::Token::pending(), ());
/// let mut service = ForwardService::new(destination)
///     .respect_shutdown(Some(std::time::Duration::from_secs(5)));
///
/// let (bytes_copied_to, bytes_copied_from) = service.call(conn).await?;
/// # assert_eq!(bytes_copied_to, 11);
/// # assert_eq!(bytes_copied_from, 11);
/// # Ok(())
/// # }
/// ```
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
