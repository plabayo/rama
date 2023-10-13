use std::{io::Error, pin::Pin};

use tower_async::Service;

use crate::transport::bytes::ByteStream;

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
/// let mut service = ForwardService::new(destination);
///
/// let (bytes_copied_to, bytes_copied_from) = service.call(stream).await?;
/// # assert_eq!(bytes_copied_to, 11);
/// # assert_eq!(bytes_copied_from, 11);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ForwardService<D> {
    destination: Pin<Box<D>>,
}

impl<D> ForwardService<D> {
    /// Creates a new [`ForwardService`],
    pub fn new(destination: D) -> Self {
        Self {
            destination: Box::pin(destination),
        }
    }
}

impl<S, D> Service<S> for ForwardService<D>
where
    S: ByteStream,
    D: ByteStream,
{
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&mut self, source: S) -> Result<Self::Response, Self::Error> {
        tokio::pin!(source);
        tokio::io::copy_bidirectional(&mut source, &mut self.destination).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_forwarder() {
        let destination = Builder::new()
            .write(b"to(1)")
            .read(b"from(1)")
            .write(b"to(2)")
            .wait(std::time::Duration::from_secs(1))
            .read(b"from(2)")
            .build();
        let stream = Builder::new()
            .read(b"to(1)")
            .write(b"from(1)")
            .read(b"to(2)")
            .write(b"from(2)")
            .build();

        ForwardService::new(destination).call(stream).await.unwrap();
    }
}
