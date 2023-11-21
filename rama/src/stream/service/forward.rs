use std::{io::Error, pin::Pin};

use crate::{
    service::Service,
    stream::Stream,
    sync::{Arc, AsyncMutex},
};

/// Async service which forwards the incoming connection bytes to the given destination,
/// and forwards the response back from the destination to the incoming connection.
///
/// # Example
///
/// ```rust
/// use rama::{service::Service, stream::service::ForwardService};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let destination = tokio_test::io::Builder::new().write(b"hello world").read(b"hello world").build();
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// let service = ForwardService::new(destination);
///
/// let (bytes_copied_to, bytes_copied_from) = service.call(stream).await?;
/// # assert_eq!(bytes_copied_to, 11);
/// # assert_eq!(bytes_copied_from, 11);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ForwardService<D> {
    destination: Arc<AsyncMutex<Pin<Box<D>>>>,
}

impl<D> Clone for ForwardService<D>
where
    D: Clone,
{
    fn clone(&self) -> Self {
        Self {
            destination: self.destination.clone(),
        }
    }
}

impl<D> ForwardService<D> {
    /// Creates a new [`ForwardService`],
    pub fn new(destination: D) -> Self {
        Self {
            destination: Arc::new(AsyncMutex::new(Box::pin(destination))),
        }
    }
}

impl<S, D> Service<S> for ForwardService<D>
where
    S: Stream,
    D: Stream,
{
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&self, source: S) -> Result<Self::Response, Self::Error> {
        crate::pin!(source);
        let mut destination_guard = self.destination.lock().await;
        let mut destination = destination_guard.as_mut();
        tokio::io::copy_bidirectional(&mut source, &mut destination).await
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
