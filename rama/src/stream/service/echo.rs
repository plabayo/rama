use std::io::Error;

use crate::{service::Service, stream::Stream};

/// An async service which echoes the incoming bytes back on the same stream.
///
/// # Example
///
/// ```rust
/// use rama::{service::Service, stream::service::EchoService};
///
/// # #[rama::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// let mut service = EchoService::new();
///
/// let bytes_copied = service.call(stream).await?;
/// # assert_eq!(bytes_copied, 11);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EchoService {
    _phantom: (),
}

impl EchoService {
    /// Creates a new [`EchoService`],
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

impl Default for EchoService {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Service<S> for EchoService
where
    S: Stream,
{
    type Response = u64;
    type Error = Error;

    async fn call(&mut self, stream: S) -> Result<Self::Response, Self::Error> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::io::copy(&mut reader, &mut writer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_echo() {
        let stream = Builder::new()
            .read(b"one")
            .write(b"one")
            .read(b"two")
            .write(b"two")
            .build();

        EchoService::new().call(stream).await.unwrap();
    }
}
