//! An async service which echoes the incoming bytes back on the same stream.

use crate::stream::Stream;
use rama_core::{Context, Service, error::BoxError};

/// An async service which echoes the incoming bytes back on the same stream.
///
/// # Example
///
/// ```rust
/// use rama_core::{error::BoxError, Context, Service};
/// use rama_net::stream::service::EchoService;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), BoxError> {
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// let service = EchoService::new();
///
/// let bytes_copied = service.serve(Context::default(), stream).await?;
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
    #[must_use]
    pub const fn new() -> Self {
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
    S: Stream + 'static,
{
    type Response = u64;
    type Error = BoxError;

    async fn serve(&self, _ctx: Context, stream: S) -> Result<Self::Response, Self::Error> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::io::copy(&mut reader, &mut writer)
            .await
            .map_err(Into::into)
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

        EchoService::new()
            .serve(Context::default(), stream)
            .await
            .unwrap();
    }
}
