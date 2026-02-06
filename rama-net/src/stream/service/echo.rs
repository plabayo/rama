use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    stream::Stream,
};

/// An async service which echoes the incoming bytes back on the same stream.
///
/// # Example
///
/// ```rust
/// use rama_core::{error::BoxError, Service};
/// use rama_net::stream::service::EchoService;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), BoxError> {
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// let service = EchoService::new();
///
/// let bytes_copied = service.serve(stream).await?;
/// # assert_eq!(bytes_copied, 11);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EchoService;

impl EchoService {
    /// Creates a new [`EchoService`],
    #[must_use]
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for EchoService {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Service<S> for EchoService
where
    S: Stream + 'static,
{
    type Output = u64;
    type Error = BoxError;

    async fn serve(&self, stream: S) -> Result<Self::Output, Self::Error> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::io::copy(&mut reader, &mut writer)
            .await
            .into_box_error()
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

        EchoService::new().serve(stream).await.unwrap();
    }
}
