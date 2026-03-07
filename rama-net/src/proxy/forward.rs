use rama_core::telemetry::tracing;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
};

use rama_core::io::{BridgeIo, Io};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A proxy [`Service`] which takes a [`BridgeIo`]
/// and copies the bytes of both the source and target [`Io`]s
/// bidirectionally.
pub struct StreamForwardService;

impl StreamForwardService {
    #[inline]
    /// Create a new [`StreamForwardService`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S, T> Service<BridgeIo<S, T>> for StreamForwardService
where
    S: Io + Unpin,
    T: Io + Unpin,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(mut left, mut right): BridgeIo<S, T>,
    ) -> Result<Self::Output, Self::Error> {
        match tokio::io::copy_bidirectional(&mut left, &mut right).await {
            Ok((bytes_copied_north, bytes_copied_south)) => {
                tracing::trace!(
                    "(proxy) I/O stream forwarder finished: bytes north: {}; bytes south: {}",
                    bytes_copied_north,
                    bytes_copied_south,
                );
                Ok(())
            }
            Err(err) => {
                if crate::conn::is_connection_error(&err) {
                    Ok(())
                } else {
                    Err(err.context("(proxy) I/O stream forwarder"))
                }
            }
        }
    }
}
