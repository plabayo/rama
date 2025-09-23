use rama_core::telemetry::tracing;
use rama_core::{
    Context, Service,
    error::{ErrorExt, OpaqueError},
};

use rama_core::stream::Stream;

use super::ProxyRequest;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A proxy [`Service`] which takes a [`ProxyRequest`]
/// and copies the bytes of both the source and target [`Stream`]s
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

impl<S, T> Service<ProxyRequest<S, T>> for StreamForwardService
where
    S: Stream + Unpin,
    T: Stream + Unpin,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        _ctx: Context,
        ProxyRequest {
            mut source,
            mut target,
        }: ProxyRequest<S, T>,
    ) -> Result<Self::Response, Self::Error> {
        match tokio::io::copy_bidirectional(&mut source, &mut target).await {
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
