use super::bytes::BytesRWTracker;
use rama_core::{Layer, Service, extensions::ExtensionsMut, stream::Stream};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] that wraps a [`Service`]'s input IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
#[derive(Debug, Clone)]
pub struct IncomingBytesTrackerService<S> {
    inner: S,
}

impl<S> IncomingBytesTrackerService<S> {
    /// Create a new [`IncomingBytesTrackerService`].
    ///
    /// See [`IncomingBytesTrackerService`] for more information.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for IncomingBytesTrackerService<S>
where
    S: Service<BytesRWTracker<IO>>,
    IO: Stream + ExtensionsMut,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let mut tracked_stream = BytesRWTracker::new(stream);
        let handle = tracked_stream.handle();
        tracked_stream.extensions_mut().insert(handle);

        self.inner.serve(tracked_stream)
    }
}

/// A [`Layer`] that wraps a [`Service`]'s input IO [`Stream`] with an atomic R/W tracker.
///
/// [`Layer`]: rama_core::Layer
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IncomingBytesTrackerLayer;

impl IncomingBytesTrackerLayer {
    /// Create a new [`IncomingBytesTrackerLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for IncomingBytesTrackerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for IncomingBytesTrackerLayer {
    type Service = IncomingBytesTrackerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IncomingBytesTrackerService { inner }
    }
}
