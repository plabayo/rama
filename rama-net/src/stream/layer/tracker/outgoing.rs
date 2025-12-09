use super::bytes::BytesRWTracker;
use crate::client::{ConnectorService, EstablishedClientConnection};
use rama_core::{Layer, Service, extensions::ExtensionsMut, stream::Stream};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] that wraps a [`Service`]'s output IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
#[derive(Debug, Clone)]
pub struct OutgoingBytesTrackerService<S> {
    inner: S,
}

impl<S> OutgoingBytesTrackerService<S> {
    /// Create a new [`OutgoingBytesTrackerService`].
    ///
    /// See [`OutgoingBytesTrackerService`] for more information.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for OutgoingBytesTrackerService<S>
where
    S: ConnectorService<Input, Connection: Stream + Unpin>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<BytesRWTracker<S::Connection>, Input>;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let mut conn = BytesRWTracker::new(conn);
        let handle = conn.handle();
        conn.extensions_mut().insert(handle);
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// A [`Layer`] that wraps a [`Service`]'s output IO [`Stream`] with an atomic R/W tracker.
///
/// [`Layer`]: rama_core::Layer
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OutgoingBytesTrackerLayer;

impl OutgoingBytesTrackerLayer {
    /// Create a new [`OutgoingBytesTrackerLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for OutgoingBytesTrackerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for OutgoingBytesTrackerLayer {
    type Service = OutgoingBytesTrackerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OutgoingBytesTrackerService { inner }
    }
}
