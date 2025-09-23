use rama_core::{Context, Layer, Service, stream::Stream};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

use super::bytes::BytesRWTracker;
use crate::client::{ConnectorService, EstablishedClientConnection};

/// A [`Service`] that wraps a [`Service`]'s output IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
pub struct OutgoingBytesTrackerService<S> {
    inner: S,
}

impl<S: fmt::Debug> fmt::Debug for OutgoingBytesTrackerService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingBytesTrackerService")
            .field("inner", &self.inner)
            .finish()
    }
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

impl<S> Clone for OutgoingBytesTrackerService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, Request> Service<Request> for OutgoingBytesTrackerService<S>
where
    S: ConnectorService<Request, Connection: Stream + Unpin, Error: Send + 'static>,
    Request: Send + 'static,
{
    type Response = EstablishedClientConnection<BytesRWTracker<S::Connection>, Request>;
    type Error = S::Error;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut ctx, req, conn } =
            self.inner.connect(ctx, req).await?;
        let conn = BytesRWTracker::new(conn);
        let handle = conn.handle();
        ctx.insert(handle);
        Ok(EstablishedClientConnection { ctx, req, conn })
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
