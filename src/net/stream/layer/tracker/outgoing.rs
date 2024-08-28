use super::bytes::BytesRWTracker;
use crate::{
    net::{
        client::{ClientConnection, EstablishedClientConnection},
        stream::Stream,
        transport::TryRefIntoTransportContext,
    },
    service::{Context, Layer, Service},
};
use std::fmt;

/// A [`Service`] that wraps a [`Service`]'s output IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: crate::service::Service
/// [`Stream`]: crate::net::stream::Stream
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

impl<S, State, Request, T> Service<State, Request> for OutgoingBytesTrackerService<S>
where
    S: Service<State, Request, Response = EstablishedClientConnection<T, State, Request>>,
    T: Stream + Unpin,
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
{
    type Response = EstablishedClientConnection<BytesRWTracker<T>, State, Request>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut ctx, req, conn } = self.inner.serve(ctx, req).await?;
        let (addr, stream) = conn.into_parts();
        let stream = BytesRWTracker::new(stream);
        let handle = stream.handle();
        ctx.insert(handle);
        let conn = ClientConnection::new(addr, stream);
        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}

/// A [`Layer`] that wraps a [`Service`]'s output IO [`Stream`] with an atomic R/W tracker.
///
/// [`Layer`]: crate::service::Layer
/// [`Service`]: crate::service::Service
/// [`Stream`]: crate::net::stream::Stream
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OutgoingBytesTrackerLayer;

impl OutgoingBytesTrackerLayer {
    /// Create a new [`OutgoingBytesTrackerLayer`].
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
