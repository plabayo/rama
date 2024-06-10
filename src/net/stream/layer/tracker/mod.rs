use crate::{
    net::stream::Stream,
    service::{Context, Layer, Service},
};
use std::future::Future;

mod bytes;
use bytes::BytesRWTracker;
#[doc(inline)]
pub use bytes::BytesRWTrackerHandle;

/// A [`Service`] that wraps a [`Service`]'s input IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: crate::service::Service
/// [`Stream`]: crate::net::stream::Stream
#[derive(Debug)]
pub struct BytesTrackerService<S> {
    inner: S,
}

impl<S> BytesTrackerService<S> {
    /// Create a new [`BytesTrackerService`].
    ///
    /// See [`BytesTrackerService`] for more information.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> Clone for BytesTrackerService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<State, S, IO> Service<State, IO> for BytesTrackerService<S>
where
    State: Send + Sync + 'static,
    S: Service<State, BytesRWTracker<IO>>,
    IO: Stream,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let tracked_stream = BytesRWTracker::new(stream);
        let handle = tracked_stream.handle();
        ctx.insert(handle);
        self.inner.serve(ctx, tracked_stream)
    }
}

/// A [`Layer`] that wraps a [`Service`]'s input IO [`Stream`] with an atomic R/W tracker.
///
/// [`Layer`]: crate::service::Layer
/// [`Service`]: crate::service::Service
/// [`Stream`]: crate::net::stream::Stream
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BytesTrackerLayer;

impl BytesTrackerLayer {
    /// Create a new [`BytesTrackerLayer`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for BytesTrackerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for BytesTrackerLayer {
    type Service = BytesTrackerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BytesTrackerService { inner }
    }
}
