use rama_core::{Context, Layer, Service, stream::Stream};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

use super::bytes::BytesRWTracker;

/// A [`Service`] that wraps a [`Service`]'s input IO [`Stream`] with an atomic R/W tracker.
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::stream::Stream
pub struct IncomingBytesTrackerService<S> {
    inner: S,
}

impl<S: fmt::Debug> fmt::Debug for IncomingBytesTrackerService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingBytesTrackerService")
            .field("inner", &self.inner)
            .finish()
    }
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

impl<S> Clone for IncomingBytesTrackerService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, IO> Service<IO> for IncomingBytesTrackerService<S>
where
    S: Service<BytesRWTracker<IO>>,
    IO: Stream,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context,
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
