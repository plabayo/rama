use crate::{
    net::TcpStream,
    service::{Layer, Service},
};

mod bytes;
use bytes::BytesRWTracker;
pub use bytes::BytesRWTrackerHandle;

#[derive(Debug)]
pub struct BytesTrackerService<S> {
    inner: S,
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

impl<S, I> Service<TcpStream<I>> for BytesTrackerService<S>
where
    S: Service<TcpStream<BytesRWTracker<I>>>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&self, stream: TcpStream<I>) -> Result<Self::Response, Self::Error> {
        let (stream, mut extensions) = stream.into_parts();

        let stream = BytesRWTracker::new(stream);
        let handle = stream.handle();
        extensions.insert(handle);

        let stream = TcpStream::from_parts(stream, extensions);

        self.inner.call(stream).await
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BytesTrackerLayer;

impl BytesTrackerLayer {
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
