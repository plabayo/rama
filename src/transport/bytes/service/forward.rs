use std::{
    io::{Error, ErrorKind},
    pin::Pin,
};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

/// Crates an async service which forwards the incoming connection bytes to the given destination,
/// and forwards the response back from the destination to the incoming connection.
#[derive(Debug)]
pub struct ForwardService<D, K> {
    destination: Pin<Box<D>>,
    _kind: std::marker::PhantomData<K>,
}

mod marker {
    /// Marker type for the graceful variant of [`super::ForwardService`].
    pub(super) struct Graceful;
    /// Marker type for the ungraceful variant of [`super::ForwardService`].
    pub(super) struct Ungraceful;
}

impl<D> ForwardService<D, marker::Graceful> {
    /// Creates a new [`ForwardService`] which respects the graceful shutdown,
    /// by being an alias of [`ForwardService::graceful`].
    pub fn new(destination: D) -> Self {
        Self::graceful(destination)
    }

    /// Creates a new [`ForwardService`] which respects the graceful shutdown,
    /// and stops bidirectionally copying bytes as soon as the shutdown is requested.
    pub fn graceful(destination: D) -> Self {
        ForwardService {
            destination: Box::pin(destination),
            _kind: std::marker::PhantomData,
        }
    }
}

impl<D> ForwardService<D, marker::Ungraceful> {
    /// Creates a new [`ForwardService`] which does not respect the graceful shutdown,
    /// and keeps bidirectionally copying bytes until the connection is closed or other error,
    /// even if the shutdown was requested already way before.
    pub fn ungraceful(destination: D) -> Self {
        ForwardService {
            destination: Box::pin(destination),
            _kind: std::marker::PhantomData,
        }
    }
}

impl<T, S, D> Service<Connection<S, T>> for ForwardService<D, marker::Graceful>
where
    S: ByteStream,
    D: ByteStream,
{
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&mut self, conn: Connection<S, T>) -> Result<Self::Response, Self::Error> {
        let (source, token, _) = conn.into_parts();
        tokio::pin!(source);
        tokio::select! {
            _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "forward: graceful shutdown requested")),
            res = tokio::io::copy_bidirectional(&mut source, &mut self.destination) => res,
        }
    }
}

impl<T, S, D> Service<Connection<S, T>> for ForwardService<D, marker::Ungraceful>
where
    S: ByteStream,
    D: ByteStream,
{
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&mut self, conn: Connection<S, T>) -> Result<Self::Response, Self::Error> {
        let (source, _, _) = conn.into_parts();
        tokio::pin!(source);
        tokio::io::copy_bidirectional(&mut source, &mut self.destination).await
    }
}
