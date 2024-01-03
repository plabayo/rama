use crate::{
    service::{Context, Layer, Service},
    stream::Stream,
    tls::dep::rustls::ServerConfig,
};
use std::sync::Arc;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsAcceptorService<S> {
    acceptor: TlsAcceptor,
    inner: S,
}

impl<S> std::fmt::Debug for TlsAcceptorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService").finish()
    }
}

impl<S> Clone for TlsAcceptorService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            acceptor: self.acceptor.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>>,
{
    type Response = S::Response;
    type Error = TtlsAcceptorError<S::Error>;

    async fn serve(&self, ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(TtlsAcceptorError::Accept)?;

        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TtlsAcceptorError::Service)
    }
}

/// Errors that can happen when using [`TlsAcceptorService`].
#[derive(Debug)]
pub enum TtlsAcceptorError<E> {
    /// An error occurred while accepting a TLS connection.
    Accept(std::io::Error),
    /// An error occurred while serving the underlying transport stream
    /// using the inner service.
    Service(E),
}

impl<E> std::fmt::Display for TtlsAcceptorError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TtlsAcceptorError::Accept(e) => write!(f, "accept error: {}", e),
            TtlsAcceptorError::Service(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E> std::error::Error for TtlsAcceptorError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TtlsAcceptorError::Accept(e) => Some(e),
            TtlsAcceptorError::Service(e) => Some(e),
        }
    }
}

/// A [`Layer`] which wraps the given service with a [`TlsAcceptorService`].
pub struct TlsAcceptorLayer {
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptorLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorLayer").finish()
    }
}

impl TlsAcceptorLayer {
    /// Creates a new [`TlsAcceptorLayer`] using the given [`ServerConfig`],
    /// which is used to configure the inner TLS acceptor.
    ///
    /// [`ServerConfig`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html
    pub fn new(config: ServerConfig) -> Self {
        Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }
}

impl<S> Layer<S> for TlsAcceptorLayer {
    type Service = TlsAcceptorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsAcceptorService {
            acceptor: self.acceptor.clone(),
            inner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::test_helpers::assert_send;

        assert_send::<TlsAcceptorLayer>();
        assert_send::<TlsAcceptorService<crate::service::IdentityService>>();
    }

    #[test]
    fn assert_sync() {
        use crate::test_helpers::assert_sync;

        assert_sync::<TlsAcceptorLayer>();
        assert_sync::<TlsAcceptorService<crate::service::IdentityService>>();
    }
}
