use crate::{
    net::stream::Stream,
    service::{Context, Service},
    tls::{
        rustls::dep::{
            rustls::server::Acceptor,
            tokio_rustls::{server::TlsStream, LazyConfigAcceptor, TlsAcceptor},
        },
        SecureTransport,
    },
};
use rustls::ServerConfig;
use std::sync::Arc;

use super::{client_config::IncomingClientHello, ServerConfigProvider, TlsClientConfigHandler};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsAcceptorService<S, H> {
    config: Arc<ServerConfig>,
    client_config_handler: H,
    inner: S,
}

impl<S, H> TlsAcceptorService<S, H> {
    /// Creates a new [`TlsAcceptorService`].
    pub fn new(config: Arc<ServerConfig>, inner: S, client_config_handler: H) -> Self {
        Self {
            config,
            client_config_handler,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S, H> std::fmt::Debug for TlsAcceptorService<S, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService").finish()
    }
}

impl<S, H> Clone for TlsAcceptorService<S, H>
where
    S: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client_config_handler: self.client_config_handler.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S, ()>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>>,
{
    type Response = S::Response;
    type Error = TlsAcceptorError<S::Error>;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = TlsAcceptor::from(self.config.clone());

        let stream = acceptor
            .accept(stream)
            .await
            .map_err(TlsAcceptorError::Accept)?;

        ctx.insert(SecureTransport::default());
        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TlsAcceptorError::Service)
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S, TlsClientConfigHandler<()>>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>>,
{
    type Response = S::Response;
    type Error = TlsAcceptorError<S::Error>;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

        let start = acceptor.await.map_err(TlsAcceptorError::Accept)?;

        if self.client_config_handler.store_client_hello {
            let accepted_client_hello = IncomingClientHello::from(start.client_hello());
            ctx.insert(accepted_client_hello);
        }

        let stream = start
            .into_stream(self.config.clone())
            .await
            .map_err(TlsAcceptorError::Accept)?;

        ctx.insert(SecureTransport::default());
        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TlsAcceptorError::Service)
    }
}

impl<T, S, IO, F> Service<T, IO> for TlsAcceptorService<S, TlsClientConfigHandler<F>>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>>,
    F: ServerConfigProvider,
{
    type Response = S::Response;
    type Error = TlsAcceptorError<S::Error>;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

        let start = acceptor.await.map_err(TlsAcceptorError::Accept)?;

        let accepted_client_hello = IncomingClientHello::from(start.client_hello());

        if self.client_config_handler.store_client_hello {
            ctx.insert(accepted_client_hello.clone());
        }

        let config = self
            .client_config_handler
            .server_config_provider
            .get_server_config(accepted_client_hello)
            .await
            .map_err(TlsAcceptorError::Accept)?
            .unwrap_or_else(|| self.config.clone());

        let stream = start
            .into_stream(config)
            .await
            .map_err(TlsAcceptorError::Accept)?;

        ctx.insert(SecureTransport::default());
        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TlsAcceptorError::Service)
    }
}

/// Errors that can happen when using [`TlsAcceptorService`].
#[derive(Debug)]
pub enum TlsAcceptorError<E> {
    /// An error occurred while accepting a TLS connection.
    Accept(std::io::Error),
    /// An error occurred while serving the underlying transport stream
    /// using the inner service.
    Service(E),
}

impl<E> std::fmt::Display for TlsAcceptorError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsAcceptorError::Accept(e) => write!(f, "accept error: {}", e),
            TlsAcceptorError::Service(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E> std::error::Error for TlsAcceptorError<E>
where
    E: std::fmt::Debug + std::fmt::Display,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsAcceptorError::Accept(e) => Some(e),
            TlsAcceptorError::Service(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::utils::test_helpers::assert_send;

        assert_send::<TlsAcceptorService<crate::service::IdentityService, ()>>();
        assert_send::<
            TlsAcceptorService<crate::service::IdentityService, TlsClientConfigHandler<()>>,
        >();
    }

    #[test]
    fn assert_sync() {
        use crate::utils::test_helpers::assert_sync;

        assert_sync::<TlsAcceptorService<crate::service::IdentityService, ()>>();
        assert_sync::<
            TlsAcceptorService<crate::service::IdentityService, TlsClientConfigHandler<()>>,
        >();
    }
}
