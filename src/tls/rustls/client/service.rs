use crate::{
    service::{Context, Service},
    stream::Stream,
    tls::rustls::dep::pki_types::ServerName,
    tls::rustls::dep::rustls::ClientConfig,
    tls::rustls::dep::tokio_rustls::{client::TlsStream, TlsConnector},
};
use std::sync::Arc;

/// A [`Service`] which makes TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsConnectService<S> {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    inner: S,
}

impl<S> TlsConnectService<S> {
    /// Creates a new [`TlsConnectService`].
    pub fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>, inner: S) -> Self {
        Self {
            config,
            server_name,
            inner,
        }
    }
}

impl<S> std::fmt::Debug for TlsConnectService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnectService").finish()
    }
}

impl<S> Clone for TlsConnectService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            server_name: self.server_name.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsConnectService<S>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>>,
{
    type Response = S::Response;
    type Error = TlsConnectError<S::Error>;

    async fn serve(&self, ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let client: TlsConnector = TlsConnector::from(self.config.clone());

        let stream = client
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(TlsConnectError::Connect)?;

        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TlsConnectError::Service)
    }
}

/// Errors that can happen when using [`TlsConnectService`].
#[derive(Debug)]
pub enum TlsConnectError<E> {
    /// An error occurred while accepting a TLS connection.
    Connect(std::io::Error),
    /// An error occurred while serving the underlying transport stream
    /// using the inner service.
    Service(E),
}

impl<E> std::fmt::Display for TlsConnectError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConnectError::Connect(e) => write!(f, "accept error: {}", e),
            TlsConnectError::Service(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E> std::error::Error for TlsConnectError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsConnectError::Connect(e) => Some(e),
            TlsConnectError::Service(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::test_helpers::assert_send;

        assert_send::<TlsConnectService<crate::service::IdentityService>>();
    }

    #[test]
    fn assert_sync() {
        use crate::test_helpers::assert_sync;

        assert_sync::<TlsConnectService<crate::service::IdentityService>>();
    }
}
