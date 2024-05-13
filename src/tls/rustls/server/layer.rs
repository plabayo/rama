use super::{TlsAcceptorService, TlsClientConfigHandler};
use crate::{service::Layer, tls::rustls::dep::rustls::ServerConfig};
use std::sync::Arc;

/// A [`Layer`] which wraps the given service with a [`TlsAcceptorService`].
#[derive(Clone)]
pub struct TlsAcceptorLayer<H> {
    config: Arc<ServerConfig>,
    client_config_handler: H,
}

impl<H> std::fmt::Debug for TlsAcceptorLayer<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorLayer").finish()
    }
}

impl TlsAcceptorLayer<()> {
    /// Creates a new [`TlsAcceptorLayer`] using the given [`ServerConfig`],
    /// which is used to configure the inner TLS acceptor.
    ///
    /// [`ServerConfig`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            client_config_handler: (),
        }
    }
}

impl<F> TlsAcceptorLayer<TlsClientConfigHandler<F>> {
    /// Creates a new [`TlsAcceptorLayer`] using the given [`ServerConfig`],
    /// which is used to configure the inner TLS acceptor and the given
    /// [`TlsClientConfigHandler`], which is used to configure or track the inner TLS connector.
    pub fn with_client_config_handler(
        config: ServerConfig,
        client_config_handler: TlsClientConfigHandler<F>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            client_config_handler,
        }
    }
}

impl<H: Clone, S> Layer<S> for TlsAcceptorLayer<H> {
    type Service = TlsAcceptorService<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsAcceptorService::new(
            self.config.clone(),
            inner,
            self.client_config_handler.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::utils::test_helpers::assert_send;

        assert_send::<TlsAcceptorLayer<()>>();
        assert_send::<TlsAcceptorLayer<TlsClientConfigHandler<()>>>();
    }

    #[test]
    fn assert_sync() {
        use crate::utils::test_helpers::assert_sync;

        assert_sync::<TlsAcceptorLayer<TlsClientConfigHandler<()>>>();
    }
}
