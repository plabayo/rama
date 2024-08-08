use super::{ServerConfig, TlsAcceptorService};
use crate::service::Layer;
use std::sync::Arc;

/// A [`Layer`] which wraps the given service with a [`TlsAcceptorService`].
#[derive(Debug, Clone)]
pub struct TlsAcceptorLayer {
    config: Arc<ServerConfig>,
    store_client_hello: bool,
}

impl TlsAcceptorLayer {
    /// Creates a new [`TlsAcceptorLayer`] using the given [`ServerConfig`],
    /// which is used to configure the inner TLS acceptor.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            store_client_hello: false,
        }
    }

    /// Set that the client hello should be stored
    pub fn with_store_client_hello(mut self, store: bool) -> Self {
        self.store_client_hello = store;
        self
    }
}

impl<S> Layer<S> for TlsAcceptorLayer {
    type Service = TlsAcceptorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsAcceptorService::new(self.config.clone(), inner, self.store_client_hello)
    }
}
