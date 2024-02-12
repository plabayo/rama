use super::TlsConnectService;
use crate::tls::dep::pki_types::ServerName;
use crate::{service::Layer, tls::dep::rustls::ClientConfig};
use std::sync::Arc;

/// A [`Layer`] which wraps the given service with a [`TlsConnectService`].
#[derive(Clone)]
pub struct TlsConnectLayer {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl std::fmt::Debug for TlsConnectLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnectLayer").finish()
    }
}

impl TlsConnectLayer {
    /// Creates a new [`TlsConnectLayer`] using the given [`ClientConfig`],
    /// which is used to configure the inner TLS connector.
    ///
    /// [`ClientConfig`]: https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html
    pub fn new(config: ClientConfig, server_name: ServerName<'static>) -> Self {
        Self {
            config: Arc::new(config),
            server_name,
        }
    }
}

impl<S> Layer<S> for TlsConnectLayer {
    type Service = TlsConnectService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnectService::new(self.config.clone(), self.server_name.clone(), inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use crate::test_helpers::assert_send;

        assert_send::<TlsConnectLayer>();
    }

    #[test]
    fn assert_sync() {
        use crate::test_helpers::assert_sync;

        assert_sync::<TlsConnectLayer>();
    }
}
