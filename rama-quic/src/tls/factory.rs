#[cfg(feature = "boring")]
use crate::proto::crypto::boring as boring_crypto;
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use crate::proto::crypto::rustls as rustls_crypto;
#[cfg(feature = "boring")]
use rama_tls_boring::client::BoringTlsConnectorConfig;
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use rama_tls_rustls::{client::RustlsTlsConnectorConfig, dep::rustls::crypto::CryptoProvider};
use std::{fmt, sync::Arc};

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use rama_core::extensions::Extensions;
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use rama_tls::client::TlsPoolId;
use rama_tls::{
    client::{TlsClientConfig, TlsClientConfigProvider},
    server::TlsServerConfig,
};

use crate::tls::{TlsConfigError, TlsOptions};
use crate::{ClientConfig, ServerConfig};

/// Build QUIC TLS configurations from Rama settings using a fixed provider.
///
/// This is the request-configuration boundary; the lower-level session provider
/// interface remains available through `ClientConfig::new`. Custom providers use
/// this same interface for construction, pool identity and server authentication.
pub trait QuicClientConfigProvider: TlsClientConfigProvider {
    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError>;
}

/// Build server configurations without requiring client-policy support.
pub trait QuicServerConfigProvider: fmt::Debug + Send + Sync {
    fn server_config(
        &self,
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<ServerConfig, TlsConfigError>;
}

/// Select the feature-default configuration provider once when constructing a connector.
/// Rustls with an enabled cryptographic implementation is preferred, then BoringSSL.
pub fn default_tls_provider() -> Result<Arc<dyn QuicClientConfigProvider>, TlsConfigError> {
    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    {
        Ok(Arc::new(RustlsTlsProvider::new(
            rustls_crypto::configured_provider(),
        )))
    }
    #[cfg(all(
        feature = "boring",
        not(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))
    ))]
    {
        Ok(Arc::new(BoringTlsProvider))
    }
    #[cfg(not(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )))]
    {
        Err(TlsConfigError::BackendUnavailable)
    }
}

/// Rustls QUIC configuration factory with an explicitly supplied cryptographic provider.
///
/// The adapter still requires the `ring` or `aws-lc` feature for its packet crypto.
/// Supplying a provider here does not install or use Rustls's process-wide default.
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
#[derive(Debug, Clone)]
pub struct RustlsTlsProvider {
    crypto: Arc<CryptoProvider>,
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl RustlsTlsProvider {
    pub fn new(crypto: Arc<CryptoProvider>) -> Self {
        Self { crypto }
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl TlsClientConfigProvider for RustlsTlsProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        RustlsTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl QuicClientConfigProvider for RustlsTlsProvider {
    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        Ok(ClientConfig::new(Arc::new(
            rustls_crypto::QuicClientConfig::from_rama(config, self.crypto.clone(), options)?,
        )))
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl QuicServerConfigProvider for RustlsTlsProvider {
    fn server_config(
        &self,
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<ServerConfig, TlsConfigError> {
        Ok(ServerConfig::with_crypto(Arc::new(
            rustls_crypto::QuicServerConfig::from_rama(config, self.crypto.clone(), options)?,
        )))
    }
}

/// BoringSSL QUIC configuration factory.
#[cfg(feature = "boring")]
#[derive(Debug, Clone, Copy, Default)]
pub struct BoringTlsProvider;

#[cfg(feature = "boring")]
impl TlsClientConfigProvider for BoringTlsProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        BoringTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        BoringTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(feature = "boring")]
impl QuicClientConfigProvider for BoringTlsProvider {
    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        Ok(ClientConfig::new(Arc::new(
            boring_crypto::QuicClientConfig::from_rama(config, options)?,
        )))
    }
}

#[cfg(feature = "boring")]
impl QuicServerConfigProvider for BoringTlsProvider {
    fn server_config(
        &self,
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<ServerConfig, TlsConfigError> {
        Ok(ServerConfig::with_crypto(Arc::new(
            boring_crypto::QuicServerConfig::from_rama(config, options)?,
        )))
    }
}

impl ClientConfig {
    /// Build through the explicitly injected provider, independently of enabled defaults.
    pub fn try_from_rama_tls_with_provider(
        config: &TlsClientConfig,
        options: TlsOptions,
        provider: &dyn QuicClientConfigProvider,
    ) -> Result<Self, TlsConfigError> {
        provider.client_config(config, options)
    }
}
impl ServerConfig {
    /// Build through the explicitly injected provider, independently of enabled defaults.
    pub fn try_from_rama_tls_with_provider(
        config: &TlsServerConfig,
        options: TlsOptions,
        provider: &dyn QuicServerConfigProvider,
    ) -> Result<Self, TlsConfigError> {
        provider.server_config(config, options)
    }
}

/// Select the feature-default server configuration provider.
pub fn default_server_tls_provider() -> Result<Arc<dyn QuicServerConfigProvider>, TlsConfigError> {
    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    {
        Ok(Arc::new(RustlsTlsProvider::new(
            rustls_crypto::configured_provider(),
        )))
    }
    #[cfg(all(
        feature = "boring",
        not(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))
    ))]
    {
        Ok(Arc::new(BoringTlsProvider))
    }
    #[cfg(not(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )))]
    {
        Err(TlsConfigError::BackendUnavailable)
    }
}

#[cfg(all(
    test,
    feature = "boring",
    feature = "rustls",
    any(feature = "aws-lc", feature = "ring")
))]
mod tests {
    use super::*;
    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_net::tls::ApplicationProtocol;
    use rama_tls_boring::client::BoringGrease;
    use rama_tls_rustls::client::ModifyRustlsClientConfig;

    #[test]
    fn injected_provider_owns_native_overrides_and_authentication() {
        let rustls = RustlsTlsProvider::new(rustls_crypto::configured_provider());
        let boring = BoringTlsProvider;
        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let extensions = config.as_extensions();
        extensions.insert(BoringGrease(true));
        assert!(boring.pool_id(extensions).is_some());
        let baseline_rustls = rustls.pool_id(extensions);
        extensions.insert(ModifyRustlsClientConfig::new(|_| {
            Err(BoxError::from_static_str("custom rustls hook"))
        }));
        assert!(!rustls.pool_id(extensions).unwrap().is_reusable());
        assert_ne!(rustls.pool_id(extensions), baseline_rustls);
        assert!(boring.pool_id(extensions).unwrap().is_reusable());
        assert!(!rustls.authenticates_server(extensions));
        assert!(boring.authenticates_server(extensions));
        rustls
            .client_config(&config, TlsOptions::default())
            .unwrap_err();
        boring
            .client_config(&config, TlsOptions::default())
            .unwrap();
    }
}
