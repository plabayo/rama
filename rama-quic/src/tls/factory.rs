use crate::{
    ClientConfig, ServerConfig,
    tls::{TlsConfigError, TlsOptions},
};
use rama_tls::{
    client::{TlsClientConfig, TlsClientConfigProvider},
    server::TlsServerConfig,
};
use std::{fmt, sync::Arc};

#[cfg(all(
    feature = "rustls",
    any(feature = "boring", feature = "aws-lc", feature = "ring")
))]
use rama_tls_rustls::client::RustlsTlsConnectorConfig;
#[cfg(feature = "boring")]
use {
    crate::proto::crypto::boring as boring_crypto,
    rama_tls_boring::client::BoringTlsConnectorConfig,
};
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use {
    crate::proto::crypto::rustls as rustls_crypto,
    rama_tls_rustls::dep::rustls::crypto::CryptoProvider,
};
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use {rama_core::extensions::Extensions, rama_tls::client::TlsPoolId};

/// Build QUIC TLS configurations from Rama settings using a fixed provider.
///
/// This is the request-configuration boundary; the lower-level session provider
/// interface remains available through `ClientConfig::new`. Custom providers use
/// this same interface for construction, pool identity and server authentication.
///
/// Common Rama TLS policies work across implementations. Native settings require
/// a provider that understands them: built-in providers reject another enabled
/// implementation's overrides. When composing different built-in stream and QUIC
/// implementations, enable both corresponding `rama-quic` features so both sets
/// of native settings can be checked. Custom providers must reject unsupported
/// policy, return a non-reusable pool identity and decline authentication claims;
/// silently ignoring restrictions would make transport selection change trust.
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
        if !rustls_supports_client_overrides(extensions) {
            return Some(TlsPoolId::non_reusable());
        }
        RustlsTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        rustls_supports_client_overrides(extensions)
            && RustlsTlsConnectorConfig::from_extensions(extensions).authenticates_server()
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
        if !boring_supports_client_overrides(extensions) {
            return Some(TlsPoolId::non_reusable());
        }
        BoringTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        boring_supports_client_overrides(extensions)
            && BoringTlsConnectorConfig::from_extensions(extensions).authenticates_server()
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

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
/// Reject native policy Rustls cannot enforce, such as a BoringSSL trust store.
/// Otherwise choosing QUIC could silently weaken a stream connector's TLS policy.
pub(crate) fn rustls_supports_client_overrides(extensions: &Extensions) -> bool {
    #[cfg(feature = "boring")]
    {
        !BoringTlsConnectorConfig::from_extensions(extensions).has_native_overrides()
    }
    #[cfg(not(feature = "boring"))]
    {
        let _ = extensions;
        true
    }
}

#[cfg(feature = "boring")]
/// Reject native policy BoringSSL cannot enforce, such as a Rustls verifier.
/// Common Rama TLS settings remain portable across providers.
pub(crate) fn boring_supports_client_overrides(extensions: &Extensions) -> bool {
    #[cfg(feature = "rustls")]
    {
        !RustlsTlsConnectorConfig::from_extensions(extensions).has_native_overrides()
    }
    #[cfg(not(feature = "rustls"))]
    {
        let _ = extensions;
        true
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
    use crate::tls::ClientConfigCache;
    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_net::tls::ApplicationProtocol;
    use rama_tls_boring::client::BoringGrease;
    use rama_tls_rustls::client::ModifyRustlsClientConfig;

    #[test]
    fn native_client_overrides_cannot_cross_quic_providers() {
        let rustls = RustlsTlsProvider::new(rustls_crypto::configured_provider());
        let boring = BoringTlsProvider;
        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let extensions = config.as_extensions();
        assert!(rustls.authenticates_server(extensions));
        assert!(boring.authenticates_server(extensions));
        assert_eq!(rustls.pool_id(extensions), boring.pool_id(extensions));

        extensions.insert(BoringGrease(true));
        assert!(boring.pool_id(extensions).unwrap().is_reusable());
        assert!(!rustls.pool_id(extensions).unwrap().is_reusable());
        assert!(!rustls.authenticates_server(extensions));
        assert!(matches!(
            rustls.client_config(&config, TlsOptions::default()),
            Err(TlsConfigError::UnsupportedClientOverrides)
        ));
        boring
            .client_config(&config, TlsOptions::default())
            .unwrap();

        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let extensions = config.as_extensions();
        extensions.insert(ModifyRustlsClientConfig::new(|_| {
            Err(BoxError::from_static_str("custom rustls hook"))
        }));
        assert!(rustls.pool_id(extensions).unwrap().is_reusable());
        assert!(!boring.pool_id(extensions).unwrap().is_reusable());
        assert!(!boring.authenticates_server(extensions));
        assert!(matches!(
            boring.client_config(&config, TlsOptions::default()),
            Err(TlsConfigError::UnsupportedClientOverrides)
        ));
        assert!(matches!(
            rustls.client_config(&config, TlsOptions::default()),
            Err(TlsConfigError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn warmed_quic_configs_do_not_hide_incompatible_native_overrides() {
        let rustls = ClientConfigCache::new(
            Arc::new(RustlsTlsProvider::new(rustls_crypto::configured_provider())),
            TlsOptions::default(),
        );
        let boring = ClientConfigCache::new(Arc::new(BoringTlsProvider), TlsOptions::default());
        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let request = Extensions::new();
        rustls.client_config(&config, &request).unwrap();
        boring.client_config(&config, &request).unwrap();

        request.insert(BoringGrease(true));
        assert!(matches!(
            rustls.client_config(&config.clone().with_overrides(&request), &request),
            Err(TlsConfigError::UnsupportedClientOverrides)
        ));
        let request = Extensions::new();
        request.insert(ModifyRustlsClientConfig::new(Ok));
        assert!(matches!(
            boring.client_config(&config.with_overrides(&request), &request),
            Err(TlsConfigError::UnsupportedClientOverrides)
        ));
    }
}
