use crate::{
    ClientConfig, ServerConfig,
    tls::{TlsConfigError, TlsOptions},
};
use rama_tls::{
    client::{TlsClientConfig, TlsClientConfigProvider},
    server::TlsServerConfig,
};
use std::{fmt, sync::Arc};

#[cfg(feature = "boring")]
use {
    crate::proto::crypto::boring as boring_crypto,
    rama_tls_boring::client::BoringTlsConnectorConfig,
};
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use {
    crate::proto::crypto::rustls as rustls_crypto,
    rama_tls_rustls::{client::RustlsTlsConnectorConfig, dep::rustls::crypto::CryptoProvider},
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
/// Built-in providers apply common Rama TLS settings and their own native
/// extensions, ignoring other providers' native settings. Construction,
/// authentication claims and pool identity describe the settings actually applied.
/// Different connectors can therefore use different TLS policies.
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
    use crate::tls::ClientConfigCache;
    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_net::tls::ApplicationProtocol;
    use rama_tls_boring::client::BoringGrease;
    use rama_tls_rustls::client::ModifyRustlsClientConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn native_settings_affect_only_the_selected_provider() {
        let rustls = RustlsTlsProvider::new(rustls_crypto::configured_provider());
        let boring = BoringTlsProvider;
        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let extensions = config.as_extensions();
        let baseline = rustls.pool_id(extensions);
        assert_eq!(baseline, boring.pool_id(extensions));

        extensions.insert(BoringGrease(true));
        assert_eq!(baseline, rustls.pool_id(extensions));
        let boring_policy = boring.pool_id(extensions);
        assert_ne!(baseline, boring_policy);
        assert!(rustls.authenticates_server(extensions));
        assert!(boring.authenticates_server(extensions));
        rustls
            .client_config(&config, TlsOptions::default())
            .unwrap();
        boring
            .client_config(&config, TlsOptions::default())
            .unwrap();

        // Both native configurations may coexist. Only Rustls executes this hook.
        extensions.insert(ModifyRustlsClientConfig::new(|_| {
            Err(BoxError::from_static_str("custom rustls hook"))
        }));
        assert_ne!(baseline, rustls.pool_id(extensions));
        assert_eq!(boring_policy, boring.pool_id(extensions));
        assert!(!rustls.authenticates_server(extensions));
        assert!(boring.authenticates_server(extensions));
        assert!(matches!(
            rustls.client_config(&config, TlsOptions::default()),
            Err(TlsConfigError::InvalidConfiguration(_))
        ));
        boring
            .client_config(&config, TlsOptions::default())
            .unwrap();
    }

    #[test]
    fn config_caches_reuse_foreign_changes_and_apply_own_changes() {
        let rustls = ClientConfigCache::new(
            Arc::new(RustlsTlsProvider::new(rustls_crypto::configured_provider())),
            TlsOptions::default(),
        );
        let boring = ClientConfigCache::new(Arc::new(BoringTlsProvider), TlsOptions::default());
        let config =
            TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let request = Extensions::new();
        let baseline_rustls = rustls.client_config(&config, &request).unwrap();
        let baseline_boring = boring.client_config(&config, &request).unwrap();

        request.insert(BoringGrease(true));
        let effective = config.clone().with_overrides(&request);
        let retained_rustls = rustls.client_config(&effective, &request).unwrap();
        let changed_boring = boring.client_config(&effective, &request).unwrap();
        assert!(Arc::ptr_eq(
            &baseline_rustls.crypto,
            &retained_rustls.crypto
        ));
        assert!(!Arc::ptr_eq(
            &baseline_boring.crypto,
            &changed_boring.crypto
        ));

        let calls = Arc::new(AtomicUsize::new(0));
        request.insert(ModifyRustlsClientConfig::new({
            let calls = calls.clone();
            move |config| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(config)
            }
        }));
        let effective = config.clone().with_overrides(&request);
        let changed_rustls = rustls.client_config(&effective, &request).unwrap();
        assert!(!Arc::ptr_eq(
            &baseline_rustls.crypto,
            &changed_rustls.crypto
        ));
        let retained_boring = boring.client_config(&effective, &request).unwrap();
        assert!(Arc::ptr_eq(&changed_boring.crypto, &retained_boring.crypto));

        request.insert(BoringGrease(false));
        let effective = config.clone().with_overrides(&request);
        let retained_rustls = rustls.client_config(&effective, &request).unwrap();
        assert!(Arc::ptr_eq(&changed_rustls.crypto, &retained_rustls.crypto));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let replaced_boring = boring.client_config(&effective, &request).unwrap();
        assert!(!Arc::ptr_eq(
            &changed_boring.crypto,
            &replaced_boring.crypto
        ));

        request.insert(ModifyRustlsClientConfig::new(|_| {
            Err(BoxError::from_static_str("replacement rejects this policy"))
        }));
        let effective = config.with_overrides(&request);
        assert!(matches!(
            rustls.client_config(&effective, &request),
            Err(TlsConfigError::InvalidConfiguration(_))
        ));
        let retained_boring = boring.client_config(&effective, &request).unwrap();
        assert!(Arc::ptr_eq(
            &replaced_boring.crypto,
            &retained_boring.crypto
        ));
    }
}
