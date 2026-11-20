#[cfg(all(feature = "boring", feature = "ua"))]
use crate::profile::replay::has_captured_tls;
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::Host;

use rama_core::{extensions::Extensions, futures::future::BoxFuture};
use std::{fmt, sync::Arc};

use crate::{
    ClientConfig, ServerConfig,
    tls::{ClientConfigRequest, ClientHandshake, TlsConfigError, TlsOptions},
};
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use rama_net::client::pool::ReuseKey;
use rama_tls::{
    client::{TlsClientConfig, TlsClientConfigProvider},
    server::TlsServerConfig,
};
#[cfg(feature = "boring")]
use {
    crate::proto::crypto::boring as boring_crypto,
    rama_crypto::dep::boring::ssl::{GreaseValues, UnknownValues},
    rama_tls::client::ClientHello,
    rama_tls_boring::client::{
        BoringClientConfigExt as _, BoringExtensionOrder, BoringServerTrustCache,
        BoringTlsConnectorConfig,
    },
};
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use {
    crate::{profile::capture, proto::crypto::rustls as rustls_crypto},
    rama_quic_proto::{
        Side, Version,
        capture::{CaptureError, InitialKeys, KeyProvider},
        crypto::{HeaderKey, PacketKey},
    },
    rama_tls_rustls::{
        client::{RustlsServerTrustCache, RustlsTlsConnectorConfig},
        dep::rustls::crypto::CryptoProvider,
    },
};
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use {
    rama_core::combinators::Either,
    rama_crypto::platform_verifier::PlatformVerifier,
    rama_tls::client::{
        NativeTrustPolicy, PlatformTrustPolicy, ServerTrustSource, TlsComponentIdentity, TlsPoolId,
        TlsServerTrust,
    },
};

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
    /// Whether this backend can offer real ECH from endpoint configuration.
    fn supports_ech(&self) -> bool {
        false
    }

    /// Optional connector-local backend session state shared by sibling configurations.
    /// These extensions hold cache metadata; they must not replace TLS security settings.
    /// The default retains each native configuration's own session state.
    fn session_defaults(&self) -> Option<Extensions> {
        None
    }

    /// Prepare peer-bound native TLS state without connection I/O.
    /// Prepared configurations bypass ordinary caches because their first native
    /// session belongs to this peer; retries obtain fresh ephemeral state.
    ///
    /// `handshake` controls ticket offers; `options` still controls ticket
    /// retention and early data. Authentication and credentials remain `policy`.
    /// Return `None` if this provider cannot prepare native sessions.
    fn prepare_client_config(
        &self,
        _policy: &TlsClientConfig,
        _options: TlsOptions,
        _peer: Host,
        _handshake: ClientHandshake,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        Ok(None)
    }

    /// Apply the final TLS settings and client handshake policy in `options`.
    /// Fresh clients must neither consult nor populate session-ticket stores,
    /// including stores supplied through native configuration hooks.
    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError>;

    /// Acquire a configuration for one connection through this provider's cache.
    ///
    /// The connector supplies a lookup bound to this provider and its cache.
    /// The default uses [`TlsClientConfigProvider::pool_id`] to classify effective settings and calls
    /// [`Self::client_config`] on a cache miss or [`Self::prepare_client_config`] for peer-bound sessions.
    /// Custom providers with mutable state can pass a supplemental key and
    /// matching native builders to [`ClientConfigRequest::get_or_build`]. Return
    /// `None` when the provider does not support the requested peer-bound handshake.
    fn acquire_client_config(
        &self,
        request: ClientConfigRequest<'_>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        request.get_or_build(
            None,
            |config, options| self.client_config(config, options),
            |config, options, peer, handshake| {
                self.prepare_client_config(config, options, peer, handshake)
            },
        )
    }

    /// Acquire a peer's configuration asynchronously when the provider needs I/O.
    /// The default calls [`Self::acquire_client_config`] on the current task.
    fn acquire_client_config_async<'a>(
        &'a self,
        request: ClientConfigRequest<'a>,
    ) -> BoxFuture<'a, Result<Option<ClientConfig>, TlsConfigError>> {
        Box::pin(async move { self.acquire_client_config(request) })
    }

    /// Whether backend-specific settings permit early data in this configuration.
    fn allows_early_data(&self, _extensions: &Extensions) -> bool {
        true
    }

    /// Whether the peer `leaf` of a connection authenticated under the effective
    /// configuration in `extensions` is also valid for `name`, including any pins
    /// scoped to it. Providers that cannot tell return `false`; a pin scoped to `name`
    /// on an intermediate or root never matches the leaf, so it fails closed.
    fn peer_matches_name(
        &self,
        extensions: &Extensions,
        leaf: &CertificateDer<'_>,
        name: &Host,
    ) -> bool;
}

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
// Static policies are already part of the pool ID. Only a reloadable source
// needs the particular verifier used by this handshake to distinguish rotations.
fn reloadable_verification_identity<R: Send + Sync + 'static>(
    request: ClientConfigRequest<'_>,
    verification: Option<&Either<Arc<R>, Arc<PlatformVerifier>>>,
) -> Option<ReuseKey> {
    let verification = verification?;
    match request
        .config()
        .as_extensions()
        .get_ref::<TlsServerTrust>()?
        .source()
    {
        ServerTrustSource::Native(policy) if policy != &NativeTrustPolicy::new() => {}
        ServerTrustSource::Platform(policy) if policy != &PlatformTrustPolicy::new() => {}
        _ => return None,
    }
    Some(match verification {
        Either::A(store) => ReuseKey::new(TlsComponentIdentity::shared(store)),
        Either::B(verifier) => ReuseKey::new(TlsComponentIdentity::shared(verifier)),
    })
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
        Ok(Arc::new(BoringTlsProvider::new()))
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
    /// Select Rustls's native cryptographic provider for this adapter.
    ///
    /// This backend-specific constructor intentionally accepts the Rustls type
    /// re-exported by `rama_tls_rustls::dep::rustls`. Backend-neutral callers use
    /// [`default_tls_provider`] or [`QuicClientConfigProvider`] instead.
    pub fn new(crypto: Arc<CryptoProvider>) -> Self {
        Self { crypto }
    }

    fn cached_with_verification(
        &self,
        request: ClientConfigRequest<'_>,
        verification: Option<&rustls_crypto::ServerVerification>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let identity = reloadable_verification_identity(request, verification);
        let build = |config: &TlsClientConfig, options| {
            rustls_crypto::QuicClientConfig::from_rama_with_verification(
                config,
                self.crypto.clone(),
                options,
                verification,
            )
        };
        request.get_or_build(
            identity,
            |config, options| {
                build(config, options).map(|native| ClientConfig::new(Arc::new(native)))
            },
            |config, options, peer, handshake| {
                self.prepare_client_config(config, options, peer, handshake)
            },
        )
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl TlsClientConfigProvider for RustlsTlsProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        RustlsTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn pool_classifier(&self) -> ReuseKey {
        ReuseKey::of::<RustlsTlsConnectorConfig>()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl QuicClientConfigProvider for RustlsTlsProvider {
    fn acquire_client_config(
        &self,
        request: ClientConfigRequest<'_>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let verification = request
            .native_cache(RustlsServerTrustCache::new)
            .server_verification(request.config().as_extensions())?;
        self.cached_with_verification(request, verification.as_ref())
    }

    fn acquire_client_config_async<'a>(
        &'a self,
        request: ClientConfigRequest<'a>,
    ) -> BoxFuture<'a, Result<Option<ClientConfig>, TlsConfigError>> {
        Box::pin(async move {
            let verification = request
                .native_cache(RustlsServerTrustCache::new)
                .server_verification_async(request.config().as_extensions())
                .await?;
            self.cached_with_verification(request, verification.as_ref())
        })
    }

    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        Ok(ClientConfig::new(Arc::new(
            rustls_crypto::QuicClientConfig::from_rama(config, self.crypto.clone(), options)?,
        )))
    }

    fn peer_matches_name(
        &self,
        extensions: &Extensions,
        leaf: &CertificateDer<'_>,
        name: &Host,
    ) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).peer_matches_name(leaf, name)
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl QuicServerConfigProvider for RustlsTlsProvider {
    fn server_config(
        &self,
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<ServerConfig, TlsConfigError> {
        Ok(ServerConfig::with_random_token_key(
            rustls_crypto::server_config_from_rama(config, self.crypto.clone(), options)?,
        ))
    }
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
impl KeyProvider for RustlsTlsProvider {
    type Header = Box<dyn HeaderKey>;
    type Packet = Box<dyn PacketKey>;

    fn initial_keys(
        &self,
        version: Version,
        dcid: &[u8],
        side: Side,
    ) -> Result<InitialKeys<Self::Header, Self::Packet>, CaptureError> {
        let dcid = capture::connection_id(dcid)?;
        version
            .wire()
            .ok_or(CaptureError::UnknownVersion(version))?;
        let suite = rustls_crypto::initial_suite_from_provider(&self.crypto)
            .ok_or(CaptureError::Undecryptable)?;
        let keys = rustls_crypto::server_initial_keys(version, &dcid, &suite)
            .map_err(|_error| CaptureError::Undecryptable)?;
        capture::receiving_keys(keys, side)
    }
}

/// BoringSSL QUIC configuration factory.
#[cfg(feature = "boring")]
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BoringTlsProvider;

#[cfg(feature = "boring")]
impl BoringTlsProvider {
    /// Select BoringSSL for QUIC TLS.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Prepare the first native TLS session for `peer` without sending packets.
    ///
    /// The first dial consumes the prepared SSL object; address retries create
    /// fresh sibling sessions. All use full handshakes, without reading or
    /// retaining tickets. This configuration belongs to `peer` and must not be
    /// shared through a cache that omits that identity.
    pub fn prepare_fresh_client_config(
        &self,
        config: &TlsClientConfig,
        peer: Host,
    ) -> Result<ClientConfig, TlsConfigError> {
        Ok(ClientConfig::new(Arc::new(
            boring_crypto::QuicClientConfig::prepare_fresh(config, peer)?,
        )))
    }

    /// Offer a client's QUIC `hello` again, as far as this engine negotiates it: values it
    /// cannot negotiate are dropped and GREASE codepoints are the client's. Building a
    /// configuration from it fails for a hello this engine cannot reproduce.
    #[must_use]
    pub fn mirror_client_hello(&self, hello: &ClientHello) -> TlsClientConfig {
        TlsClientConfig::new_from_client_hello(hello)
            .with_unknown_values(UnknownValues::Drop)
            .with_grease_values(GreaseValues::Pinned)
    }
    fn cached_with_verification(
        request: ClientConfigRequest<'_>,
        verification: Option<&boring_crypto::ServerVerification>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let identity = reloadable_verification_identity(request, verification);
        let build = |config: &TlsClientConfig, options| {
            boring_crypto::QuicClientConfig::from_rama_with_verification(
                config,
                options,
                verification,
            )
        };
        request.get_or_build(
            identity,
            |config, options| {
                build(config, options).map(|native| ClientConfig::new(Arc::new(native)))
            },
            |config, options, peer, handshake| {
                build(config, options)?
                    .with_handshake(peer, handshake)
                    .map(|native| Some(ClientConfig::new(Arc::new(native))))
            },
        )
    }
}

#[cfg(feature = "boring")]
impl TlsClientConfigProvider for BoringTlsProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        BoringTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn pool_classifier(&self) -> ReuseKey {
        ReuseKey::of::<BoringTlsConnectorConfig>()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        BoringTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(feature = "boring")]
impl QuicClientConfigProvider for BoringTlsProvider {
    fn acquire_client_config(
        &self,
        request: ClientConfigRequest<'_>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let verification = request
            .native_cache(BoringServerTrustCache::new)
            .server_verification(request.config().as_extensions())?;
        Self::cached_with_verification(request, verification.as_ref())
    }

    fn acquire_client_config_async<'a>(
        &'a self,
        request: ClientConfigRequest<'a>,
    ) -> BoxFuture<'a, Result<Option<ClientConfig>, TlsConfigError>> {
        Box::pin(async move {
            let verification = request
                .native_cache(BoringServerTrustCache::new)
                .server_verification_async(request.config().as_extensions())
                .await?;
            Self::cached_with_verification(request, verification.as_ref())
        })
    }

    fn supports_ech(&self) -> bool {
        true
    }

    fn prepare_client_config(
        &self,
        policy: &TlsClientConfig,
        options: TlsOptions,
        peer: Host,
        handshake: ClientHandshake,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        boring_crypto::QuicClientConfig::prepare_client(policy, options, peer, handshake)
            .map(|config| Some(ClientConfig::new(Arc::new(config))))
    }

    fn allows_early_data(&self, extensions: &Extensions) -> bool {
        #[cfg(feature = "ua")]
        if has_captured_tls(extensions) {
            return false;
        }
        !extensions.contains::<BoringExtensionOrder>()
    }

    fn session_defaults(&self) -> Option<Extensions> {
        Some(boring_crypto::SharedClientSessions::defaults())
    }

    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        Ok(ClientConfig::new(Arc::new(
            boring_crypto::QuicClientConfig::from_rama(config, options)?,
        )))
    }

    fn peer_matches_name(
        &self,
        extensions: &Extensions,
        leaf: &CertificateDer<'_>,
        name: &Host,
    ) -> bool {
        BoringTlsConnectorConfig::from_extensions(extensions).peer_matches_name(leaf, name)
    }
}

#[cfg(feature = "boring")]
impl QuicServerConfigProvider for BoringTlsProvider {
    fn server_config(
        &self,
        config: &TlsServerConfig,
        options: TlsOptions,
    ) -> Result<ServerConfig, TlsConfigError> {
        Ok(ServerConfig::with_random_token_key(
            boring_crypto::server_config_from_rama(config, options)?,
        ))
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
        Ok(Arc::new(BoringTlsProvider::new()))
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
    use std::{
        assert_matches,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rama_core::error::{BoxError, BoxErrorExt as _};
    use rama_core::futures::stream;
    use rama_net::tls::ApplicationProtocol;
    use rama_tls::client::{
        ChannelReloadTrigger, NativeTrustPolicy, PlatformTrustPolicy, TlsServerTrust,
    };
    use rama_tls_boring::client::BoringGrease;
    use rama_tls_boring::core::x509::store::X509StoreBuilder;
    use rama_tls_rustls::client::ModifyRustlsClientConfig;
    use rama_tls_rustls::{client::RustlsClientConfigExt as _, verify::NoServerCertVerifier};
    use std::task::Poll;

    use super::*;
    use crate::tls::ClientConfigCache;

    #[test]
    fn native_settings_affect_only_the_selected_provider() {
        let rustls = RustlsTlsProvider::new(rustls_crypto::configured_provider());
        let boring = BoringTlsProvider::new();
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
        assert_matches!(
            rustls.client_config(&config, TlsOptions::default()),
            Err(TlsConfigError::InvalidConfiguration(_)),
        );
        boring
            .client_config(&config, TlsOptions::default())
            .unwrap();
    }

    #[test]
    fn native_reload_rotates_cached_quic_configs() {
        use rama_crypto::{native_certs::bundled_root_certs, pem::PemEncode as _};
        use std::{env, fs, path::PathBuf, process::Command};

        // Give the test its own SSL_CERT_FILE without mutating the test runner's environment.
        const CHILD: &str = "RAMA_TEST_QUIC_NATIVE_RELOAD";
        let Some(dir) = env::var_os(CHILD) else {
            let dir = rama_utils::fs::TempDir::new_sync().unwrap();
            let status = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tls::factory::tests::native_reload_rotates_cached_quic_configs",
                    "--nocapture",
                ])
                .env(CHILD, dir.path())
                .env("SSL_CERT_FILE", dir.path().join("roots.pem"))
                .env_remove("SSL_CERT_DIR")
                .env("SSL_CERT_EXTRA_FILE", dir.path().join("extras.pem"))
                .env_remove("SSL_CERT_EXTRA_DIR")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        };

        let dir = PathBuf::from(dir);
        let bundle = dir.join("roots.pem");
        let extras = dir.join("extras.pem");
        assert_eq!(
            env::var_os("SSL_CERT_FILE").as_deref(),
            Some(bundle.as_os_str())
        );
        let roots = bundled_root_certs();
        let caches = [
            ClientConfigCache::new(Arc::new(BoringTlsProvider::new()), TlsOptions::default()),
            ClientConfigCache::new(
                Arc::new(RustlsTlsProvider::new(rustls_crypto::configured_provider())),
                TlsOptions::default(),
            ),
        ];
        let request = Extensions::new();
        let (native_sender, native_trigger) = ChannelReloadTrigger::new();
        let (platform_sender, platform_trigger) = ChannelReloadTrigger::new();
        for (trust, sender, changed_file) in [
            (
                TlsServerTrust::from(NativeTrustPolicy::new().with_reload_trigger(native_trigger)),
                native_sender,
                &bundle,
            ),
            (
                TlsServerTrust::from(
                    PlatformTrustPolicy::new().with_reload_trigger(platform_trigger),
                ),
                platform_sender,
                &extras,
            ),
        ] {
            fs::write(&bundle, roots[0].to_pem()).unwrap();
            fs::write(&extras, b"").unwrap();
            let config = TlsClientConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_trust(trust);
            let initial = caches
                .each_ref()
                .map(|cache| cache.client_config(&config, &request).unwrap());
            // An explicit reread of identical roots preserves the backend configuration.
            sender.request_reload().unwrap();
            for (cache, old) in caches.iter().zip(&initial) {
                let repeated = cache.client_config(&config, &request).unwrap();
                assert!(Arc::ptr_eq(&old.crypto, &repeated.crypto));
            }

            fs::write(changed_file, roots[1].to_pem()).unwrap();
            sender.request_reload().unwrap();
            for (cache, old) in caches.iter().zip(&initial) {
                let current = cache.client_config(&config, &request).unwrap();
                assert!(!Arc::ptr_eq(&old.crypto, &current.crypto));
                let repeated = cache.client_config(&config, &request).unwrap();
                assert!(Arc::ptr_eq(&current.crypto, &repeated.crypto));
            }
        }
    }

    #[tokio::test]
    async fn native_verifier_overrides_skip_common_trust_reload() {
        let configs = [
            ClientConfigCache::new(Arc::new(BoringTlsProvider::new()), TlsOptions::default()),
            ClientConfigCache::new(
                Arc::new(RustlsTlsProvider::new(rustls_crypto::configured_provider())),
                TlsOptions::default(),
            ),
        ];
        let polls = Arc::new(AtomicUsize::new(0));
        let trigger = stream::poll_fn({
            let polls = polls.clone();
            move |_| {
                polls.fetch_add(1, Ordering::Relaxed);
                Poll::Pending
            }
        });
        let policy = NativeTrustPolicy::new().with_reload_trigger(trigger);
        let base = || {
            TlsClientConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_trust(policy.clone())
        };
        let overrides = [
            base()
                .with_server_verify_cert_store(Arc::new(X509StoreBuilder::new().unwrap().build())),
            base().with_cert_verifier(Arc::new(NoServerCertVerifier::new())),
        ];
        let request = Extensions::new();
        let peer = Host::from_static("example.test");
        for (cache, override_config) in configs.iter().zip(overrides) {
            let first = cache.client_config(&override_config, &request).unwrap();
            let next = cache
                .client_config_for_peer_async(override_config, &request, &peer)
                .await
                .unwrap();
            assert!(Arc::ptr_eq(&first.crypto, &next.crypto));
        }
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_caches_reuse_foreign_changes_and_apply_own_changes() {
        let rustls = ClientConfigCache::new(
            Arc::new(RustlsTlsProvider::new(rustls_crypto::configured_provider())),
            TlsOptions::default(),
        );
        let boring =
            ClientConfigCache::new(Arc::new(BoringTlsProvider::new()), TlsOptions::default());
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
        assert_matches!(
            rustls.client_config(&effective, &request),
            Err(TlsConfigError::InvalidConfiguration(_)),
        );
        let retained_boring = boring.client_config(&effective, &request).unwrap();
        assert!(Arc::ptr_eq(
            &replaced_boring.crypto,
            &retained_boring.crypto
        ));
    }
}
