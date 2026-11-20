//! Bounded reuse of native QUIC TLS configurations and their session state.

use std::{borrow::Cow, collections::VecDeque, fmt, num::NonZeroUsize, sync::Arc};

use parking_lot::Mutex;
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use rama_core::extensions::Extension;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
};
use rama_net::{address::Host, client::pool::ReuseKey, tls::AlpnPolicy};
use rama_tls::client::{
    EchRequirement, TlsClientConfig, TlsEncryptedClientHello, TlsPoolId, TlsServerName,
};

use super::{
    ClientHandshake, ClientSessionPolicy, QuicClientConfigProvider, TlsConfigError, TlsOptions,
};
use crate::ClientConfig;
// Keep native override configurations bounded alongside the protected default context.
const MAX_CACHED_OVERRIDES: usize = 64;

/// Reuse native TLS configuration and session state when opening QUIC connections.
///
/// A cache belongs to one provider and fixed QUIC TLS defaults. An explicit
/// [`AlpnPolicy`] in the common TLS configuration overrides the ALPN default.
/// Clones share its
/// state: one protected default entry and up to 64 recently used override entries.
/// Shared custom components retain session state. Request policies explicitly
/// marked non-reusable bypass caching. Failed builds are never retained. Providers
/// must identify changed defaults, or keep them fixed for the cache's lifetime.
///
/// This does not pool connections or apply request overrides. Supply the final
/// TLS configuration to [`Self::client_config`], then customize transport settings
/// on the returned [`ClientConfig`] as needed. For reloadable trust, obtain a new
/// result for each connection. Each result is an independent clone
/// sharing the native TLS configuration and its session state. Providers can also
/// share a bounded, policy-keyed ticket store across sibling native configurations.
/// Fresh client policies still cache native configurations, but skip provider
/// ticket defaults and require the provider to disable ticket storage and offers.
#[derive(Clone)]
pub struct ClientConfigCache {
    provider: Arc<dyn QuicClientConfigProvider>,
    options: TlsOptions,
    state: Arc<CacheState>,
}

struct CacheState {
    configs: Mutex<Configs>,
    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    native: Extensions,
    server_trust_cache_capacity: Option<NonZeroUsize>,
}

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
#[derive(Debug)]
struct NativeCache<T>(T);

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
impl<T: fmt::Debug + Send + Sync + 'static> Extension for NativeCache<T> {}

impl fmt::Debug for ClientConfigCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigCache")
            .field("provider", &self.provider)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl ClientConfigCache {
    fn needs_endpoint_ech(&self, config: &TlsClientConfig) -> bool {
        let ext = config.as_extensions();
        ext.get_ref::<EchRequirement>() == Some(&EchRequirement::Required)
            || (self.provider.supports_ech()
                && ext
                    .get_ref::<TlsEncryptedClientHello>()
                    .is_none_or(|intent| intent.0)
                && ext.contains::<rama_net::tls::TargetEchConfig>())
    }

    fn effective_options(&self, config: &TlsClientConfig) -> TlsOptions {
        let options = if self.needs_endpoint_ech(config) {
            self.options.with_early_data(false)
        } else {
            self.options
        };
        let options = config
            .as_extensions()
            .get_ref::<AlpnPolicy>()
            .map_or(options, |policy| options.with_alpn(*policy));

        if self.provider.allows_early_data(config.as_extensions()) {
            options
        } else {
            options.with_early_data(false)
        }
    }

    pub(crate) fn allows_early_data(&self, config: &TlsClientConfig) -> bool {
        self.effective_options(config).early_data
    }

    /// Bind cached configurations to one provider and its QUIC TLS options.
    pub fn new(provider: Arc<dyn QuicClientConfigProvider>, options: TlsOptions) -> Self {
        Self::new_with_capacity(provider, options, None)
    }

    fn new_with_capacity(
        provider: Arc<dyn QuicClientConfigProvider>,
        options: TlsOptions,
        capacity: Option<NonZeroUsize>,
    ) -> Self {
        let session_defaults = match options.client_sessions {
            ClientSessionPolicy::Reuse => provider.session_defaults(),
            ClientSessionPolicy::Fresh => None,
        };
        Self {
            provider,
            options,
            state: Arc::new(CacheState {
                configs: Mutex::new(Configs {
                    session_defaults,
                    ..Configs::default()
                }),
                #[cfg(any(
                    feature = "boring",
                    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
                ))]
                native: Extensions::new(),
                server_trust_cache_capacity: capacity,
            }),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the capacity of the connector's native server trust cache.
        /// Built-in providers retain up to eight derived stores by default.
        pub fn server_trust_cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.state = Self::new_with_capacity(self.provider.clone(), self.options, Some(capacity)).state;
            self
        }
    }

    pub(crate) fn with_options(&self, options: TlsOptions) -> Self {
        Self::new_with_capacity(
            self.provider.clone(),
            options,
            self.state.server_trust_cache_capacity,
        )
    }

    /// The provider used both to classify policies and to construct configurations.
    pub fn provider(&self) -> &Arc<dyn QuicClientConfigProvider> {
        &self.provider
    }

    /// Prepare a peer-bound handshake with this connector's ticket domain and
    /// options. Prepared state bypasses the ordinary configuration cache; only
    /// backend session metadata is shared.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "keep the existing public peer-bound construction signature"
    )]
    pub fn prepare_client_config(
        &self,
        config: &TlsClientConfig,
        peer: Host,
        handshake: ClientHandshake,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let overrides = Extensions::new();
        let mut request = self.request(config, &overrides, Some(&peer));
        request.handshake = Some(handshake);
        self.provider.acquire_client_config(request)
    }

    /// Build or reuse the final TLS configuration, classified by this cache's provider.
    ///
    /// `overrides` contains request settings before connector defaults are applied.
    /// It selects the protected default slot or bounded override cache and makes
    /// explicitly non-reusable request policies bypass caching even if masked later.
    /// The key combines the request identity with the effective configuration
    /// identity, including final application requirements such as ALPN. Defaults
    /// are checked on each call; any defaults omitted from the identity must remain
    /// fixed. Provider classification must cover every relevant setting.
    ///
    /// Provider code runs outside the cache lock. Concurrent equivalent builds
    /// may do redundant work, but converge on the same retained configuration.
    pub fn client_config(
        &self,
        config: &TlsClientConfig,
        overrides: &Extensions,
    ) -> Result<ClientConfig, TlsConfigError> {
        let request = self.request(config, overrides, None);
        request.require(self.provider.acquire_client_config(request)?)
    }

    /// Build native TLS for `peer`, applying any explicit handshake-offer policy.
    /// The configured provider and ticket domain remain authoritative. A provider
    /// without that capability returns an error instead of silently ignoring it.
    /// Peer-bound prepared sessions bypass the ordinary configuration cache.
    pub fn client_config_for_peer(
        &self,
        config: &TlsClientConfig,
        overrides: &Extensions,
        peer: &Host,
    ) -> Result<ClientConfig, TlsConfigError> {
        let request = self.request(config, overrides, Some(peer));
        request.require(self.provider.acquire_client_config(request)?)
    }

    pub(crate) async fn client_config_for_peer_async(
        &self,
        config: TlsClientConfig,
        overrides: &Extensions,
        peer: &Host,
    ) -> Result<ClientConfig, TlsConfigError> {
        let request = self.request(&config, overrides, Some(peer));
        request.require(self.provider.acquire_client_config_async(request).await?)
    }

    fn request<'a>(
        &'a self,
        config: &'a TlsClientConfig,
        overrides: &'a Extensions,
        peer: Option<&'a Host>,
    ) -> ClientConfigRequest<'a> {
        ClientConfigRequest {
            cache: self,
            config,
            overrides,
            peer,
            handshake: None,
        }
    }
}

/// A single client configuration lookup, bound to the connector's provider and cache.
/// The cache passes this request to its provider for each new connection.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ClientConfigRequest<'a> {
    cache: &'a ClientConfigCache,
    config: &'a TlsClientConfig,
    overrides: &'a Extensions,
    peer: Option<&'a Host>,
    handshake: Option<ClientHandshake>,
}

impl<'a> ClientConfigRequest<'a> {
    fn require(&self, config: Option<ClientConfig>) -> Result<ClientConfig, TlsConfigError> {
        config.ok_or_else(|| {
            TlsConfigError::InvalidConfiguration(BoxError::from_static_str(
                if self.cache.needs_endpoint_ech(self.config) {
                    "TLS provider cannot prepare endpoint ECH"
                } else {
                    "TLS provider does not support the requested QUIC handshake policy"
                },
            ))
        })
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    pub(super) fn native_cache<T: Default + fmt::Debug + Send + Sync + 'static>(
        &self,
        new: fn(NonZeroUsize) -> T,
    ) -> &'a T {
        let state = &self.cache.state;
        if let Some(cache) = state.native.get_ref::<NativeCache<T>>() {
            return &cache.0;
        }
        // Serialize initial publication so concurrent handshakes share one cache.
        let _lock = state.configs.lock();
        &state
            .native
            .self_get_ref_or_insert(|| {
                NativeCache(
                    state
                        .server_trust_cache_capacity
                        .map_or_else(T::default, new),
                )
            })
            .0
    }

    /// The effective TLS policy requested by the connection.
    pub fn config(&self) -> &'a TlsClientConfig {
        self.config
    }

    /// Build or reuse a native configuration. The optional key supplements the
    /// request and effective policy identities with provider-specific state.
    /// Use a value key for a logical revision or an owning key for a shared object.
    ///
    /// The ordinary builder runs on cache misses and for nonreusable policies.
    /// The peer-bound builder runs for endpoint ECH or explicit session offers;
    /// its result belongs to the specified peer and bypasses this cache.
    /// A peer-bound builder can return `None` when it cannot serve that request.
    pub fn get_or_build(
        self,
        identity: Option<ReuseKey>,
        build: impl FnOnce(&TlsClientConfig, TlsOptions) -> Result<ClientConfig, TlsConfigError>,
        prepare: impl FnOnce(
            &TlsClientConfig,
            TlsOptions,
            Host,
            ClientHandshake,
        ) -> Result<Option<ClientConfig>, TlsConfigError>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        let Self {
            cache,
            config,
            overrides,
            peer,
            handshake: explicit,
        } = self;
        let options = cache.effective_options(config);
        let handshake = explicit.unwrap_or_else(|| {
            config
                .as_extensions()
                .get_ref::<ClientHandshake>()
                .copied()
                .unwrap_or_default()
        });
        let ech = cache.needs_endpoint_ech(config);
        if explicit.is_some() || ech || handshake != ClientHandshake::Auto {
            let peer = peer
                .or_else(|| {
                    config
                        .as_extensions()
                        .get_ref::<TlsServerName>()
                        .map(|name| &name.0)
                })
                .ok_or_else(|| {
                    TlsConfigError::InvalidConfiguration(BoxError::from_static_str(if ech {
                        "endpoint ECH requires a peer identity"
                    } else {
                        "an explicit QUIC handshake policy requires a destination"
                    }))
                })?;
            let defaults = cache.state.configs.lock().session_defaults.clone();
            return prepare(
                &scoped_config(config, defaults.as_ref()),
                options,
                peer.clone(),
                handshake,
            );
        }
        let request_policy = cache.provider.pool_id(overrides);
        let effective_policy = cache.provider.pool_id(config.as_extensions());
        if request_policy.as_ref().is_some_and(|id| !id.is_reusable()) {
            return build(config, options).map(Some);
        }

        // An opaque default is scoped to this cache, not shared across connectors.
        // Keep comparable request overrides distinct even if the effective ID is opaque.
        let is_default = request_policy.is_none();
        let policy = (
            request_policy,
            effective_policy,
            identity,
            options.early_data,
        );
        let session_defaults = {
            let mut configs = cache.state.configs.lock();
            if let Some(config) = configs.get(&policy, is_default) {
                return Ok(Some(config));
            }
            configs.session_defaults.clone()
        };
        let config = build(&scoped_config(config, session_defaults.as_ref()), options)?;
        let mut configs = cache.state.configs.lock();
        if let Some(existing) = configs.get(&policy, is_default) {
            return Ok(Some(existing));
        }
        configs.insert(policy, is_default, config.clone());
        Ok(Some(config))
    }
}

fn scoped_config<'a>(
    config: &'a TlsClientConfig,
    defaults: Option<&Extensions>,
) -> Cow<'a, TlsClientConfig> {
    if let Some(defaults) = defaults {
        let scoped = config.clone();
        scoped.as_extensions().extend(defaults);
        Cow::Owned(scoped)
    } else {
        Cow::Borrowed(config)
    }
}

type Policy = (Option<TlsPoolId>, Option<TlsPoolId>, Option<ReuseKey>, bool);

struct Entry {
    policy: Policy,
    config: ClientConfig,
}

#[derive(Default)]
struct Configs {
    session_defaults: Option<Extensions>,
    default: Option<Entry>,
    overrides: VecDeque<Entry>,
}

impl Configs {
    fn get(&mut self, policy: &Policy, is_default: bool) -> Option<ClientConfig> {
        if is_default {
            return self
                .default
                .as_ref()
                .filter(|entry| &entry.policy == policy)
                .map(|entry| entry.config.clone());
        }
        let index = self
            .overrides
            .iter()
            .position(|entry| &entry.policy == policy)?;
        let entry = self.overrides.remove(index)?;
        let config = entry.config.clone();
        self.overrides.push_front(entry);
        Some(config)
    }

    fn insert(&mut self, policy: Policy, is_default: bool, config: ClientConfig) {
        let entry = Entry { policy, config };
        if is_default {
            self.default = Some(entry);
        } else {
            if self.overrides.len() == MAX_CACHED_OVERRIDES {
                self.overrides.pop_back();
            }
            self.overrides.push_front(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Barrier, Weak,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    use rama_core::extensions::Extension;
    use rama_crypto::pki_types::CertificateDer;
    use rama_net::{address::Host, client::pool::ReuseKey, tls::TlsAlpn};
    use rama_quic_proto::{Version, transport_parameters::TransportParameters};
    use rama_tls::{
        KeyLogIntent, TlsKeyLog,
        client::{TlsClientConfigProvider, TlsServerName},
        keylog::NoopKeyLogSink,
    };
    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    use {rama_core::futures::stream, rama_tls::client::NativeTrustPolicy, std::task::Poll};

    use super::*;
    use crate::{
        ConnectError, TransportConfig,
        tls::provider::{ClientConfig as CryptoClientConfig, Session},
    };

    struct TestCrypto;

    impl CryptoClientConfig for TestCrypto {
        fn start_session(
            self: Arc<Self>,
            _: Version,
            _: &str,
            _: &TransportParameters,
        ) -> Result<Box<dyn Session>, ConnectError> {
            Err(ConnectError::EndpointStopping)
        }

        fn supports_version_switch(&self) -> bool {
            false
        }

        fn resumable_version(&self, _: &str) -> Option<Version> {
            None
        }
    }

    #[derive(Debug, Extension)]
    struct OpaquePolicy;

    #[derive(Default)]
    struct TestProvider {
        calls: AtomicUsize,
        defaults_calls: AtomicUsize,
        fail_next: AtomicBool,
        alpn_policies: Mutex<Vec<AlpnPolicy>>,
        rendezvous: Option<Barrier>,
        cache: Mutex<Weak<CacheState>>,
    }

    impl fmt::Debug for TestProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestProvider").finish_non_exhaustive()
        }
    }

    impl TlsClientConfigProvider for TestProvider {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            if extensions.contains::<OpaquePolicy>() {
                return Some(TlsPoolId::non_reusable());
            }
            TlsPoolId::builder()
                .maybe_with_server_name(extensions.get_ref::<TlsServerName>())
                .maybe_with_alpn(extensions.get_ref::<TlsAlpn>())
                .maybe_with_alpn_policy(extensions.get_ref::<AlpnPolicy>())
                .maybe_with_keylog(extensions.get_ref::<TlsKeyLog>())
                .build()
        }

        fn pool_classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn authenticates_server(&self, _: &Extensions) -> bool {
            true
        }
    }

    impl QuicClientConfigProvider for TestProvider {
        fn supports_ech(&self) -> bool {
            true
        }

        fn prepare_client_config(
            &self,
            policy: &TlsClientConfig,
            options: TlsOptions,
            _: Host,
            _: ClientHandshake,
        ) -> Result<Option<ClientConfig>, TlsConfigError> {
            if policy
                .as_extensions()
                .contains::<rama_net::tls::TargetEchConfig>()
            {
                self.client_config(policy, options).map(Some)
            } else {
                Ok(None)
            }
        }

        fn peer_matches_name(&self, _: &Extensions, _: &CertificateDer<'_>, _: &Host) -> bool {
            false
        }

        fn session_defaults(&self) -> Option<Extensions> {
            self.defaults_calls.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn client_config(
            &self,
            _: &TlsClientConfig,
            options: TlsOptions,
        ) -> Result<ClientConfig, TlsConfigError> {
            self.alpn_policies.lock().push(options.alpn);
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_next.swap(false, Ordering::Relaxed) {
                return Err(TlsConfigError::BackendUnavailable);
            }
            let cache = self.cache.lock().upgrade();
            if let Some(cache) = cache {
                assert!(
                    cache.configs.try_lock().is_some(),
                    "provider must run outside the cache lock"
                );
            }
            if let Some(barrier) = &self.rendezvous {
                barrier.wait();
            }
            Ok(ClientConfig::new(Arc::new(TestCrypto)))
        }
    }

    fn named(index: usize) -> TlsClientConfig {
        TlsClientConfig::new()
            .with_server_name(Host::try_from(format!("host-{index}.example")).unwrap())
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    #[tokio::test]
    async fn a_custom_provider_does_not_poll_common_trust_reload() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let polls = Arc::new(AtomicUsize::new(0));
        let trigger = stream::poll_fn({
            let polls = polls.clone();
            move |_| {
                polls.fetch_add(1, Ordering::Relaxed);
                Poll::Pending
            }
        });
        let config =
            named(0).with_server_trust(NativeTrustPolicy::new().with_reload_trigger(trigger));
        let peer = Host::from_static("host-0.example");
        let overrides = Extensions::new();
        let first = cache
            .client_config_for_peer(&config, &overrides, &peer)
            .unwrap();
        let second = cache
            .client_config_for_peer_async(config, &overrides, &peer)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first.crypto, &second.crypto));
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    #[test]
    fn connector_clones_share_their_native_store_cache_and_capacity() {
        #[derive(Debug, Default)]
        struct Store(usize);
        fn new_store(capacity: NonZeroUsize) -> Store {
            Store(capacity.get())
        }
        let provider = Arc::new(TestProvider::default());
        let first = ClientConfigCache::new(provider.clone(), TlsOptions::default())
            .with_server_trust_cache_capacity(NonZeroUsize::new(3).unwrap())
            .with_options(TlsOptions::default());
        let clone = first.clone();
        let other = ClientConfigCache::new(provider, TlsOptions::default());
        let config = named(0);
        let overrides = Extensions::new();
        let a = first
            .request(&config, &overrides, None)
            .native_cache(new_store);
        let b = clone
            .request(&config, &overrides, None)
            .native_cache(new_store);
        let c = other
            .request(&config, &overrides, None)
            .native_cache(new_store);
        assert_eq!(a.0, 3);
        assert_eq!(c.0, 0);
        assert!(std::ptr::eq(a, b));
        assert!(!std::ptr::eq(a, c));
    }

    #[test]
    fn custom_provider_revisions_are_cached_only_by_the_owning_connector() {
        #[derive(Debug, Default)]
        struct RevisionProvider {
            revision: AtomicUsize,
            builds: AtomicUsize,
        }

        impl TlsClientConfigProvider for RevisionProvider {
            fn pool_id(&self, _: &Extensions) -> Option<TlsPoolId> {
                None
            }
            fn pool_classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }
            fn authenticates_server(&self, _: &Extensions) -> bool {
                false
            }
        }

        impl QuicClientConfigProvider for RevisionProvider {
            fn acquire_client_config(
                &self,
                request: ClientConfigRequest<'_>,
            ) -> Result<Option<ClientConfig>, TlsConfigError> {
                let revision = self.revision.load(Ordering::Relaxed);
                request.get_or_build(
                    Some(ReuseKey::from_bits::<Self>(revision as u128)),
                    |config, options| self.client_config(config, options),
                    |config, options, peer, handshake| {
                        self.prepare_client_config(config, options, peer, handshake)
                    },
                )
            }
            fn client_config(
                &self,
                _: &TlsClientConfig,
                _: TlsOptions,
            ) -> Result<ClientConfig, TlsConfigError> {
                self.builds.fetch_add(1, Ordering::Relaxed);
                Ok(ClientConfig::new(Arc::new(TestCrypto)))
            }
            fn peer_matches_name(&self, _: &Extensions, _: &CertificateDer<'_>, _: &Host) -> bool {
                false
            }
        }

        let first = Arc::new(RevisionProvider::default());
        let second = Arc::new(RevisionProvider::default());
        let a = ClientConfigCache::new(first.clone(), TlsOptions::default());
        let b = ClientConfigCache::new(second.clone(), TlsOptions::default());
        let config = named(0);
        let overrides = Extensions::new();
        let lookup =
            |cache: &ClientConfigCache| cache.client_config(&config, &overrides).unwrap().crypto;
        let before = lookup(&a);
        let other = lookup(&b);
        assert!(Arc::ptr_eq(&before, &lookup(&a)));
        assert!(!Arc::ptr_eq(&before, &other));
        first.revision.store(1, Ordering::Relaxed);
        let after = lookup(&a);
        assert!(!Arc::ptr_eq(&before, &after));
        assert!(Arc::ptr_eq(&after, &lookup(&a)));
        assert!(Arc::ptr_eq(&other, &lookup(&b)));
        assert_eq!(first.builds.load(Ordering::Relaxed), 2);
        assert_eq!(second.builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn alpn_policy_overrides_reach_provider_and_partition_cached_configs() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(
            provider.clone(),
            TlsOptions::default().with_alpn(AlpnPolicy::OutOfBandAgreement),
        );
        for policy in [
            None,
            Some(AlpnPolicy::Require),
            Some(AlpnPolicy::OutOfBandAgreement),
            None,
            Some(AlpnPolicy::Require),
        ] {
            let mut config = TlsClientConfig::new();
            if let Some(policy) = policy {
                config.set_alpn_policy(policy);
            }
            cache
                .client_config(&config, config.as_extensions())
                .unwrap();
        }
        assert_eq!(provider.calls.load(Ordering::Relaxed), 3);
        assert_eq!(
            *provider.alpn_policies.lock(),
            [
                AlpnPolicy::OutOfBandAgreement,
                AlpnPolicy::Require,
                AlpnPolicy::OutOfBandAgreement
            ]
        );
    }

    #[test]
    fn fresh_cache_skips_provider_session_defaults() {
        let provider = Arc::new(TestProvider::default());
        let _ordinary = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        assert_eq!(provider.defaults_calls.load(Ordering::Relaxed), 1);
        for _ in 0..8 {
            let _fresh = ClientConfigCache::new(
                provider.clone(),
                TlsOptions::default().with_client_sessions(ClientSessionPolicy::Fresh),
            );
        }
        assert_eq!(provider.defaults_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn overrides_are_lru_bounded_and_cannot_evict_default_session_state() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider, TlsOptions::default());
        let defaults = TlsClientConfig::new();
        let default = cache
            .client_config(&defaults, defaults.as_extensions())
            .unwrap();
        let config = named(0);
        let oldest = cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        let mut next_oldest = None;
        for index in 1..MAX_CACHED_OVERRIDES {
            let config = named(index);
            let native = cache
                .client_config(&config, config.as_extensions())
                .unwrap();
            if index == 1 {
                next_oldest = Some(native);
            }
        }
        // Refresh the oldest entry; the next oldest must be evicted instead.
        let config = named(0);
        let retained = cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        assert!(Arc::ptr_eq(&oldest.crypto, &retained.crypto));
        let config = named(MAX_CACHED_OVERRIDES);
        cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        assert_eq!(
            cache.state.configs.lock().overrides.len(),
            MAX_CACHED_OVERRIDES
        );
        let retained = cache
            .client_config(&defaults, defaults.as_extensions())
            .unwrap();
        assert!(Arc::ptr_eq(&default.crypto, &retained.crypto));
        let config = named(1);
        let rebuilt = cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        assert!(!Arc::ptr_eq(&next_oldest.unwrap().crypto, &rebuilt.crypto));
    }

    #[test]
    fn comparable_defaults_invalidate_and_opaque_requests_bypass_the_cache() {
        let cache =
            ClientConfigCache::new(Arc::new(TestProvider::default()), TlsOptions::default());
        let overrides = Extensions::new();
        let config = named(0);
        let original = cache.client_config(&config, &overrides).unwrap();
        config
            .as_extensions()
            .insert(TlsServerName(Host::from_static("changed.example")));
        let changed = cache.client_config(&config, &overrides).unwrap();
        assert!(!Arc::ptr_eq(&original.crypto, &changed.crypto));

        // Even an opaque request override masked by final settings cannot share state.
        overrides.insert(OpaquePolicy);
        let first = cache.client_config(&config, &overrides).unwrap();
        let second = cache.client_config(&config, &overrides).unwrap();
        assert!(!Arc::ptr_eq(&first.crypto, &second.crypto));
    }

    #[test]
    fn fixed_opaque_defaults_retain_sessions_without_merging_request_policies() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let config = TlsClientConfig::new();
        config.as_extensions().insert(OpaquePolicy);
        let original = cache.client_config(&config, &Extensions::new()).unwrap();
        let repeated = cache.client_config(&config, &Extensions::new()).unwrap();
        assert!(Arc::ptr_eq(&original.crypto, &repeated.crypto));
        let overrides = named(0);
        let effective = config.clone().with_overrides(overrides.as_extensions());
        let changed = cache
            .client_config(&effective, overrides.as_extensions())
            .unwrap();
        let repeated = cache
            .client_config(&effective, overrides.as_extensions())
            .unwrap();
        assert!(Arc::ptr_eq(&changed.crypto, &repeated.crypto));
        assert!(!Arc::ptr_eq(&original.crypto, &changed.crypto));
        let defaults = cache.client_config(&config, &Extensions::new()).unwrap();
        assert!(Arc::ptr_eq(&original.crypto, &defaults.crypto));
        assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn shared_components_retain_session_state_and_replacements_invalidate_it() {
        let cache =
            ClientConfigCache::new(Arc::new(TestProvider::default()), TlsOptions::default());
        let sink = Arc::new(NoopKeyLogSink);
        let config = TlsClientConfig::new().with_keylog(KeyLogIntent::Custom(sink.clone()));
        let first = cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        let clone = TlsClientConfig::new().with_keylog(KeyLogIntent::Custom(sink));
        let repeated = cache.client_config(&clone, clone.as_extensions()).unwrap();
        assert!(Arc::ptr_eq(&first.crypto, &repeated.crypto));
        let changed =
            TlsClientConfig::new().with_keylog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        let replacement = cache
            .client_config(&changed, changed.as_extensions())
            .unwrap();
        assert!(!Arc::ptr_eq(&first.crypto, &replacement.crypto));

        // Effective connector defaults must also notice a replaced component.
        let defaults = Extensions::new();
        let first = cache.client_config(&config, &defaults).unwrap();
        let replacement = cache.client_config(&changed, &defaults).unwrap();
        assert!(!Arc::ptr_eq(&first.crypto, &replacement.crypto));
    }

    #[test]
    fn opportunistic_endpoint_ech_is_uncached_and_disables_early_data() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider, TlsOptions::default().with_early_data(true));
        let tls = TlsClientConfig::new().with_server_name(Host::from_static("origin.example"));
        tls.as_extensions()
            .insert(rama_net::tls::TargetEchConfig::new(
                "origin.example:443".parse().unwrap(),
                vec![0, 1, 2],
            ));
        assert!(!cache.allows_early_data(&tls));
        let first = cache.client_config(&tls, tls.as_extensions()).unwrap();
        let second = cache.client_config(&tls, tls.as_extensions()).unwrap();
        assert!(!Arc::ptr_eq(&first.crypto, &second.crypto));
        tls.as_extensions().insert(TlsEncryptedClientHello(false));
        assert!(cache.allows_early_data(&tls));
        let first = cache.client_config(&tls, tls.as_extensions()).unwrap();
        let second = cache.client_config(&tls, tls.as_extensions()).unwrap();
        assert!(Arc::ptr_eq(&first.crypto, &second.crypto));
    }

    #[test]
    fn failed_builds_are_retried_and_transport_customization_stays_local() {
        let provider = Arc::new(TestProvider::default());
        provider.fail_next.store(true, Ordering::Relaxed);
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let tls = TlsClientConfig::new();
        cache.client_config(&tls, tls.as_extensions()).unwrap_err();
        let mut first = cache.client_config(&tls, tls.as_extensions()).unwrap();
        let transport = Arc::new(TransportConfig::default());
        first.set_transport_config(transport.clone());
        let second = cache.client_config(&tls, tls.as_extensions()).unwrap();
        assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
        assert!(Arc::ptr_eq(&first.crypto, &second.crypto));
        assert!(!Arc::ptr_eq(&second.transport, &transport));
    }

    #[test]
    fn providers_and_tls_options_have_independent_session_state() {
        let provider = Arc::new(TestProvider::default());
        let ordinary = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let early = ClientConfigCache::new(provider, TlsOptions::default().with_early_data(true));
        let other =
            ClientConfigCache::new(Arc::new(TestProvider::default()), TlsOptions::default());
        let tls = TlsClientConfig::new();
        let ordinary = ordinary.client_config(&tls, tls.as_extensions()).unwrap();
        for cache in [early, other] {
            let config = cache.client_config(&tls, tls.as_extensions()).unwrap();
            assert!(!Arc::ptr_eq(&ordinary.crypto, &config.crypto));
        }
    }

    #[test]
    fn provider_runs_without_holding_the_cache_lock() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        *provider.cache.lock() = Arc::downgrade(&cache.state);
        let tls = TlsClientConfig::new();
        cache.client_config(&tls, tls.as_extensions()).unwrap();
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn concurrent_builds_converge() {
        let provider = Arc::new(TestProvider {
            rendezvous: Some(Barrier::new(2)),
            ..Default::default()
        });
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        // A try_lock in either provider call could observe the other caller's
        // cache lookup. Check lock ownership separately, without competing threads.
        let clone = cache.clone();
        let tls = TlsClientConfig::new();
        let (first, second) = thread::scope(|scope| {
            let first = scope.spawn(|| cache.client_config(&tls, tls.as_extensions()).unwrap());
            let second = scope.spawn(|| clone.client_config(&tls, tls.as_extensions()).unwrap());
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
        assert!(Arc::ptr_eq(&first.crypto, &second.crypto));
    }

    #[test]
    fn automatic_handshake_policy_uses_the_ordinary_configuration_cache() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let config = TlsClientConfig::new().with_client_handshake(ClientHandshake::Auto);
        let first = cache
            .client_config(&config, config.as_extensions())
            .unwrap();
        let second = cache
            .client_config_for_peer(
                &config,
                config.as_extensions(),
                &Host::from_static("localhost"),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first.crypto, &second.crypto));
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn native_handshake_policy_cannot_fall_back_to_an_ordinary_client() {
        let provider = Arc::new(TestProvider::default());
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        let peer = Host::try_from("localhost").unwrap();
        for handshake in [ClientHandshake::Full, ClientHandshake::Resumed] {
            let config = named(0);
            config.as_extensions().insert(handshake);
            cache
                .client_config_for_peer(&config, config.as_extensions(), &peer)
                .unwrap_err();
            cache
                .client_config(&config, config.as_extensions())
                .unwrap_err();

            let unnamed = TlsClientConfig::new();
            unnamed.as_extensions().insert(handshake);
            cache
                .client_config(&unnamed, unnamed.as_extensions())
                .unwrap_err();
        }
        assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
        assert!(cache.state.configs.lock().default.is_none());
        assert!(cache.state.configs.lock().overrides.is_empty());
    }

    #[cfg(feature = "boring")]
    #[test]
    fn early_options_are_explicit_and_pinned_client_hello_shapes_win() {
        use crate::tls::BoringTlsProvider;
        use rama_tls_boring::client::BoringExtensionOrder;

        let tls = TlsClientConfig::new();
        let ordinary =
            ClientConfigCache::new(Arc::new(BoringTlsProvider::new()), TlsOptions::default());
        assert!(!ordinary.allows_early_data(&tls));
        let early = ClientConfigCache::new(
            Arc::new(BoringTlsProvider::new()),
            TlsOptions::default().with_early_data(true),
        );
        assert!(early.allows_early_data(&tls));
        tls.as_extensions().insert(BoringExtensionOrder(Vec::new()));
        assert!(!early.allows_early_data(&tls));
    }
}
