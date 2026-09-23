//! Bounded reuse of native QUIC TLS configurations and their session state.

use super::{QuicClientConfigProvider, TlsConfigError, TlsOptions};
use crate::ClientConfig;
use parking_lot::Mutex;
use rama_core::extensions::Extensions;
use rama_tls::client::{TlsClientConfig, TlsPoolId};
use std::{collections::VecDeque, fmt, sync::Arc};

// Keep uncommon policies bounded without letting them evict default session state.
const MAX_CACHED_OVERRIDES: usize = 64;

/// Reuse native TLS configuration and session state when opening QUIC connections.
///
/// A cache belongs to one provider and fixed QUIC TLS options. Clones share its
/// state: one protected default entry and up to 64 recently used override entries.
/// Opaque policies bypass caching, and failed builds are never retained.
/// Provider defaults must remain fixed for the cache's lifetime; dynamic policy
/// must be represented in its identity or classified as non-reusable.
///
/// This does not pool connections or apply request overrides. Supply the final
/// TLS configuration to [`Self::client_config`], then customize transport settings
/// on the returned [`ClientConfig`] as needed; each result is an independent clone
/// sharing the native TLS configuration and its session state.
#[derive(Clone)]
pub struct ClientConfigCache {
    provider: Arc<dyn QuicClientConfigProvider>,
    options: TlsOptions,
    configs: Arc<Mutex<Configs>>,
}

impl fmt::Debug for ClientConfigCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigCache")
            .field("provider", &self.provider)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl ClientConfigCache {
    /// Bind cached configurations to one provider and its QUIC TLS options.
    pub fn new(provider: Arc<dyn QuicClientConfigProvider>, options: TlsOptions) -> Self {
        Self {
            provider,
            options,
            configs: Arc::default(),
        }
    }

    /// The provider used both to classify policies and to construct configurations.
    pub fn provider(&self) -> &Arc<dyn QuicClientConfigProvider> {
        &self.provider
    }

    /// Build or reuse the final TLS configuration, classified by this cache's provider.
    ///
    /// `overrides` contains request settings before connector defaults are applied.
    /// It selects the protected default slot or bounded override cache and makes
    /// opaque request policies bypass caching even if later settings mask them.
    /// The cache key always describes `config`, including defaults and any final
    /// application requirements such as ALPN. Changed defaults cannot reuse stale
    /// configuration. Provider classification must include every relevant setting.
    ///
    /// Provider code runs outside the cache lock. Concurrent equivalent builds
    /// may do redundant work, but converge on the same retained configuration.
    pub fn client_config(
        &self,
        config: &TlsClientConfig,
        overrides: &Extensions,
    ) -> Result<ClientConfig, TlsConfigError> {
        let request_policy = self.provider.pool_id(overrides);
        let effective_policy = self.provider.pool_id(config.as_extensions());
        if request_policy.is_some_and(|id| !id.is_reusable())
            || effective_policy.is_some_and(|id| !id.is_reusable())
        {
            return self.provider.client_config(config, self.options);
        }

        let is_default = request_policy.is_none();
        if let Some(config) = self.configs.lock().get(effective_policy, is_default) {
            return Ok(config);
        }

        let config = self.provider.client_config(config, self.options)?;
        let mut configs = self.configs.lock();
        if let Some(existing) = configs.get(effective_policy, is_default) {
            return Ok(existing);
        }
        configs.insert(effective_policy, is_default, config.clone());
        Ok(config)
    }
}

struct Entry {
    policy: Option<TlsPoolId>,
    config: ClientConfig,
}

#[derive(Default)]
struct Configs {
    default: Option<Entry>,
    overrides: VecDeque<Entry>,
}

impl Configs {
    fn get(&mut self, policy: Option<TlsPoolId>, is_default: bool) -> Option<ClientConfig> {
        if is_default {
            return self
                .default
                .as_ref()
                .filter(|entry| entry.policy == policy)
                .map(|entry| entry.config.clone());
        }
        let index = self
            .overrides
            .iter()
            .position(|entry| entry.policy == policy)?;
        let entry = self.overrides.remove(index)?;
        let config = entry.config.clone();
        self.overrides.push_front(entry);
        Some(config)
    }

    fn insert(&mut self, policy: Option<TlsPoolId>, is_default: bool, config: ClientConfig) {
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
    use super::*;
    use crate::{
        ConnectError, TransportConfig,
        tls::provider::{ClientConfig as CryptoClientConfig, Session},
    };
    use rama_core::extensions::Extension;
    use rama_net::{address::Host, tls::TlsAlpn};
    use rama_quic_proto::{Version, transport_parameters::TransportParameters};
    use rama_tls::client::{TlsClientConfigProvider, TlsServerName};
    use std::{
        sync::{
            Barrier, Weak,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
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
    }

    #[derive(Debug, Extension)]
    struct OpaquePolicy;

    #[derive(Default)]
    struct TestProvider {
        calls: AtomicUsize,
        fail_next: AtomicBool,
        rendezvous: Option<Barrier>,
        cache: Mutex<Weak<Mutex<Configs>>>,
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
                .build()
        }

        fn authenticates_server(&self, _: &Extensions) -> bool {
            true
        }
    }

    impl QuicClientConfigProvider for TestProvider {
        fn client_config(
            &self,
            _: &TlsClientConfig,
            _: TlsOptions,
        ) -> Result<ClientConfig, TlsConfigError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_next.swap(false, Ordering::Relaxed) {
                return Err(TlsConfigError::BackendUnavailable);
            }
            let cache = self.cache.lock().upgrade();
            if let Some(cache) = cache {
                assert!(
                    cache.try_lock().is_some(),
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
        assert_eq!(cache.configs.lock().overrides.len(), MAX_CACHED_OVERRIDES);
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
    fn changed_defaults_and_opaque_settings_cannot_reuse_native_configuration() {
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
        config.as_extensions().insert(OpaquePolicy);
        let first = cache.client_config(&config, &Extensions::new()).unwrap();
        let second = cache.client_config(&config, &Extensions::new()).unwrap();
        assert!(!Arc::ptr_eq(&first.crypto, &second.crypto));
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
    fn concurrent_builds_converge_without_holding_the_lock_during_provider_calls() {
        let provider = Arc::new(TestProvider {
            rendezvous: Some(Barrier::new(2)),
            ..Default::default()
        });
        let cache = ClientConfigCache::new(provider.clone(), TlsOptions::default());
        *provider.cache.lock() = Arc::downgrade(&cache.configs);
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
}
