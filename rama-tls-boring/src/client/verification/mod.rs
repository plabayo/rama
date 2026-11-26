use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use moka::sync::Cache;
use rama_boring::ssl::SslConnector;
use rama_core::{
    combinators::Either,
    error::{ArcError, BoxError},
    extensions::Extensions,
};
use rama_crypto::pki_types::CertificateDer;
use rama_tls::client::{
    ServerTrustKey, ServerTrustRoots, ServerTrustSnapshot, SharedServerTrustRoots, TlsPoolId,
    TlsServerTrust, TlsServerTrustAnchors, shared_platform_verifier,
    shared_platform_verifier_async,
};
use tokio::task::spawn_blocking;

use super::{BoringServerVerification, BoringTlsConnectorConfig};

mod roots;
pub(super) use roots::native as native_root_store;

#[derive(Clone, Copy)]
enum StoreRoots<'a> {
    Native,
    WebPki,
    NativeCertificates(&'a [CertificateDer<'static>]),
    Custom(&'a TlsServerTrustAnchors),
}

pub(crate) const DEFAULT_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// A bounded cache of native server verification stores for one BoringSSL connector.
///
/// Clones share entries. Construct a new cache to isolate it from other
/// connectors. Native roots, bundled WebPKI roots and the platform verifier
/// use shared defaults when no custom anchors or reload policy applies.
/// The default capacity is eight, allowing a few request policies and recent
/// trust changes without retaining many native stores.
#[non_exhaustive]
pub struct BoringServerTrustCache {
    capacity: NonZeroUsize,
    caches: OnceLock<Arc<OwnedCaches>>,
}

#[derive(Default)]
struct OwnedCaches {
    stores: OnceLock<Cache<ServerTrustKey, BoringServerVerification>>,
    contexts: OnceLock<Cache<TlsPoolId, SslConnector>>,
}

impl BoringServerTrustCache {
    /// Create an independent cache.
    ///
    /// `capacity` separately bounds derived stores and stateless contexts.
    #[must_use]
    pub const fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            caches: OnceLock::new(),
        }
    }

    /// Access the bounded verification caches.
    fn caches(&self) -> &Arc<OwnedCaches> {
        self.caches.get_or_init(|| Arc::new(OwnedCaches::default()))
    }

    /// Access the cached native trust stores.
    fn stores(&self) -> &Cache<ServerTrustKey, BoringServerVerification> {
        self.caches()
            .stores
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

    /// Access the cached contexts that do not retain sessions.
    pub(super) fn stateless_contexts(&self) -> &Cache<TlsPoolId, SslConnector> {
        self.caches()
            .contexts
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

    /// Acquire native trust for the effective TLS configuration.
    ///
    /// Returns `None` when verification is disabled or the backend's default
    /// or custom store applies. This synchronous operation can block.
    pub fn server_verification(
        &self,
        extensions: &Extensions,
    ) -> Result<Option<BoringServerVerification>, BoxError> {
        let Some(trust) = BoringTlsConnectorConfig::common_server_trust(extensions) else {
            return Ok(None);
        };
        let snapshot = ServerTrustSnapshot::read(trust)?;
        if let Some(shared) = snapshot.shared() {
            return get_shared(shared).map(Some);
        }
        cached(self.stores(), &snapshot, build).map(Some)
    }

    /// Acquire native trust on a Tokio runtime.
    ///
    /// Native trust reads and cold store construction run on blocking workers.
    /// Returns `None` in the same cases as [`Self::server_verification`].
    pub async fn server_verification_async(
        &self,
        extensions: &Extensions,
    ) -> Result<Option<BoringServerVerification>, BoxError> {
        if !BoringTlsConnectorConfig::uses_common_server_trust_in(extensions) {
            return Ok(None);
        }
        let Some(trust) = extensions.get_ref::<TlsServerTrust>() else {
            acquire_shared_async(SharedServerTrustRoots::Native).await?;
            return Ok(None);
        };
        self.acquire_async_with(trust, build).await.map(Some)
    }

    /// Build missing verification state on a blocking worker.
    async fn acquire_async_with(
        &self,
        trust: &TlsServerTrust,
        build: fn(&ServerTrustSnapshot) -> Result<BoringServerVerification, BoxError>,
    ) -> Result<BoringServerVerification, BoxError> {
        let snapshot = ServerTrustSnapshot::read_async(trust).await?;
        if let Some(shared) = snapshot.shared() {
            return acquire_shared_async(shared).await;
        }
        let cache = self.stores();
        if let Some(store) = cache.get(&snapshot.key()) {
            return Ok(store);
        }
        let cache = cache.clone();
        spawn_blocking(move || cached(&cache, &snapshot, build)).await?
    }
}

impl Default for BoringServerTrustCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }
}

impl Clone for BoringServerTrustCache {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            caches: OnceLock::from(self.caches().clone()),
        }
    }
}

impl fmt::Debug for BoringServerTrustCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringServerTrustCache")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

fn get_shared(shared: SharedServerTrustRoots) -> Result<BoringServerVerification, BoxError> {
    match shared {
        SharedServerTrustRoots::Native => roots::native().map(Either::A),
        SharedServerTrustRoots::WebPki => roots::webpki().map(Either::A),
        SharedServerTrustRoots::Platform => Ok(Either::B(shared_platform_verifier())),
    }
}

fn build(snapshot: &ServerTrustSnapshot) -> Result<BoringServerVerification, BoxError> {
    let base = match snapshot.roots() {
        ServerTrustRoots::Shared(SharedServerTrustRoots::Platform)
        | ServerTrustRoots::PlatformExtras(_) => {
            return snapshot.platform_verifier().map(Either::B);
        }
        ServerTrustRoots::Shared(SharedServerTrustRoots::Native) => StoreRoots::Native,
        ServerTrustRoots::Shared(SharedServerTrustRoots::WebPki) => StoreRoots::WebPki,
        ServerTrustRoots::Native(anchors) => StoreRoots::NativeCertificates(anchors),
        ServerTrustRoots::Custom(anchors) => StoreRoots::Custom(anchors),
    };
    roots::derived(base, snapshot.additional_anchors()).map(Either::A)
}

fn cached(
    cache: &Cache<ServerTrustKey, BoringServerVerification>,
    snapshot: &ServerTrustSnapshot,
    build: fn(&ServerTrustSnapshot) -> Result<BoringServerVerification, BoxError>,
) -> Result<BoringServerVerification, BoxError> {
    cache
        .try_get_with(snapshot.key(), || build(snapshot).map_err(ArcError::from))
        .map_err(|error| {
            ArcError::clone(&error)
                .context("construct BoringSSL server verification")
                .into()
        })
}

pub(super) fn acquire(trust: &TlsServerTrust) -> Result<BoringServerVerification, BoxError> {
    let snapshot = ServerTrustSnapshot::read(trust)?;
    match snapshot.shared() {
        Some(shared) => get_shared(shared),
        None => build(&snapshot),
    }
}

async fn acquire_shared_async(
    shared: SharedServerTrustRoots,
) -> Result<BoringServerVerification, BoxError> {
    match shared {
        SharedServerTrustRoots::Native => roots::native_async().await.map(Either::A),
        SharedServerTrustRoots::WebPki => roots::webpki_async().await.map(Either::A),
        SharedServerTrustRoots::Platform => shared_platform_verifier_async().await.map(Either::B),
    }
}

/// Whether `trust` needs a store derived for it rather than a process-wide one.
pub(super) fn uses_derived_store(trust: &TlsServerTrust) -> bool {
    ServerTrustSnapshot::shared_for(trust).is_none()
}

#[cfg(test)]
mod tests;
