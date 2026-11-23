use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use moka::sync::Cache;
use rama_boring::ssl::SslConnector;
use rama_core::{
    combinators::Either,
    error::{BoxError, ErrorExt as _},
    extensions::Extensions,
};
use rama_crypto::{pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_tls::client::{
    NativeTrustPolicy, PlatformTrustPolicy, ServerTrustSource, TlsComponentIdentity, TlsPoolId,
    TlsServerTrust, TlsServerTrustAnchors, server_trust_anchors, server_trust_anchors_async,
};

use super::{BoringServerVerification, BoringTlsConnectorConfig};

mod roots;
pub(super) use roots::native as native_root_store;

type Certificates = Arc<[CertificateDer<'static>]>;

#[derive(Clone, Copy)]
enum StoreRoots<'a> {
    Native,
    WebPki,
    NativeCertificates(&'a [CertificateDer<'static>]),
    Custom(&'a TlsServerTrustAnchors),
}

#[derive(Clone, Copy)]
enum SharedRoots {
    Native,
    WebPki,
    Platform,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum StoreKey {
    Static(TlsServerTrust),
    Reloaded {
        anchors: TlsComponentIdentity<[CertificateDer<'static>]>,
        additional: Option<TlsServerTrustAnchors>,
        platform: bool,
    },
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
    stores: OnceLock<Cache<StoreKey, BoringServerVerification>>,
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

    fn caches(&self) -> &Arc<OwnedCaches> {
        self.caches.get_or_init(|| Arc::new(OwnedCaches::default()))
    }

    fn stores(&self) -> &Cache<StoreKey, BoringServerVerification> {
        self.caches()
            .stores
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

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
        if let Some(roots) = SharedRoots::for_trust(trust) {
            return roots.get().map(Some);
        }
        let anchors = reload_source(trust).map(server_trust_anchors).transpose()?;
        cached(self.stores(), store_key(trust, anchors.as_ref()), || {
            build(trust, anchors.as_ref())
        })
        .map(Some)
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
            acquire_shared_async(SharedRoots::Native).await?;
            return Ok(None);
        };
        self.acquire_async_with(trust, build).await.map(Some)
    }

    async fn acquire_async_with(
        &self,
        trust: &TlsServerTrust,
        build: fn(
            &TlsServerTrust,
            Option<&Certificates>,
        ) -> Result<BoringServerVerification, BoxError>,
    ) -> Result<BoringServerVerification, BoxError> {
        if let Some(roots) = SharedRoots::for_trust(trust) {
            return acquire_shared_async(roots).await;
        }
        let anchors = match reload_source(trust) {
            Some(source) => Some(server_trust_anchors_async(source).await?),
            None => None,
        };
        let key = store_key(trust, anchors.as_ref());
        let cache = self.stores();
        if let Some(store) = cache.get(&key) {
            return Ok(store);
        }
        let cache = cache.clone();
        let trust = trust.clone();
        tokio::task::spawn_blocking(move || cached(&cache, key, || build(&trust, anchors.as_ref())))
            .await?
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

static PLATFORM: OnceLock<Arc<PlatformVerifier>> = OnceLock::new();

pub(super) fn reload_source(trust: &TlsServerTrust) -> Option<&ServerTrustSource> {
    let source = trust.source();
    match source {
        ServerTrustSource::Native(policy) if *policy != NativeTrustPolicy::new() => Some(source),
        ServerTrustSource::Platform(policy) if *policy != PlatformTrustPolicy::new() => {
            Some(source)
        }
        _ => None,
    }
}

fn uses_platform_verifier(trust: &TlsServerTrust) -> bool {
    PlatformVerifier::IS_AVAILABLE && matches!(trust.source(), ServerTrustSource::Platform(_))
}

impl SharedRoots {
    fn for_trust(trust: &TlsServerTrust) -> Option<Self> {
        if trust.additional_anchors().is_some() || reload_source(trust).is_some() {
            return None;
        }
        match trust.source() {
            ServerTrustSource::Platform(_) if PlatformVerifier::IS_AVAILABLE => {
                Some(Self::Platform)
            }
            ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => Some(Self::Native),
            ServerTrustSource::WebPki => Some(Self::WebPki),
            ServerTrustSource::Custom(_) => None,
        }
    }

    fn get(self) -> Result<BoringServerVerification, BoxError> {
        match self {
            Self::Native => roots::native().map(Either::A),
            Self::WebPki => roots::webpki().map(Either::A),
            Self::Platform => Ok(Either::B(
                PLATFORM.get_or_init(PlatformVerifier::shared).clone(),
            )),
        }
    }

    fn ready(self) -> Option<Result<BoringServerVerification, BoxError>> {
        match self {
            Self::Native => roots::native_ready().map(|store| store.map(Either::A)),
            Self::WebPki => roots::webpki_ready().map(|store| store.map(Either::A)),
            Self::Platform => PLATFORM
                .get()
                .map(|verifier| Ok(Either::B(verifier.clone()))),
        }
    }
}

fn store_key(trust: &TlsServerTrust, anchors: Option<&Certificates>) -> StoreKey {
    match anchors {
        Some(anchors) => StoreKey::Reloaded {
            anchors: TlsComponentIdentity::shared(anchors),
            additional: trust.additional_anchors().cloned(),
            platform: uses_platform_verifier(trust),
        },
        None => StoreKey::Static(trust.clone()),
    }
}

fn build(
    trust: &TlsServerTrust,
    anchors: Option<&Certificates>,
) -> Result<BoringServerVerification, BoxError> {
    let additional = trust.additional_anchors();
    if uses_platform_verifier(trust) {
        let extras = anchors
            .cloned()
            .unwrap_or_else(rama_crypto::native_certs::shared_extra_trust_anchors);
        let certificates = extras.iter().chain(
            additional
                .into_iter()
                .flat_map(TlsServerTrustAnchors::certificates),
        );
        return Ok(Either::B(Arc::new(PlatformVerifier::try_with_extra_roots(
            certificates.cloned(),
        )?)));
    }

    let base = match trust.source() {
        ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => anchors
            .map_or(StoreRoots::Native, |roots| {
                StoreRoots::NativeCertificates(roots)
            }),
        ServerTrustSource::WebPki => StoreRoots::WebPki,
        ServerTrustSource::Custom(anchors) => StoreRoots::Custom(anchors),
    };
    roots::derived(base, additional).map(Either::A)
}

fn cached(
    cache: &Cache<StoreKey, BoringServerVerification>,
    key: StoreKey,
    build: impl FnOnce() -> Result<BoringServerVerification, BoxError>,
) -> Result<BoringServerVerification, BoxError> {
    cache.try_get_with(key, build).map_err(|error| {
        error
            .to_string()
            .context("construct BoringSSL server verification")
    })
}

pub(super) fn acquire(trust: &TlsServerTrust) -> Result<BoringServerVerification, BoxError> {
    if let Some(roots) = SharedRoots::for_trust(trust) {
        return roots.get();
    }
    let anchors = reload_source(trust).map(server_trust_anchors).transpose()?;
    build(trust, anchors.as_ref())
}

async fn acquire_shared_async(roots: SharedRoots) -> Result<BoringServerVerification, BoxError> {
    if let Some(store) = roots.ready() {
        return store;
    }
    tokio::task::spawn_blocking(move || roots.get()).await?
}

pub(super) fn uses_derived_store(trust: &TlsServerTrust) -> bool {
    SharedRoots::for_trust(trust).is_none()
}

#[cfg(test)]
mod tests;
