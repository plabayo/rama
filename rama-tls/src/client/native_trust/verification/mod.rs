use std::sync::{Arc, LazyLock, OnceLock};

use moka::sync::Cache;
use rama_core::combinators::Either;
use rama_core::error::{BoxError, ErrorExt as _};
use rama_crypto::{pki_types::CertificateDer, platform_verifier::PlatformVerifier};

use crate::client::{ServerTrustSource, TlsServerTrust, TlsServerTrustAnchors};

type Material<R> = Either<Arc<R>, Arc<PlatformVerifier>>;

#[derive(Clone, Copy)]
pub(super) enum StoreRoots<'a> {
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

impl SharedRoots {
    fn for_trust(trust: &TlsServerTrust) -> Option<Self> {
        if trust.additional_anchors().is_some() {
            return None;
        }
        let source = trust.source();
        match source {
            ServerTrustSource::Platform(_) if PlatformVerifier::IS_AVAILABLE => source
                .prepared_platform_roots()
                .is_none()
                .then_some(Self::Platform),
            ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => source
                .prepared_native_roots()
                .is_none()
                .then_some(Self::Native),
            ServerTrustSource::WebPki => Some(Self::WebPki),
            ServerTrustSource::Custom(_) => None,
        }
    }
}

static PLATFORM: OnceLock<Arc<PlatformVerifier>> = OnceLock::new();

struct SharedStore<R> {
    get: fn() -> Result<Arc<R>, BoxError>,
    ready: fn() -> Option<Result<Arc<R>, BoxError>>,
}

struct Stores<R> {
    native: SharedStore<R>,
    webpki: SharedStore<R>,
    derived: fn(StoreRoots<'_>, Option<&TlsServerTrustAnchors>) -> Result<Arc<R>, BoxError>,
    cache: Cache<TlsServerTrust, Material<R>>,
}

impl<R: Send + Sync + 'static> Stores<R> {
    fn new(
        native: SharedStore<R>,
        webpki: SharedStore<R>,
        derived: fn(StoreRoots<'_>, Option<&TlsServerTrustAnchors>) -> Result<Arc<R>, BoxError>,
    ) -> Self {
        Self {
            native,
            webpki,
            derived,
            cache: Cache::new(64),
        }
    }

    fn shared(&self, roots: SharedRoots) -> Result<Material<R>, BoxError> {
        match roots {
            SharedRoots::Native => (self.native.get)().map(Either::A),
            SharedRoots::WebPki => (self.webpki.get)().map(Either::A),
            SharedRoots::Platform => Ok(Either::B(
                PLATFORM.get_or_init(PlatformVerifier::shared).clone(),
            )),
        }
    }

    fn shared_ready(&self, roots: SharedRoots) -> Option<Result<Material<R>, BoxError>> {
        match roots {
            SharedRoots::Native => (self.native.ready)().map(|store| store.map(Either::A)),
            SharedRoots::WebPki => (self.webpki.ready)().map(|store| store.map(Either::A)),
            SharedRoots::Platform => PLATFORM.get().map(|store| Ok(Either::B(store.clone()))),
        }
    }

    fn cached(&self, effective: &TlsServerTrust) -> Result<Material<R>, BoxError> {
        self.cache
            .try_get_with(effective.clone(), || {
                let source = effective.source();
                let additional = effective.additional_anchors();
                let material = if matches!(source, ServerTrustSource::Platform(_))
                    && PlatformVerifier::IS_AVAILABLE
                {
                    let environment;
                    let extras = if let Some(roots) = source.prepared_platform_roots() {
                        roots
                    } else {
                        environment = rama_crypto::native_certs::shared_extra_trust_anchors();
                        &environment
                    };
                    let roots = extras.iter().chain(
                        additional
                            .into_iter()
                            .flat_map(TlsServerTrustAnchors::certificates),
                    );
                    Either::B(Arc::new(PlatformVerifier::try_with_extra_roots(
                        roots.cloned(),
                    )?))
                } else {
                    let base = match source {
                        ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => source
                            .prepared_native_roots()
                            .map_or(StoreRoots::Native, StoreRoots::NativeCertificates),
                        ServerTrustSource::WebPki => StoreRoots::WebPki,
                        ServerTrustSource::Custom(anchors) => StoreRoots::Custom(anchors),
                    };
                    Either::A((self.derived)(base, additional)?)
                };
                Ok::<_, BoxError>(material)
            })
            .map_err(|error| {
                error
                    .to_string()
                    .context("construct native server verification")
            })
    }

    fn acquire(&self, policy: &TlsServerTrust) -> Result<Material<R>, BoxError> {
        let effective = policy
            .source()
            .snapshot()?
            .map(|source| policy.clone().with_source(source));
        let effective = effective.as_ref().unwrap_or(policy);
        if let Some(roots) = SharedRoots::for_trust(effective) {
            return self.shared(roots);
        }
        self.cached(effective)
    }

    async fn acquire_async(
        &'static self,
        policy: &TlsServerTrust,
    ) -> Result<Material<R>, BoxError> {
        let effective = policy
            .source()
            .snapshot_async()
            .await?
            .map(|source| policy.clone().with_source(source));
        let effective = effective.as_ref().unwrap_or(policy);
        if let Some(roots) = SharedRoots::for_trust(effective) {
            if let Some(material) = self.shared_ready(roots) {
                return material;
            }
            return tokio::task::spawn_blocking(move || self.shared(roots)).await?;
        }
        if let Some(material) = self.cache.get(effective) {
            return Ok(material);
        }
        let effective = effective.clone();
        tokio::task::spawn_blocking(move || self.cached(&effective)).await?
    }
}

#[cfg(feature = "boring-native-verification")]
use rama_boring::x509::store::X509Store;

#[cfg(feature = "boring-native-verification")]
static BORING: LazyLock<Stores<X509Store>> = LazyLock::new(|| {
    Stores::new(
        SharedStore {
            get: super::boring::native,
            ready: super::boring::native_ready,
        },
        SharedStore {
            get: super::boring::webpki,
            ready: super::boring::webpki_ready,
        },
        super::boring::derived,
    )
});

/// Acquire the BoringSSL trust store or platform verifier for a handshake.
/// Synchronous acquisition can block while reading and building the trust store.
#[cfg(feature = "boring-native-verification")]
pub fn boring_server_verification(
    policy: &TlsServerTrust,
) -> Result<Either<Arc<X509Store>, Arc<PlatformVerifier>>, BoxError> {
    BORING.acquire(policy)
}

/// The process-wide BoringSSL root store based on native roots.
#[cfg(feature = "boring-native-verification")]
pub fn boring_native_root_store() -> Result<Arc<X509Store>, BoxError> {
    super::boring::native()
}

/// Acquire BoringSSL verification on a Tokio runtime.
/// Reloadable trust reads and derived store construction run on blocking workers.
#[cfg(feature = "boring-native-verification")]
pub async fn boring_server_verification_async(
    policy: &TlsServerTrust,
) -> Result<Either<Arc<X509Store>, Arc<PlatformVerifier>>, BoxError> {
    BORING.acquire_async(policy).await
}

#[cfg(feature = "rustls-native-verification")]
use ::rustls::RootCertStore;

#[cfg(feature = "rustls-native-verification")]
static RUSTLS: LazyLock<Stores<RootCertStore>> = LazyLock::new(|| {
    Stores::new(
        SharedStore {
            get: || Ok(super::rustls::native()),
            ready: || super::rustls::native_ready().map(Ok),
        },
        SharedStore {
            get: || Ok(super::rustls::webpki()),
            ready: || super::rustls::webpki_ready().map(Ok),
        },
        super::rustls::derived,
    )
});

/// Acquire the rustls trust store or platform verifier for a handshake.
/// Synchronous acquisition can block while reading and building the trust store.
#[cfg(feature = "rustls-native-verification")]
pub fn rustls_server_verification(
    policy: &TlsServerTrust,
) -> Result<Either<Arc<RootCertStore>, Arc<PlatformVerifier>>, BoxError> {
    RUSTLS.acquire(policy)
}

/// Acquire rustls verification on a Tokio runtime.
/// Reloadable trust reads and derived store construction run on blocking workers.
#[cfg(feature = "rustls-native-verification")]
pub async fn rustls_server_verification_async(
    policy: &TlsServerTrust,
) -> Result<Either<Arc<RootCertStore>, Arc<PlatformVerifier>>, BoxError> {
    RUSTLS.acquire_async(policy).await
}

/// The process-wide rustls root store based on native roots.
#[cfg(feature = "rustls-native-verification")]
pub fn rustls_native_root_store() -> Arc<RootCertStore> {
    super::rustls::native()
}

/// The process-wide rustls root store based on bundled WebPKI roots.
#[cfg(feature = "rustls-native-verification")]
pub fn rustls_webpki_root_store() -> Arc<RootCertStore> {
    super::rustls::webpki()
}

#[cfg(test)]
mod tests;
