use std::{
    num::NonZeroUsize,
    sync::{Arc, LazyLock, OnceLock},
};

use moka::sync::Cache;
use rama_core::{
    combinators::Either,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::Extensions,
    telemetry::tracing::trace,
};
use rama_crypto::{native_certs, pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_tls::client::{
    DynTlsServerCertChainPolicy, NativeTrustPolicy, PlatformTrustPolicy, ServerTrustSource,
    ServerVerifyMode, TlsComponentIdentity, TlsServerCertPins, TlsServerTrust,
    TlsServerTrustAnchors, TlsServerVerify, server_trust_anchors, server_trust_anchors_async,
};
use rustls::RootCertStore;

use super::{RustlsServerCertVerifier, RustlsServerVerification};

static NATIVE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(builtin(
        &native_certs::shared_native_trust_anchors(),
        "native",
    ))
});
static WEBPKI: LazyLock<Arc<RootCertStore>> =
    LazyLock::new(|| Arc::new(builtin(native_certs::bundled_root_certs(), "WebPKI")));

pub(super) fn native() -> Arc<RootCertStore> {
    NATIVE.clone()
}

pub(super) fn webpki() -> Arc<RootCertStore> {
    WEBPKI.clone()
}

fn builtin(anchors: &[CertificateDer<'static>], source: &'static str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(anchors.iter().cloned());
    trace!(
        added,
        ignored, source, "initialised shared rustls root store"
    );
    roots
}

type AnchorSlice = [CertificateDer<'static>];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SharedRoots {
    Native,
    WebPki,
    Platform,
}

static PLATFORM: OnceLock<Arc<PlatformVerifier>> = OnceLock::new();
/// Bounded cache of derived Rustls trust stores and platform verifiers.
///
/// The default capacity is eight derived stores. Each instance owns its
/// derived stores, and cloning shares that instance. Static built-in stores
/// are shared process-wide.
#[derive(Debug)]
#[non_exhaustive]
pub struct RustlsServerTrustCache {
    capacity: NonZeroUsize,
    derived: OnceLock<Cache<TrustKey, RustlsServerVerification>>,
}

impl Default for RustlsServerTrustCache {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl Clone for RustlsServerTrustCache {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            derived: OnceLock::from(self.cache().clone()),
        }
    }
}

impl RustlsServerTrustCache {
    pub(super) const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::new(8).unwrap();

    /// Construct a cache with the given maximum number of derived stores.
    #[must_use]
    pub const fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            derived: OnceLock::new(),
        }
    }

    fn cache(&self) -> &Cache<TrustKey, RustlsServerVerification> {
        self.derived
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

    /// Acquire the verifier for a connection. This may block on trust-store IO.
    ///
    /// The native default is used when no policy is set. Returns `None` when
    /// an application verifier handles the connection or no roots are needed.
    pub fn server_verification(
        &self,
        extensions: &Extensions,
    ) -> Result<Option<RustlsServerVerification>, BoxError> {
        match verification_source(extensions) {
            VerificationSource::Policy(trust) => self.acquire(trust).map(Some),
            VerificationSource::Native => Ok(Some(SharedRoots::Native.acquire())),
            VerificationSource::Unused => Ok(None),
        }
    }

    /// Acquire the verifier on a Tokio runtime, offloading trust-store IO and
    /// construction of native verification material to blocking workers.
    pub async fn server_verification_async(
        &self,
        extensions: &Extensions,
    ) -> Result<Option<RustlsServerVerification>, BoxError> {
        match verification_source(extensions) {
            VerificationSource::Policy(trust) => self.acquire_async(trust).await.map(Some),
            VerificationSource::Native => SharedRoots::Native.acquire_async().await.map(Some),
            VerificationSource::Unused => Ok(None),
        }
    }

    fn acquire(&self, trust: &TlsServerTrust) -> Result<RustlsServerVerification, BoxError> {
        let additional = trust.additional_anchors();
        let roots = match Source::for_trust(trust) {
            Source::Shared(shared) if additional.is_none() => return Ok(shared.acquire()),
            Source::Shared(shared) => StoreRoots::Shared(shared),
            Source::Custom(anchors) => StoreRoots::Custom(anchors.clone()),
            Source::Reloadable(source) => {
                StoreRoots::snapshot(source, server_trust_anchors(source)?)
            }
        };
        let key = roots.key(additional);
        cached(self.cache(), roots, key)
    }

    async fn acquire_async(
        &self,
        trust: &TlsServerTrust,
    ) -> Result<RustlsServerVerification, BoxError> {
        let additional = trust.additional_anchors();
        let roots = match Source::for_trust(trust) {
            Source::Shared(shared) if additional.is_none() => return shared.acquire_async().await,
            Source::Shared(shared) => StoreRoots::Shared(shared),
            Source::Custom(anchors) => StoreRoots::Custom(anchors.clone()),
            Source::Reloadable(source) => {
                StoreRoots::snapshot(source, server_trust_anchors_async(source).await?)
            }
        };
        let key = roots.key(additional);
        let cache = self.cache();
        if let Some(verification) = cache.get(&key) {
            return Ok(verification);
        }
        let cache = cache.clone();
        tokio::task::spawn_blocking(move || cached(&cache, roots, key)).await?
    }
}

enum VerificationSource<'a> {
    Native,
    Policy(&'a TlsServerTrust),
    Unused,
}

fn verification_source(extensions: &Extensions) -> VerificationSource<'_> {
    let mode = extensions
        .get_ref::<TlsServerVerify>()
        .map(|verify| verify.0)
        .unwrap_or_default();
    match mode {
        ServerVerifyMode::Auto if !extensions.contains::<RustlsServerCertVerifier>() => extensions
            .get_ref::<TlsServerTrust>()
            .map_or(VerificationSource::Native, VerificationSource::Policy),
        // The pin-only verifier uses the default store for signature verification setup.
        ServerVerifyMode::Disable
            if extensions.contains::<TlsServerCertPins>()
                && !extensions.contains::<DynTlsServerCertChainPolicy>() =>
        {
            VerificationSource::Native
        }
        _ => VerificationSource::Unused,
    }
}

impl SharedRoots {
    fn acquire(self) -> RustlsServerVerification {
        match self {
            Self::Native => Either::A(native()),
            Self::WebPki => Either::A(webpki()),
            Self::Platform => Either::B(PLATFORM.get_or_init(PlatformVerifier::shared).clone()),
        }
    }

    async fn acquire_async(self) -> Result<RustlsServerVerification, BoxError> {
        if let Some(verification) = self.ready() {
            return Ok(verification);
        }
        Ok(tokio::task::spawn_blocking(move || self.acquire()).await?)
    }

    fn ready(self) -> Option<RustlsServerVerification> {
        match self {
            Self::Native => LazyLock::get(&NATIVE).cloned().map(Either::A),
            Self::WebPki => LazyLock::get(&WEBPKI).cloned().map(Either::A),
            Self::Platform => PLATFORM.get().cloned().map(Either::B),
        }
    }
}

enum Source<'a> {
    Shared(SharedRoots),
    Custom(&'a TlsServerTrustAnchors),
    Reloadable(&'a ServerTrustSource),
}

impl<'a> Source<'a> {
    fn for_trust(trust: &'a TlsServerTrust) -> Self {
        match trust.source() {
            ServerTrustSource::WebPki => Self::Shared(SharedRoots::WebPki),
            ServerTrustSource::Native(policy) if policy == &NativeTrustPolicy::new() => {
                Self::Shared(SharedRoots::Native)
            }
            ServerTrustSource::Platform(policy) if policy == &PlatformTrustPolicy::new() => {
                Self::Shared(if PlatformVerifier::IS_AVAILABLE {
                    SharedRoots::Platform
                } else {
                    SharedRoots::Native
                })
            }
            ServerTrustSource::Custom(anchors) => Self::Custom(anchors),
            source => Self::Reloadable(source),
        }
    }
}

enum StoreRoots {
    Shared(SharedRoots),
    Custom(TlsServerTrustAnchors),
    Snapshot {
        platform: bool,
        anchors: Arc<AnchorSlice>,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RootKey {
    Shared(SharedRoots),
    Custom(TlsServerTrustAnchors),
    Snapshot {
        platform: bool,
        // Retain the anchor allocation while its address is a cache key.
        anchors: TlsComponentIdentity<AnchorSlice>,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TrustKey {
    base: RootKey,
    additional: Option<TlsServerTrustAnchors>,
}

impl StoreRoots {
    fn snapshot(source: &ServerTrustSource, anchors: Arc<AnchorSlice>) -> Self {
        Self::Snapshot {
            platform: PlatformVerifier::IS_AVAILABLE
                && matches!(source, ServerTrustSource::Platform(_)),
            anchors,
        }
    }

    fn key(&self, additional: Option<&TlsServerTrustAnchors>) -> TrustKey {
        let base = match self {
            Self::Shared(roots) => RootKey::Shared(*roots),
            Self::Custom(anchors) => RootKey::Custom(anchors.clone()),
            Self::Snapshot { platform, anchors } => RootKey::Snapshot {
                platform: *platform,
                anchors: TlsComponentIdentity::shared(anchors),
            },
        };
        TrustKey {
            base,
            additional: additional.cloned(),
        }
    }
}

pub(super) fn acquire(trust: &TlsServerTrust) -> Result<RustlsServerVerification, BoxError> {
    let additional = trust.additional_anchors();
    let roots = match Source::for_trust(trust) {
        Source::Shared(shared) if additional.is_none() => return Ok(shared.acquire()),
        Source::Shared(shared) => StoreRoots::Shared(shared),
        Source::Custom(anchors) => StoreRoots::Custom(anchors.clone()),
        Source::Reloadable(source) => StoreRoots::snapshot(source, server_trust_anchors(source)?),
    };
    derive(roots, additional)
}

fn cached(
    cache: &Cache<TrustKey, RustlsServerVerification>,
    roots: StoreRoots,
    key: TrustKey,
) -> Result<RustlsServerVerification, BoxError> {
    let additional = key.additional.clone();
    cache
        .try_get_with(key, || derive(roots, additional.as_ref()))
        .map_err(|error| {
            error
                .to_string()
                .context("construct rustls server verification")
        })
}

fn derive(
    base: StoreRoots,
    additional: Option<&TlsServerTrustAnchors>,
) -> Result<RustlsServerVerification, BoxError> {
    let mut store = match base {
        StoreRoots::Shared(SharedRoots::Native) => native().as_ref().clone(),
        StoreRoots::Shared(SharedRoots::WebPki) => webpki().as_ref().clone(),
        StoreRoots::Shared(SharedRoots::Platform) => {
            return build_platform_verifier(
                &native_certs::shared_extra_trust_anchors(),
                additional,
            );
        }
        StoreRoots::Snapshot {
            platform: true,
            anchors,
        } => {
            return build_platform_verifier(&anchors, additional);
        }
        StoreRoots::Snapshot {
            platform: false,
            anchors,
        } => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(anchors.iter().cloned());
            roots
        }
        StoreRoots::Custom(anchors) => {
            let mut roots = RootCertStore::empty();
            add_configured_roots(&mut roots, &anchors)?;
            roots
        }
    };
    if let Some(anchors) = additional {
        add_configured_roots(&mut store, anchors)?;
    }
    Ok(Either::A(Arc::new(store)))
}

fn build_platform_verifier(
    extras: &AnchorSlice,
    additional: Option<&TlsServerTrustAnchors>,
) -> Result<RustlsServerVerification, BoxError> {
    let roots = extras.iter().chain(
        additional
            .into_iter()
            .flat_map(TlsServerTrustAnchors::certificates),
    );
    Ok(Either::B(Arc::new(PlatformVerifier::try_with_extra_roots(
        roots.cloned(),
    )?)))
}

fn add_configured_roots(
    roots: &mut RootCertStore,
    anchors: &TlsServerTrustAnchors,
) -> Result<(), BoxError> {
    for certificate in anchors.certificates() {
        roots
            .add(certificate.clone())
            .context("add configured server trust anchor to rustls root store")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
