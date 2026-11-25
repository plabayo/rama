use std::{
    num::NonZeroUsize,
    sync::{Arc, LazyLock, OnceLock},
};

use moka::sync::Cache;
use rama_core::{
    combinators::Either,
    error::{ArcError, BoxError, ErrorContext as _},
    extensions::Extensions,
    telemetry::tracing::{debug, trace},
};
use rama_crypto::{native_certs, pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_tls::client::{
    DynTlsServerCertChainPolicy, ServerTrustKey, ServerTrustRoots, ServerTrustSnapshot,
    ServerVerifyMode, SharedServerTrustRoots, TlsServerCertPins, TlsServerTrust,
    TlsServerTrustAnchors, TlsServerVerify, shared_platform_verifier,
    shared_platform_verifier_async,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::{runtime::Handle, task::spawn_blocking};

use super::{NativeConfigKey, RustlsServerCertVerifier};

static NATIVE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(builtin(
        &native_certs::shared_native_trust_anchors(),
        "native",
    ))
});
static WEBPKI: LazyLock<Arc<RootCertStore>> =
    LazyLock::new(|| Arc::new(builtin(native_certs::bundled_root_certs(), "WebPKI")));

// The trust of connections without a policy, which reads no trust store.
static NATIVE_TRUST: TlsServerTrust = TlsServerTrust::native_roots();

pub(super) fn native() -> Arc<RootCertStore> {
    NATIVE.clone()
}

pub(super) fn webpki() -> Arc<RootCertStore> {
    WEBPKI.clone()
}

fn builtin(anchors: &[CertificateDer<'static>], kind: &'static str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for anchor in anchors {
        if let Err(err) = roots.add(CertificateDer::from(anchor.as_ref())) {
            debug!(%err, trust_anchor_kind = kind, "rustls connector: failed to add built-in trust anchor");
        }
    }
    trace!(
        added = roots.len(),
        trust_anchor_kind = kind,
        "rustls connector: root store built from built-in trust anchors"
    );
    roots
}

/// Server verification derived from one trust snapshot, bound to that snapshot's key.
///
/// Acquire it through [`RustlsServerTrustCache`]. The key travels with the
/// verifier, so sessions a configuration resumes end with that trust generation.
#[derive(Debug, Clone)]
pub struct RustlsServerVerification {
    pub(super) verifier: Either<Arc<RootCertStore>, Arc<PlatformVerifier>>,
    pub(super) trust_key: ServerTrustKey,
}

impl RustlsServerVerification {
    /// The root store or operating system verifier.
    #[must_use]
    pub fn verifier(&self) -> &Either<Arc<RootCertStore>, Arc<PlatformVerifier>> {
        &self.verifier
    }

    /// The key of the trust snapshot the verifier was derived from.
    #[must_use]
    pub fn trust_key(&self) -> &ServerTrustKey {
        &self.trust_key
    }
}

/// Bounded cache of derived Rustls trust stores, platform verifiers and
/// native client configurations.
///
/// The default capacity is eight derived stores and eight configurations.
/// Each instance owns its entries, and cloning shares that instance. Static
/// built-in stores are shared process-wide. A cached configuration carries
/// the session tickets of its connections, so connections resume only
/// under an identical policy and trust snapshot.
#[derive(Debug)]
#[non_exhaustive]
pub struct RustlsServerTrustCache {
    capacity: NonZeroUsize,
    derived: OnceLock<Cache<ServerTrustKey, RustlsServerVerification>>,
    configs: OnceLock<Cache<NativeConfigKey, Arc<ClientConfig>>>,
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
            configs: OnceLock::from(self.configs().clone()),
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
            configs: OnceLock::new(),
        }
    }

    /// Access the shared native verification cache.
    fn cache(&self) -> &Cache<ServerTrustKey, RustlsServerVerification> {
        self.derived
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

    /// Access the cached native TLS configurations.
    fn configs(&self) -> &Cache<NativeConfigKey, Arc<ClientConfig>> {
        self.configs
            .get_or_init(|| Cache::new(self.capacity.get() as u64))
    }

    /// The cached native configuration under `key`, built on a miss.
    pub(super) fn client_config(
        &self,
        key: NativeConfigKey,
        build: impl FnOnce() -> Result<ClientConfig, BoxError>,
    ) -> Result<Arc<ClientConfig>, BoxError> {
        self.configs()
            .try_get_with(key, || build().map(Arc::new).map_err(ArcError::from))
            .map_err(|error| {
                ArcError::clone(&error)
                    .context("construct rustls client configuration")
                    .into()
            })
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
            VerificationSource::Unused => Ok(None),
        }
    }

    /// Acquire verification state for this policy.
    fn acquire(&self, trust: &TlsServerTrust) -> Result<RustlsServerVerification, BoxError> {
        let snapshot = ServerTrustSnapshot::read(trust)?;
        if let Some(shared) = snapshot.shared() {
            return Ok(RustlsServerVerification {
                verifier: acquire_shared(shared),
                trust_key: snapshot.key(),
            });
        }
        cached(self.cache(), &snapshot)
    }

    /// Acquire verification state after asynchronous trust preparation.
    async fn acquire_async(
        &self,
        trust: &TlsServerTrust,
    ) -> Result<RustlsServerVerification, BoxError> {
        let snapshot = ServerTrustSnapshot::read_async(trust).await?;
        if let Some(shared) = snapshot.shared() {
            return Ok(RustlsServerVerification {
                verifier: acquire_shared_async(shared).await?,
                trust_key: snapshot.key(),
            });
        }
        let cache = self.cache();
        if let Some(verification) = cache.get(&snapshot.key()) {
            return Ok(verification);
        }
        let cache = cache.clone();
        spawn_blocking(move || cached(&cache, &snapshot)).await?
    }
}

enum VerificationSource<'a> {
    Policy(&'a TlsServerTrust),
    Unused,
}

fn verification_source(extensions: &Extensions) -> VerificationSource<'_> {
    let mode = extensions
        .get_ref::<TlsServerVerify>()
        .map(|verify| verify.0)
        .unwrap_or_default();
    match mode {
        ServerVerifyMode::Auto if !extensions.contains::<RustlsServerCertVerifier>() => {
            VerificationSource::Policy(extensions.get_ref().unwrap_or(&NATIVE_TRUST))
        }
        // The pin-only verifier uses the default store for signature verification setup.
        ServerVerifyMode::Disable
            if extensions.contains::<TlsServerCertPins>()
                && !extensions.contains::<DynTlsServerCertChainPolicy>() =>
        {
            VerificationSource::Policy(&NATIVE_TRUST)
        }
        _ => VerificationSource::Unused,
    }
}

fn acquire_shared(
    shared: SharedServerTrustRoots,
) -> Either<Arc<RootCertStore>, Arc<PlatformVerifier>> {
    match shared {
        SharedServerTrustRoots::Native => Either::A(native()),
        SharedServerTrustRoots::WebPki => Either::A(webpki()),
        SharedServerTrustRoots::Platform => Either::B(shared_platform_verifier()),
    }
}

async fn acquire_shared_async(
    shared: SharedServerTrustRoots,
) -> Result<Either<Arc<RootCertStore>, Arc<PlatformVerifier>>, BoxError> {
    let store = match shared {
        SharedServerTrustRoots::Native => &NATIVE,
        SharedServerTrustRoots::WebPki => &WEBPKI,
        SharedServerTrustRoots::Platform => {
            return shared_platform_verifier_async().await.map(Either::B);
        }
    };
    // A built store without leaving the task; a first build runs off the async worker.
    if let Some(roots) = LazyLock::get(store) {
        return Ok(Either::A(roots.clone()));
    }
    let force = move || Either::A(LazyLock::force(store).clone());
    match Handle::try_current() {
        Ok(runtime) => Ok(runtime.spawn_blocking(force).await?),
        Err(_no_runtime) => Ok(force()),
    }
}

pub(super) fn acquire(trust: &TlsServerTrust) -> Result<RustlsServerVerification, BoxError> {
    let snapshot = ServerTrustSnapshot::read(trust)?;
    let verifier = match snapshot.shared() {
        Some(shared) => acquire_shared(shared),
        None => derive(&snapshot)?,
    };
    Ok(RustlsServerVerification {
        verifier,
        trust_key: snapshot.key(),
    })
}

fn cached(
    cache: &Cache<ServerTrustKey, RustlsServerVerification>,
    snapshot: &ServerTrustSnapshot,
) -> Result<RustlsServerVerification, BoxError> {
    let trust_key = snapshot.key();
    cache
        .try_get_with(trust_key.clone(), || {
            derive(snapshot)
                .map(|verifier| RustlsServerVerification {
                    verifier,
                    trust_key,
                })
                .map_err(ArcError::from)
        })
        .map_err(|error| {
            ArcError::clone(&error)
                .context("construct rustls server verification")
                .into()
        })
}

fn derive(
    snapshot: &ServerTrustSnapshot,
) -> Result<Either<Arc<RootCertStore>, Arc<PlatformVerifier>>, BoxError> {
    let mut store = match snapshot.roots() {
        ServerTrustRoots::Shared(SharedServerTrustRoots::Platform)
        | ServerTrustRoots::PlatformExtras(_) => {
            return snapshot.platform_verifier().map(Either::B);
        }
        ServerTrustRoots::Shared(SharedServerTrustRoots::Native) => native().as_ref().clone(),
        ServerTrustRoots::Shared(SharedServerTrustRoots::WebPki) => webpki().as_ref().clone(),
        ServerTrustRoots::Native(anchors) => builtin(anchors, "native"),
        ServerTrustRoots::Custom(anchors) => {
            let mut roots = RootCertStore::empty();
            add_configured_roots(&mut roots, anchors)?;
            roots
        }
    };
    if let Some(anchors) = snapshot.additional_anchors() {
        add_configured_roots(&mut store, anchors)?;
    }
    Ok(Either::A(Arc::new(store)))
}

fn add_configured_roots(
    roots: &mut RootCertStore,
    anchors: &TlsServerTrustAnchors,
) -> Result<(), BoxError> {
    for certificate in anchors.certificates() {
        roots
            .add(CertificateDer::from(certificate.as_ref()))
            .context("add configured server trust anchor to rustls root store")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
