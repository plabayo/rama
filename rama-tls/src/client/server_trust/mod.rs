use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};
use rama_crypto::pki_types::CertificateDer;
use rama_utils::macros::generate_set_and_with;
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

#[cfg(feature = "native-certs")]
mod native;

/// Settings for the native root store used by [`ServerTrustSource::Native`].
///
/// The default uses a static snapshot. With the `native-certs` feature,
/// this policy supports refresh triggers and an age limit.
///
/// Configure this policy once and clone it so callers share its reload state
/// and can reuse pooled connections. Refreshes apply to new handshakes.
/// Established pooled connections can continue serving requests until they close.
/// Rama’s rustls and BoringSSL connectors, including their QUIC providers,
/// apply this policy. A custom verifier controls its own trust decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeTrustPolicy {
    #[cfg(feature = "native-certs")]
    state: native::NativeTrustState,
}

impl NativeTrustPolicy {
    /// Use a static snapshot of native roots.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "native-certs")]
            state: native::NativeTrustState::STATIC,
        }
    }
}

impl Default for NativeTrustPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Settings for the platform verifier used by [`ServerTrustSource::Platform`].
///
/// The operating system verifier determines system trust. With the
/// `native-certs` feature, a reload policy on supported targets refreshes
/// only extra anchors supplied through `SSL_CERT_EXTRA_FILE` and
/// `SSL_CERT_EXTRA_DIR`. On other targets a reload policy refreshes the full
/// native root store, including its environment configuration.
///
/// Configure this policy once and clone it so callers share its reload state
/// and can reuse pooled connections. Refreshes apply to new handshakes.
/// Established pooled connections can continue serving requests until they close.
/// Rama’s rustls and BoringSSL connectors, including their QUIC providers,
/// apply this policy. A custom verifier controls its own trust decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PlatformTrustPolicy {
    #[cfg(feature = "native-certs")]
    state: native::NativeTrustState,
}

impl PlatformTrustPolicy {
    /// Use the operating system verifier, or static native roots if unavailable.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "native-certs")]
            state: native::NativeTrustState::STATIC,
        }
    }
}

impl Default for PlatformTrustPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// DER-encoded certificates used as TLS client server trust anchors.
///
/// Certificates are installed as explicit trust anchors. Backends may therefore
/// terminate a verified chain at a configured root, intermediate, or end-entity
/// certificate. Use certificate pinning when exact certificate or SPKI matching
/// is required instead of trust-anchor semantics.
#[derive(Debug, Clone)]
pub struct TlsServerTrustAnchors {
    certificates: Arc<[CertificateDer<'static>]>,
    digest: super::pool::PolicyDigest,
}

impl PartialEq for TlsServerTrustAnchors {
    fn eq(&self, other: &Self) -> bool {
        self.certificates == other.certificates
    }
}

impl Eq for TlsServerTrustAnchors {}

impl Hash for TlsServerTrustAnchors {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl TlsServerTrustAnchors {
    /// Create a non-empty set of server trust anchors.
    pub fn try_new(
        certificates: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, BoxError> {
        let certificates: Arc<[CertificateDer<'static>]> = certificates.into_iter().collect();
        if certificates.is_empty() {
            return Err(BoxError::from_static_str(
                "server trust anchor set cannot be empty",
            ));
        }
        let digest = super::pool::policy_digest(b"rama.tls.trust-anchors.v1", &certificates);
        Ok(Self {
            certificates,
            digest,
        })
    }

    /// Return the configured trust-anchor certificates.
    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }
}

/// Source of trust for normal server-certificate verification.
///
/// Construct static sources with [`Self::native_roots`] and
/// [`Self::platform_verifier`]. Match those sources with `Native(_)` and
/// `Platform(_)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServerTrustSource {
    /// A snapshot of the native roots, or the roots in `SSL_CERT_FILE` and
    /// `SSL_CERT_DIR`, which replace them. Bundled WebPKI roots are the
    /// fallback only without such an override. Roots in `SSL_CERT_EXTRA_FILE`
    /// and `SSL_CERT_EXTRA_DIR` are always added.
    /// A native trust policy can opt into refreshing its snapshot.
    Native(NativeTrustPolicy),
    /// Rama's bundled Mozilla (CCADB) roots, independent of the host OS.
    WebPki,
    /// Only the supplied trust anchors.
    Custom(TlsServerTrustAnchors),
    /// The operating system's certificate verifier validates the chain and
    /// server identity, including enterprise trust settings and the platform's
    /// distrust and revocation policy. Roots in `SSL_CERT_EXTRA_FILE` and
    /// `SSL_CERT_EXTRA_DIR` are trusted in addition; `SSL_CERT_FILE` and
    /// `SSL_CERT_DIR` are ignored, as they replace a root store.
    ///
    /// Available on Apple platforms, Windows and Android. Other platforms have
    /// no such verifier and verify against [`ServerTrustSource::Native`] instead,
    /// environment variables included.
    /// On Android it needs an initialized `ndk-context`; without one every
    /// verification fails.
    ///
    /// Native verification may block on network access and is not cancellable.
    /// Boring runs it on Tokio's blocking pool. rustls verifies synchronously:
    /// it uses `block_in_place` on a multithread runtime and runs inline on a
    /// current-thread runtime. A handshake timeout cannot preempt this call;
    /// current-thread executors can be stalled until native verification returns.
    /// Bound concurrent connections and size the blocking pool for native work;
    /// handshake deadlines alone do not bound running platform verifications.
    /// This matters especially for relays whose clients choose upstream hosts
    /// and can steer certificate AIA or OCSP fetches to slow endpoints.
    /// See the `rama_crypto::platform_verifier` module (available with
    /// `rama-crypto`'s `native-certs` feature) for revocation and Android limits.
    Platform(PlatformTrustPolicy),
}

impl ServerTrustSource {
    /// Use a static snapshot of native roots.
    #[must_use]
    pub const fn native_roots() -> Self {
        Self::Native(NativeTrustPolicy::new())
    }

    /// Use the operating system verifier, or static native roots if unavailable.
    #[must_use]
    pub const fn platform_verifier() -> Self {
        Self::Platform(PlatformTrustPolicy::new())
    }
}

impl Default for ServerTrustSource {
    fn default() -> Self {
        Self::native_roots()
    }
}

/// Server trust policy used with [`ServerVerifyMode::Auto`](super::ServerVerifyMode::Auto).
///
/// A backend-specific verifier or store takes precedence. The policy is ignored
/// when server verification is disabled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsServerTrust {
    source: ServerTrustSource,
    additional_anchors: Option<TlsServerTrustAnchors>,
}

impl TlsServerTrust {
    /// Use a snapshot of the native roots, or explicitly configured environment
    /// roots. Bundled WebPKI roots are the fallback only without an environment
    /// override.
    #[must_use]
    pub const fn native_roots() -> Self {
        Self::new(ServerTrustSource::native_roots())
    }

    /// Use Rama's bundled Mozilla (CCADB) roots.
    #[must_use]
    pub const fn webpki_roots() -> Self {
        Self::new(ServerTrustSource::WebPki)
    }

    /// Use only `anchors` as trust roots.
    #[must_use]
    pub const fn custom(anchors: TlsServerTrustAnchors) -> Self {
        Self::new(ServerTrustSource::Custom(anchors))
    }

    /// Delegate chain and server identity validation to the operating system.
    ///
    /// See [`ServerTrustSource::Platform`].
    #[must_use]
    pub const fn platform_verifier() -> Self {
        Self::new(ServerTrustSource::platform_verifier())
    }

    /// Use `source` without additional trust anchors.
    #[must_use]
    pub const fn new(source: ServerTrustSource) -> Self {
        Self {
            source,
            additional_anchors: None,
        }
    }

    /// Return the current source of trust.
    pub fn source(&self) -> &ServerTrustSource {
        &self.source
    }

    /// Return trust anchors added to the source of trust.
    pub fn additional_anchors(&self) -> Option<&TlsServerTrustAnchors> {
        self.additional_anchors.as_ref()
    }

    generate_set_and_with! {
        /// Set the source of trust while retaining additional anchors.
        pub fn source(mut self, source: ServerTrustSource) -> Self {
            self.source = source;
            self
        }
    }

    generate_set_and_with! {
        /// Add certificates to the source of trust.
        ///
        /// With [`ServerTrustSource::Platform`] the certificates are trusted in
        /// addition to the operating system's own trust settings.
        pub fn additional_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.additional_anchors = Some(TlsServerTrustAnchors::try_new(certificates)?);
            Ok(self)
        }
    }
}

impl Default for TlsServerTrust {
    fn default() -> Self {
        Self::native_roots()
    }
}

impl From<NativeTrustPolicy> for TlsServerTrust {
    fn from(policy: NativeTrustPolicy) -> Self {
        Self::new(ServerTrustSource::Native(policy))
    }
}

impl From<PlatformTrustPolicy> for TlsServerTrust {
    fn from(policy: PlatformTrustPolicy) -> Self {
        Self::new(ServerTrustSource::Platform(policy))
    }
}
