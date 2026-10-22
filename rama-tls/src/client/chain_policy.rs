use ahash::HashSet;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::Extension,
};
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::Host;
use std::{borrow::Cow, fmt, sync::Arc};

use super::{TlsComponentIdentity, TlsPoolComponent};

/// A reject-only check of the server certificate chain.
///
/// The policy runs after the certificate verifier accepted the chain, for every
/// [`ServerTrustSource`], and also when server verification is disabled. It can
/// therefore only reject a connection, never accept a chain the verifier refused.
///
/// A resumed session is bound to the policy it was established under. The
/// BoringSSL backend checks the session's stored chain against the policy
/// again on resumption; the rustls backend resumes without a new check, as
/// TLS does for verification in general.
///
/// [`ServerTrustSource`]: super::ServerTrustSource
pub trait TlsServerCertChainPolicy: fmt::Debug + Send + Sync + 'static {
    /// Return an error to reject `chain`.
    fn check(&self, chain: &ServerCertChain<'_>) -> Result<(), BoxError>;
}

/// How a [`ServerCertChain`] was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerCertChainKind {
    /// The path the verifier built and accepted: leaf first, ending at the
    /// trust anchor, which the server may not have sent.
    Verified,
    /// The certificates in the order the server sent them, leaf first: no
    /// verified path is known, because verification is disabled or done by
    /// a custom verifier.
    Presented,
}

/// A server certificate chain handed to a [`TlsServerCertChainPolicy`].
#[derive(Debug, Clone)]
pub struct ServerCertChain<'a> {
    kind: ServerCertChainKind,
    server_name: Option<&'a Host>,
    certificates: &'a [ServerChainCertificate<'a>],
}

impl<'a> ServerCertChain<'a> {
    /// Create a chain, leaf first.
    #[must_use]
    pub const fn new(
        kind: ServerCertChainKind,
        server_name: Option<&'a Host>,
        certificates: &'a [ServerChainCertificate<'a>],
    ) -> Self {
        Self {
            kind,
            server_name,
            certificates,
        }
    }

    /// How this chain was obtained.
    #[must_use]
    pub const fn kind(&self) -> ServerCertChainKind {
        self.kind
    }

    /// The server identity the connection was made for, if any.
    #[must_use]
    pub const fn server_name(&self) -> Option<&'a Host> {
        self.server_name
    }

    /// The certificates, leaf first.
    #[must_use]
    pub const fn certificates(&self) -> &'a [ServerChainCertificate<'a>] {
        self.certificates
    }
}

/// One certificate of a [`ServerCertChain`].
#[derive(Debug, Clone)]
pub struct ServerChainCertificate<'a>(ChainEntry<'a>);

#[derive(Debug, Clone)]
enum ChainEntry<'a> {
    Certificate(CertificateDer<'a>),
    TrustAnchor(Cow<'a, [u8]>),
}

impl<'a> ServerChainCertificate<'a> {
    /// A complete DER-encoded certificate.
    #[must_use]
    pub const fn certificate(certificate: CertificateDer<'a>) -> Self {
        Self(ChainEntry::Certificate(certificate))
    }

    /// A trust anchor known only by its DER-encoded `SubjectPublicKeyInfo`,
    /// as some verifiers store their roots.
    #[must_use]
    pub const fn trust_anchor(subject_public_key_info: Cow<'a, [u8]>) -> Self {
        Self(ChainEntry::TrustAnchor(subject_public_key_info))
    }

    /// The DER-encoded certificate, unless only the trust anchor key is known.
    #[must_use]
    pub fn as_certificate(&self) -> Option<&CertificateDer<'a>> {
        match &self.0 {
            ChainEntry::Certificate(certificate) => Some(certificate),
            ChainEntry::TrustAnchor(_) => None,
        }
    }

    /// SHA-256 of the `SubjectPublicKeyInfo`, the same digest as a key pin.
    pub fn spki_sha256(&self) -> Result<[u8; 32], BoxError> {
        match &self.0 {
            ChainEntry::Certificate(certificate) => rama_crypto::cert::spki_sha256(certificate),
            ChainEntry::TrustAnchor(spki) => Ok(rama_crypto::cert::sha256(spki)),
        }
    }
}

/// A shared, type-erased [`TlsServerCertChainPolicy`], as enforced by a TLS
/// client. Every policy converts into one.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct DynTlsServerCertChainPolicy(Arc<dyn TlsServerCertChainPolicy>);

impl DynTlsServerCertChainPolicy {
    /// Enforce `policy`.
    pub fn new(policy: impl TlsServerCertChainPolicy) -> Self {
        Self(Arc::new(policy))
    }

    /// Enforce a shared `policy`.
    #[must_use]
    pub fn from_shared(policy: Arc<dyn TlsServerCertChainPolicy>) -> Self {
        Self(policy)
    }

    /// Check `chain` against the policy.
    pub fn check(&self, chain: &ServerCertChain<'_>) -> Result<(), BoxError> {
        self.0.check(chain)
    }
}

impl<P: TlsServerCertChainPolicy> From<P> for DynTlsServerCertChainPolicy {
    fn from(policy: P) -> Self {
        Self::new(policy)
    }
}

impl TlsPoolComponent for DynTlsServerCertChainPolicy {
    type Identity = TlsComponentIdentity<dyn TlsServerCertChainPolicy>;

    fn pool_component_identity(&self) -> Self::Identity {
        TlsComponentIdentity::shared(&self.0)
    }
}

/// Reject server chains that contain any of a set of distrusted public keys.
///
/// Keys are matched by the SHA-256 of their `SubjectPublicKeyInfo` at every
/// position of the chain, so a distrusted CA is caught under any of its
/// certificates, including cross-signed ones. Configured as `sha256/<base64>`,
/// the format of a key pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DistrustedServerKeys {
    spki_sha256: HashSet<[u8; 32]>,
}

impl DistrustedServerKeys {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Distrust the key with the given `SubjectPublicKeyInfo` SHA-256 digest.
    #[must_use]
    pub fn with_spki_sha256(mut self, digest: [u8; 32]) -> Self {
        self.spki_sha256.insert(digest);
        self
    }

    /// Distrust the public key of `certificate`.
    pub fn try_with_key_of(self, certificate: &CertificateDer<'_>) -> Result<Self, BoxError> {
        Ok(self.with_spki_sha256(rama_crypto::cert::spki_sha256(certificate)?))
    }

    /// Whether no key is distrusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spki_sha256.is_empty()
    }
}

impl std::str::FromStr for DistrustedServerKeys {
    type Err = BoxError;

    /// Parse whitespace- or comma-separated `sha256/<base64>` digests.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|key| !key.is_empty())
            .try_fold(Self::new(), |keys, key| {
                let digest = key.strip_prefix("sha256/").ok_or_else(|| {
                    BoxError::from_static_str("distrusted key must use the sha256/<base64> format")
                })?;
                let digest: [u8; 32] = BASE64_STANDARD
                    .decode(digest)
                    .context("decode base64 distrusted key digest")?
                    .as_slice()
                    .try_into()
                    .context("distrusted key digest must be 32 bytes")?;
                Ok(keys.with_spki_sha256(digest))
            })
    }
}

impl TlsServerCertChainPolicy for DistrustedServerKeys {
    fn check(&self, chain: &ServerCertChain<'_>) -> Result<(), BoxError> {
        for (position, certificate) in chain.certificates().iter().enumerate() {
            let digest = certificate.spki_sha256()?;
            if self.spki_sha256.contains(&digest) {
                return Err(BoxError::from_static_str(
                    "server certificate chain uses a distrusted key",
                )
                .context_field("position", position)
                .context_str_field("key", format!("sha256/{}", BASE64_STANDARD.encode(digest))));
            }
        }
        Ok(())
    }
}
