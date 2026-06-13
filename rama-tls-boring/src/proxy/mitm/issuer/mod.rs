use std::{fmt, sync::Arc};

use rama_boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use rama_utils::collections::NonEmptyVec;

mod cache;
mod deny;
mod either;
mod memory;
mod static_pair;

/// A MITM leaf certificate minted by a [`BoringMitmCertIssuer`]: the cert chain
/// (`leaf` first, then the signing CA chain), the leaf private key, and an
/// optional pre-built OCSP `good` staple for the leaf.
#[derive(Clone)]
pub struct MitmIssuedCert {
    /// Leaf certificate first, followed by the issuing CA chain.
    pub crt_chain: NonEmptyVec<X509>,
    /// Private key of the leaf certificate.
    pub key: PKey<Private>,
    /// DER-encoded OCSP response (`good`) for the leaf, signed by the MITM CA
    /// that issued it, ready to staple via `SslRef::set_ocsp_status`.
    ///
    /// `None` when stapling does not apply — e.g. the upstream certificate
    /// advertised no OCSP, or staple generation was skipped/failed (stapling is
    /// best-effort and never blocks issuance).
    pub ocsp_staple: Option<Arc<[u8]>>,
}

impl fmt::Debug for MitmIssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmIssuedCert")
            .field("crt_chain", &self.crt_chain)
            .field("key", &"PKey<Private>")
            .field("ocsp_staple", &self.ocsp_staple.as_ref().map(|s| s.len()))
            .finish()
    }
}

pub trait BoringMitmCertIssuer: Sized + Send + Sync + 'static {
    type Error: Send + 'static;

    fn issue_mitm_x509_cert(
        &self,
        original: X509,
    ) -> impl Future<Output = Result<MitmIssuedCert, Self::Error>> + Send + '_;
}

pub use self::{
    cache::{BoringMitmCertIssuerCacheConfig, CachedBoringMitmCertIssuer},
    deny::{CertIssueDeniedError, DenyBoringMitmCertIssuer},
    memory::InMemoryBoringMitmCertIssuer,
    static_pair::StaticBoringMitmCertIssuer,
};
