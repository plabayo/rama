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

pub trait BoringMitmCertIssuer: Sized + Send + Sync + 'static {
    type Error: Send + 'static;

    fn issue_mitm_x509_cert(
        &self,
        original: X509,
    ) -> impl Future<Output = Result<(NonEmptyVec<X509>, PKey<Private>), Self::Error>> + Send + '_;
}

pub use self::{
    cache::{BoringMitmCertIssuerCacheConfig, CachedBoringMitmCertIssuer},
    deny::{CertIssueDeniedError, DenyBoringMitmCertIssuer},
    memory::InMemoryBoringMitmCertIssuer,
    static_pair::StaticBoringMitmCertIssuer,
};
