use rama_boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use rama_utils::{collections::NonEmptyVec, macros::error::static_str_error};

use super::BoringMitmCertIssuer;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// a [`BoringMitmCertIssuer`] implementation which
/// denies all incoming cert issue requests with a [`CertIssueDeniedError`].
pub struct DenyBoringMitmCertIssuer;

impl DenyBoringMitmCertIssuer {
    #[inline(always)]
    /// Create a new [`Default`] [`DenyBoringMitmCertIssuer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

static_str_error! {
    #[doc = "cert issueing denied"]
    pub struct CertIssueDeniedError;
}

impl BoringMitmCertIssuer for DenyBoringMitmCertIssuer {
    type Error = CertIssueDeniedError;

    fn issue_mitm_x509_cert(
        &self,
        _: X509,
    ) -> impl Future<Output = Result<(NonEmptyVec<X509>, PKey<Private>), Self::Error>> + Send + '_
    {
        std::future::ready(Err(CertIssueDeniedError))
    }
}
