use std::{convert::Infallible, fmt};

use rama_boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use rama_utils::collections::NonEmptyVec;

use super::BoringMitmCertIssuer;

#[derive(Clone)]
/// A [`BoringMitmCertIssuer`] which clones its own pair data,
/// for each issued cert, completely ignoring the original reference.
pub struct StaticBoringMitmCertIssuer {
    crt_chain: NonEmptyVec<X509>,
    key: PKey<Private>,
}

impl fmt::Debug for StaticBoringMitmCertIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticBoringMitmCertIssuer")
            .field("crt_chain", &self.crt_chain)
            .field("key", &"PKey<Private>")
            .finish()
    }
}

impl StaticBoringMitmCertIssuer {
    #[inline(always)]
    /// Create a new [`StaticBoringMitmCertIssuer`].
    #[must_use]
    pub fn new(crt_chain: NonEmptyVec<X509>, key: PKey<Private>) -> Self {
        Self { crt_chain, key }
    }
}

impl BoringMitmCertIssuer for StaticBoringMitmCertIssuer {
    type Error = Infallible;

    #[inline(always)]
    fn issue_mitm_x509_cert(
        &self,
        _: X509,
    ) -> impl Future<Output = Result<(NonEmptyVec<X509>, PKey<Private>), Self::Error>> + Send + '_
    {
        std::future::ready(Ok((self.crt_chain.clone(), self.key.clone())))
    }
}
