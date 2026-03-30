use std::fmt;

use rama_boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use rama_core::error::BoxError;
use rama_net::tls::server::SelfSignedData;
use rama_utils::collections::{NonEmptyVec, non_empty_vec};

use crate::server::utils::self_signed_server_auth_gen_ca;

use super::BoringMitmCertIssuer;

#[derive(Clone)]
/// A [`BoringMitmCertIssuer`] which mirrors the original reference
/// using its internal (in-memory) CA crt/key pair to sign.
pub struct InMemoryBoringMitmCertIssuer {
    ca_crt: X509,
    ca_key: PKey<Private>,
}

impl fmt::Debug for InMemoryBoringMitmCertIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryBoringMitmCertIssuer")
            .field("ca_crt", &self.ca_crt)
            .field("ca_key", &"PKey<Private>")
            .finish()
    }
}

impl InMemoryBoringMitmCertIssuer {
    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`].
    #[must_use]
    pub fn new(ca_crt: X509, ca_key: PKey<Private>) -> Self {
        Self { ca_crt, ca_key }
    }

    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`] with self-signed CA using the given data.
    pub fn try_new_self_signed(data: &SelfSignedData) -> Result<Self, BoxError> {
        let (ca_cert, ca_privkey) = self_signed_server_auth_gen_ca(data)?;
        Ok(Self::new(ca_cert, ca_privkey))
    }
}

impl BoringMitmCertIssuer for InMemoryBoringMitmCertIssuer {
    type Error = BoxError;

    #[inline(always)]
    async fn issue_mitm_x509_cert(
        &self,
        original: X509,
    ) -> Result<(NonEmptyVec<X509>, PKey<Private>), Self::Error> {
        let (crt, key) = crate::server::utils::self_signed_server_auth_mirror_cert(
            &original,
            &self.ca_crt,
            &self.ca_key,
        )?;
        Ok((non_empty_vec![crt, self.ca_crt.clone()], key))
    }
}
