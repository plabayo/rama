use crate::dep::pki_types::pem::PemObject;
use crate::dep::pki_types::{CertificateDer, PrivateKeyDer};
use rama_core::error::{BoxError, ErrorContext};

// TODO move all certificate parsing / utils in here

/// Parse a PEM buffer into a DER certificate chain
pub fn pem_to_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certificate chain")
}

/// Parse a PEM buffer into a single private key
///
/// The first key section PKCS#8 / PKCS#1 / SEC1 are auto-detected
pub fn pem_to_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, BoxError> {
    PrivateKeyDer::from_pem_slice(pem).context("parse PEM private key")
}
