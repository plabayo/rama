//! a basic parser for .pem files containing cryptographic keys and certificates
//!
//! The input to this crate is a .pem file containing potentially many sections,
//! and the output is those sections as alleged DER-encodings.  This crate does
//! not decode the actual DER-encoded keys/certificates.
//!
//! > Permanent fork from archived project:
//! > <https://github.com/rustls/pemfile>
//! >
//! > Originally developed by Joseph Birr-Pixton,
//! > See rama third-party fork README for more information.
//!
//! ## Quick start
//!
//! Starting with an `io::BufRead` containing the file to be read:
//! - Use `read_all()` to ingest the whole file, then work through the contents in-memory, or,
//! - Use `read_one()` to stream through the file, processing the items as found, or,
//! - Use `certs()` to extract just the certificates (silently discarding other sections), and
//!   similarly for `rsa_private_keys()` and `pkcs8_private_keys()`.

use std::io;
use std::iter;

use self::pem_file::{Item, read_one};
use crate::dep::pki_types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, PrivateKeyDer,
    PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer, SubjectPublicKeyInfoDer,
};

pub mod pem_file;

/// Return an iterator over certificates from `rd`.
///
/// Filters out any PEM sections that are not certificates and yields errors if a problem
/// occurs while trying to extract a certificate.
pub fn certs(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::X509Certificate(cert)) => Some(Ok(cert)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return the first private key found in `rd`.
///
/// Yields the first PEM section describing a private key (of any type), or an error if a
/// problem occurs while trying to read PEM sections.
pub fn private_key(rd: &mut dyn io::BufRead) -> Result<Option<PrivateKeyDer<'static>>, io::Error> {
    for result in iter::from_fn(move || read_one(rd).transpose()) {
        match result? {
            Item::Pkcs1Key(key) => return Ok(Some(key.into())),
            Item::Pkcs8Key(key) => return Ok(Some(key.into())),
            Item::Sec1Key(key) => return Ok(Some(key.into())),
            Item::X509Certificate(_)
            | Item::SubjectPublicKeyInfo(_)
            | Item::Crl(_)
            | Item::Csr(_) => (),
        }
    }

    Ok(None)
}

/// Return the first certificate signing request (CSR) found in `rd`.
///
/// Yields the first PEM section describing a certificate signing request, or an error if a
/// problem occurs while trying to read PEM sections.
pub fn csr(
    rd: &mut dyn io::BufRead,
) -> Result<Option<CertificateSigningRequestDer<'static>>, io::Error> {
    for result in iter::from_fn(move || read_one(rd).transpose()) {
        match result? {
            Item::Csr(csr) => return Ok(Some(csr)),
            Item::Pkcs1Key(_)
            | Item::Pkcs8Key(_)
            | Item::Sec1Key(_)
            | Item::X509Certificate(_)
            | Item::SubjectPublicKeyInfo(_)
            | Item::Crl(_) => (),
        }
    }

    Ok(None)
}

/// Return an iterator certificate revocation lists (CRLs) from `rd`.
///
/// Filters out any PEM sections that are not CRLs and yields errors if a problem occurs
/// while trying to extract a CRL.
pub fn crls(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateRevocationListDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Crl(crl)) => Some(Ok(crl)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over RSA private keys from `rd`.
///
/// Filters out any PEM sections that are not RSA private keys and yields errors if a problem
/// occurs while trying to extract an RSA private key.
pub fn rsa_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over PKCS8-encoded private keys from `rd`.
///
/// Filters out any PEM sections that are not PKCS8-encoded private keys and yields errors if a
/// problem occurs while trying to extract an RSA private key.
pub fn pkcs8_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs8KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs8Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over SEC1-encoded EC private keys from `rd`.
///
/// Filters out any PEM sections that are not SEC1-encoded EC private keys and yields errors if a
/// problem occurs while trying to extract a SEC1-encoded EC private key.
pub fn ec_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivateSec1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Sec1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over SPKI-encoded keys from `rd`.
///
/// Filters out any PEM sections that are not SPKI-encoded public keys and yields errors if a
/// problem occurs while trying to extract a SPKI-encoded public key.
pub fn public_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<SubjectPublicKeyInfoDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::SubjectPublicKeyInfo(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}
