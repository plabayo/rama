//! One-shot trust loading with certificate validation and source error checks.
//!
//! Callers decide when to read again and how long to keep a previous result.

use super::{
    CertPaths, CertificateDer, CertificateResult, ENV_EXTRA_CERT_DIR, ENV_EXTRA_CERT_FILE,
    sort_and_deduplicate,
};
use crate::pki_types::pem::{self, PemObject as _};
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    telemetry::tracing::debug,
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

/// Read and validate the native roots and environment-supplied extra roots once.
///
/// Returns the deduplicated anchors and whether bundled roots supplied the base
/// store. Set `allow_bundled_fallback` on initial load if bundled roots are
/// acceptable on an empty system. Passing the returned flag on subsequent
/// reads prevents an empty system store from expanding an existing trust policy.
/// Explicit replacement paths always take precedence. This operation may block.
pub fn load_validated_native_certs(
    allow_bundled_fallback: bool,
) -> Result<(Vec<CertificateDer<'static>>, bool), BoxError> {
    let base_paths = CertPaths::from_env();
    let extra_paths = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
    load_from_sources(
        &base_paths,
        &extra_paths,
        allow_bundled_fallback,
        load_system_roots,
    )
}

/// Read, validate, and deduplicate the roots configured by `SSL_CERT_EXTRA_FILE`
/// and `SSL_CERT_EXTRA_DIR` in one pass. These roots supplement the live platform verifier.
///
/// This read may block. It only consults the extra-root paths.
pub fn load_validated_extra_certs() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let extra_paths = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
    let mut certs = checked_load_paths(&extra_paths)?;
    sort_and_deduplicate(&mut certs);
    Ok(certs)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn load_system_roots() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    load_system_paths(&super::unix::system_paths())
}

#[cfg(target_os = "macos")]
fn load_system_roots() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    checked_system_load(super::macos::load_native_certs_for_validation())
}

#[cfg(windows)]
fn load_system_roots() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    checked_system_load(super::platform::load_native_certs())
}

fn load_from_sources(
    base: &CertPaths,
    extra: &CertPaths,
    allow_bundled_fallback: bool,
    load_system: impl FnOnce() -> Result<Vec<CertificateDer<'static>>, BoxError>,
) -> Result<(Vec<CertificateDer<'static>>, bool), BoxError> {
    let has_overrides = base.has_overrides();
    let mut certs = if has_overrides {
        checked_load_paths(base)?
    } else {
        load_system()?
    };
    let used_bundled_fallback = allow_bundled_fallback && !has_overrides && certs.is_empty();
    if used_bundled_fallback {
        certs.extend_from_slice(super::bundled_root_certs());
    }

    certs.extend(checked_load_paths(extra)?);
    sort_and_deduplicate(&mut certs);
    Ok((certs, used_bundled_fallback))
}

// A malformed explicit bundle fails the read, while bad directory entries are skipped.
fn checked_load_paths(paths: &CertPaths) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let mut bundle_certs = 0;
    let result = super::read_cert_paths(paths.file.as_deref(), &paths.dirs, |path, out| {
        let errors = out.errors.len();
        load_bundle(path, out, false);
        if out.errors.len() > errors {
            out.source_error.get_or_insert(errors);
        }
        bundle_certs = out.certs.len();
    });
    checked_load(result, bundle_certs)
}

#[cfg(all(unix, any(test, not(target_os = "macos"))))]
fn load_system_paths(paths: &CertPaths) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let result = super::read_cert_paths(paths.file.as_deref(), &paths.dirs, |path, out| {
        load_bundle(path, out, true);
    });
    checked_system_load(result)
}

// An empty bundle can intentionally withdraw all trust. Nonempty text must
// contain certificates for a validated read to succeed.
fn load_bundle(path: &Path, result: &mut CertificateResult, authoritative: bool) {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            if authoritative {
                result.source_io_error(error, path, "opening native trust bundle");
            } else {
                result.io_error(error, path, "opening native trust bundle");
            }
            return;
        }
    };
    let mut reader = BundleReader {
        file,
        has_content: false,
    };
    let mut found_entry = false;
    for entry in CertificateDer::pem_reader_iter(&mut reader) {
        found_entry = true;
        match entry {
            Ok(cert) => result.certs.push(cert),
            Err(pem::Error::Io(error)) if authoritative => {
                result.source_io_error(error, path, "reading native trust bundle");
            }
            Err(error) => result.pem_error(error, path),
        }
    }
    if !found_entry && reader.has_content {
        result.io_error(
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no PEM certificates in nonempty native trust file",
            ),
            path,
            "reading native trust bundle",
        );
    }
}

struct BundleReader {
    file: File,
    has_content: bool,
}

impl Read for BundleReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(buffer)?;
        self.has_content = self.has_content
            || buffer[..count]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace());
        Ok(count)
    }
}

fn checked_system_load(
    result: CertificateResult,
) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    checked_load(result, 0)
}

/// Fails on a source error or an invalid certificate among the first `strict_certs`;
/// other bad entries are skipped unless nothing valid remains.
fn checked_load(
    mut result: CertificateResult,
    strict_certs: usize,
) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    if let Some(index) = result.source_error {
        return Err(result.errors.swap_remove(index).into());
    }
    for cert in &result.certs[..strict_certs] {
        validate_anchor(cert)?;
    }

    let mut first_error = None;
    for error in result.errors {
        debug!(%error, "skipping invalid native trust entry");
        first_error.get_or_insert_with(|| error.into());
    }
    let mut index = 0;
    result.certs.retain(|cert| {
        index += 1;
        if index <= strict_certs {
            return true;
        }
        match validate_anchor(cert) {
            Ok(()) => true,
            Err(error) => {
                debug!(%error, "skipping invalid native trust certificate");
                first_error.get_or_insert(error);
                false
            }
        }
    });
    if result.certs.is_empty()
        && let Some(error) = first_error
    {
        return Err(error);
    }
    Ok(result.certs)
}

fn validate_anchor(cert: &CertificateDer<'static>) -> Result<(), BoxError> {
    let (rest, _) =
        x509_parser::parse_x509_certificate(cert).context("parse native trust certificate")?;
    if !rest.is_empty() {
        return Err(BoxError::from_static_str(
            "unexpected trailing bytes in native trust certificate",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
