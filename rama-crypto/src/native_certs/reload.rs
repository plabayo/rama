use super::{
    CertPaths, CertificateDer, CertificateResult, ENV_EXTRA_CERT_DIR, ENV_EXTRA_CERT_FILE,
};
use crate::pki_types::pem::PemObject as _;
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

/// Read the native roots and environment-supplied extra roots for a fresh snapshot.
///
/// Returns the deduplicated anchors and whether bundled roots supplied the base
/// store. Set `allow_bundled_fallback` on initial load if bundled roots are
/// acceptable on an empty system. Passing the returned flag on subsequent
/// reads prevents an empty system store from expanding an existing trust policy.
/// Explicit replacement paths always take precedence. This operation may block.
pub fn load_reloadable_native_certs(
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

#[cfg(all(unix, not(target_os = "macos")))]
fn load_system_roots() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    checked_load_paths(&super::unix::system_paths())
}

#[cfg(any(target_os = "macos", windows))]
fn load_system_roots() -> Result<Vec<CertificateDer<'static>>, BoxError> {
    checked_load(super::platform::load_native_certs())
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
    certs.sort_unstable_by(|a, b| a.cmp(b));
    certs.dedup();
    Ok((certs, used_bundled_fallback))
}

fn checked_load_paths(paths: &CertPaths) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let result = super::read_cert_paths(paths.file.as_deref(), &paths.dirs, load_bundle);
    checked_load(result)
}

// For a reload, an empty bundle can intentionally withdraw all trust. Reject a
// nonempty file with no certificates so a malformed update keeps the last snapshot.
fn load_bundle(path: &Path, result: &mut CertificateResult) {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            result.io_error(error, path, "opening native trust bundle");
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

fn checked_load(result: CertificateResult) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    if let Some(error) = result.errors.into_iter().next() {
        return Err(error.into());
    }
    for cert in &result.certs {
        let (rest, _) =
            x509_parser::parse_x509_certificate(cert).context("parse native trust certificate")?;
        if !rest.is_empty() {
            return Err(BoxError::from_static_str(
                "unexpected trailing bytes in native trust certificate",
            ));
        }
    }
    Ok(result.certs)
}

#[cfg(all(test, unix))]
mod tests;
