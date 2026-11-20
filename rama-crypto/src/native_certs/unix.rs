use super::{CertPaths, CertificateResult};

pub(super) fn load_native_certs() -> CertificateResult {
    system_paths().load()
}

pub(super) fn system_paths() -> CertPaths {
    let likely_locations = openssl_probe::probe();
    CertPaths {
        file: likely_locations.cert_file,
        dirs: likely_locations.cert_dir,
    }
}
