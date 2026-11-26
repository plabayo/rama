use std::path::Path;

use super::{CertPaths, CertificateResult, discover_cert_paths};

pub(super) fn load_native_certs() -> CertificateResult {
    system_paths().load()
}

pub(super) fn system_paths() -> CertPaths {
    discover_cert_paths(
        CERTIFICATE_FILE_NAMES.iter().map(Path::new),
        CERTIFICATE_DIRS.iter().map(Path::new),
    )
}

#[cfg(target_os = "linux")]
const CERTIFICATE_DIRS: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/security/certificates",
];

#[cfg(target_os = "freebsd")]
const CERTIFICATE_DIRS: &[&str] = &["/etc/ssl/certs", "/usr/local/share/certs"];

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
const CERTIFICATE_DIRS: &[&str] = &["/etc/certs/CA"];

#[cfg(target_os = "netbsd")]
const CERTIFICATE_DIRS: &[&str] = &["/etc/openssl/certs"];

#[cfg(target_os = "aix")]
const CERTIFICATE_DIRS: &[&str] = &["/var/ssl/certs"];

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "netbsd",
    target_os = "aix"
)))]
const CERTIFICATE_DIRS: &[&str] = &["/etc/ssl/certs"];

#[cfg(target_os = "linux")]
const CERTIFICATE_FILE_NAMES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
    "/opt/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/certs/cacert.pem",
];

#[cfg(target_os = "freebsd")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/usr/local/etc/ssl/cert.pem"];

#[cfg(target_os = "dragonfly")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/usr/local/share/certs/ca-root-nss.crt"];

#[cfg(target_os = "netbsd")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/etc/openssl/certs/ca-certificates.crt"];

#[cfg(target_os = "openbsd")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/etc/ssl/cert.pem"];

#[cfg(target_os = "solaris")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/etc/certs/ca-certificates.crt"];

#[cfg(target_os = "illumos")]
const CERTIFICATE_FILE_NAMES: &[&str] = &[
    "/etc/ssl/cacert.pem",
    "/etc/certs/ca-certificates.crt",
    "/etc/ssl/certs/ca-certificates.crt",
];

#[cfg(target_os = "android")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/data/data/com.termux/files/usr/etc/tls/cert.pem"];

#[cfg(target_os = "haiku")]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/boot/system/data/ssl/CARootCertificates.pem"];

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "android",
    target_os = "haiku",
)))]
const CERTIFICATE_FILE_NAMES: &[&str] = &["/etc/ssl/certs/ca-certificates.crt"];
