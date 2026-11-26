//! Load the platform's native certificate store (system trust chain) in a
//! tls-implementation agnostic way, as [`pki_types`] certificates.
//!
//! The certificates returned here can be fed into any tls backend (e.g.
//! `rustls` or `boring`), which is why this lives in `rama-crypto` rather than
//! in one of the tls backend crates.
//!
//! The main entry points are:
//!
//! - [`shared_native_trust_anchors`]: the cached, process-wide default trust
//!   anchors used by rama tls clients. Loads the native store once; if nothing
//!   is found it warns and falls back to the bundled webpki roots.
//! - [`load_native_certs`]: a one-shot (uncached) read of the platform store,
//!   for callers that want to manage caching/merging themselves.
//! - [`bundled_root_certs`]: the bundled Mozilla (CCADB) root certificates used
//!   as the fallback.
//!
//! # Attribution
//!
//! The platform readers and `SSL_CERT_FILE`/`SSL_CERT_DIR` handling are an
//! adapted fork of [`rustls-native-certs`] (Apache-2.0 OR ISC OR MIT), with the
//! pending [permission-skip fix][pr228] folded in and the public surface
//! reshaped around rama's [`pki_types`] re-export, error and tracing
//! conventions.
//!
//! [`pki_types`]: crate::pki_types
//! [`rustls-native-certs`]: https://github.com/rustls/rustls-native-certs
//! [pr228]: https://github.com/rustls/rustls-native-certs/pull/228

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::{
    env,
    error::Error as StdError,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};

use rama_core::{
    error::BoxError,
    telemetry::tracing::{debug, warn},
};

use crate::pki_types::{
    CertificateDer,
    pem::{self, PemObject},
};

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(any(target_os = "macos", windows))]
mod notifications;

mod changes;
mod load;
#[doc(inline)]
pub use changes::{NativeCertsChanges, NativeCertsWake};
#[doc(inline)]
pub use load::{load_validated_extra_certs, load_validated_native_certs};

type SharedTrustAnchors = Arc<[CertificateDer<'static>]>;

/// Returns the cached, process-wide default trust anchors used by rama tls
/// clients (both the `rustls` and `boring` backends consume these).
///
/// On first call this loads the platform's native certificate store via
/// [`load_native_certs`] (honoring `SSL_CERT_FILE`/`SSL_CERT_DIR`). If the
/// native store yields no certificates, a warning is logged and the bundled
/// webpki roots ([`bundled_root_certs`]) are used instead so that clients on
/// minimal systems (e.g. distroless containers) still have a sane default.
///
/// The [`shared_extra_trust_anchors`] are always added.
///
/// The result is cached for the lifetime of the process: the (potentially
/// expensive) native read happens at most once.
pub fn shared_native_trust_anchors() -> Arc<[CertificateDer<'static>]> {
    NATIVE_TRUST_ANCHORS.clone()
}

/// Acquire the process-wide anchors from [`shared_native_trust_anchors`].
///
/// When the cache is cold, initialization runs on a Tokio blocking worker.
/// Once the anchors are cached, they are returned directly.
pub async fn shared_native_trust_anchors_async() -> Result<Arc<[CertificateDer<'static>]>, BoxError>
{
    acquire_trust_anchors(&NATIVE_TRUST_ANCHORS).await
}

static NATIVE_TRUST_ANCHORS: LazyLock<SharedTrustAnchors> = LazyLock::new(|| {
    let paths = CertPaths::from_env();
    let result = load_native_certs_with_paths(&paths);
    for err in &result.errors {
        debug!(%err, "rama native-certs: error while loading native root certificate");
    }

    native_base(&result, paths.has_overrides())
        .iter()
        .chain(shared_extra_trust_anchors().iter())
        .cloned()
        .collect()
});

/// The native roots, or the bundled roots when an unconfigured system store
/// holds none. Unreadable entries never enable that fallback.
fn native_base(result: &CertificateResult, has_overrides: bool) -> &[CertificateDer<'static>] {
    if !result.certs.is_empty() || has_overrides {
        debug!(
            native_cert_count = result.certs.len(),
            "rama native-certs: loaded native system root certificates"
        );
        return &result.certs;
    }
    if result.unreadable.is_some() {
        warn!(
            native_cert_errors = result.errors.len(),
            "rama native-certs: native root certificate files are unreadable; \
             trusting no native roots instead of the bundled webpki root certificates"
        );
        return &result.certs;
    }
    warn!(
        native_cert_errors = result.errors.len(),
        "rama native-certs: no native system root certificates found; \
         falling back to the bundled webpki (Mozilla CCADB) root certificates"
    );
    bundled_root_certs()
}

/// Returns the cached, process-wide extra trust anchors, loaded from
/// `SSL_CERT_EXTRA_FILE` (a PEM file) and `SSL_CERT_EXTRA_DIR` (directories,
/// split like `SSL_CERT_DIR`).
///
/// Unlike `SSL_CERT_FILE` and `SSL_CERT_DIR`, which replace the native store,
/// these are trusted in addition to it, and also by the platform verifier.
/// Empty when neither variable is set.
pub fn shared_extra_trust_anchors() -> Arc<[CertificateDer<'static>]> {
    EXTRA_TRUST_ANCHORS.clone()
}

/// Acquire the process-wide anchors from [`shared_extra_trust_anchors`].
///
/// When the cache is cold, initialization runs on a Tokio blocking worker.
/// Once the anchors are cached, they are returned directly.
pub async fn shared_extra_trust_anchors_async() -> Result<Arc<[CertificateDer<'static>]>, BoxError>
{
    acquire_trust_anchors(&EXTRA_TRUST_ANCHORS).await
}

static EXTRA_TRUST_ANCHORS: LazyLock<SharedTrustAnchors> = LazyLock::new(|| {
    let paths = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
    if !paths.has_overrides() {
        return Arc::default();
    }
    let result = paths.load();
    for err in &result.errors {
        warn!(%err, "rama native-certs: error while loading extra root certificate");
    }
    debug!(
        extra_cert_count = result.certs.len(),
        "rama native-certs: loaded extra root certificates"
    );
    result.certs.into()
});

async fn acquire_trust_anchors(
    anchors: &'static LazyLock<SharedTrustAnchors>,
) -> Result<SharedTrustAnchors, BoxError> {
    if let Some(anchors) = LazyLock::get(anchors) {
        return Ok(anchors.clone());
    }
    Ok(tokio::task::spawn_blocking(move || LazyLock::force(anchors).clone()).await?)
}

/// The bundled Mozilla (CCADB) root certificates, used as the fallback by
/// [`shared_native_trust_anchors`] and available for explicit use.
///
/// This is a re-export of the data shipped by the [`webpki-root-certs`] crate.
///
/// [`webpki-root-certs`]: https://docs.rs/webpki-root-certs
pub fn bundled_root_certs() -> &'static [CertificateDer<'static>] {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
}

/// Load root certificates found in the platform's native certificate store.
///
/// ## Environment Variables
///
/// | Env. Var.     | Description                                                       |
/// |---------------|-------------------------------------------------------------------|
/// | SSL_CERT_FILE | File containing an arbitrary number of certificates in PEM format.|
/// | SSL_CERT_DIR  | `:`/`;` separated list of directories containing certificate files.|
///
/// If **either** (or **both**) are set, certificates are only loaded from the
/// locations specified via environment variables and not the platform-native
/// certificate store. `SSL_CERT_EXTRA_FILE` and `SSL_CERT_EXTRA_DIR` add to
/// the store instead, see [`shared_extra_trust_anchors`].
///
/// ## Caveats
///
/// This function can be expensive: on some platforms it involves loading and
/// parsing a ~300KB disk file, or querying the OS keychain. Prefer
/// [`shared_native_trust_anchors`] which caches the result.
pub fn load_native_certs() -> CertificateResult {
    load_native_certs_with_paths(&CertPaths::from_env())
}

fn load_native_certs_with_paths(paths: &CertPaths) -> CertificateResult {
    match paths.has_overrides() {
        true => paths.load(),
        _ => platform::load_native_certs(),
    }
}

/// Results from trying to load certificates from the platform's native store.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CertificateResult {
    /// Any certificates that were successfully loaded.
    pub certs: Vec<CertificateDer<'static>>,
    /// Any errors encountered while loading certificates.
    pub errors: Vec<Error>,
    /// Index of the first native trust source error.
    source_error: Option<usize>,
    /// Index of the first filesystem read failure other than a missing path.
    unreadable: Option<usize>,
}

impl CertificateResult {
    fn pem_error(&mut self, err: pem::Error, path: &Path) {
        if let pem::Error::Io(error) = &err
            && error.kind() != io::ErrorKind::NotFound
        {
            self.unreadable.get_or_insert(self.errors.len());
        }
        self.errors.push(Error {
            context: "failed to read PEM from file",
            kind: match err {
                pem::Error::Io(err) => ErrorKind::Io {
                    inner: err,
                    path: path.to_owned(),
                },
                _ => ErrorKind::Pem(err),
            },
        });
    }

    fn io_error(&mut self, err: io::Error, path: &Path, context: &'static str) {
        if err.kind() != io::ErrorKind::NotFound {
            self.unreadable.get_or_insert(self.errors.len());
        }
        self.errors.push(Error {
            context,
            kind: ErrorKind::Io {
                inner: err,
                path: path.to_owned(),
            },
        });
    }

    fn source_io_error(&mut self, err: io::Error, path: &Path, context: &'static str) {
        self.source_error.get_or_insert(self.errors.len());
        self.io_error(err, path, context);
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn os_source_error(
        &mut self,
        err: Box<dyn StdError + Send + Sync + 'static>,
        context: &'static str,
    ) {
        self.source_error.get_or_insert(self.errors.len());
        self.os_error(err, context);
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn os_error(&mut self, err: Box<dyn StdError + Send + Sync + 'static>, context: &'static str) {
        self.errors.push(Error {
            context,
            kind: ErrorKind::Os(err),
        });
    }
}

/// Certificate paths from a file and/or directory environment variable pair.
struct CertPaths {
    file: Option<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl CertPaths {
    fn from_env() -> Self {
        Self::from_env_vars(ENV_CERT_FILE, ENV_CERT_DIR)
    }

    fn from_env_vars(file_var: &str, dir_var: &str) -> Self {
        Self {
            file: env::var_os(file_var).map(PathBuf::from),
            // Read `SSL_CERT_DIR`, split it on the platform delimiter (`:` on
            // unix, `;` on windows), ignoring empty entries.
            //
            // See <https://docs.openssl.org/3.5/man1/openssl-rehash/#options>
            dirs: match env::var_os(dir_var) {
                Some(dirs) => env::split_paths(&dirs)
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect(),
                None => Vec::new(),
            },
        }
    }

    fn load(&self) -> CertificateResult {
        load_certs_from_paths_internal(self.file.as_deref(), &self.dirs)
    }

    fn has_overrides(&self) -> bool {
        self.file.is_some() || !self.dirs.is_empty()
    }
}

#[cfg(all(unix, any(not(target_os = "macos"), test)))]
fn discover_cert_paths<'a>(
    files: impl IntoIterator<Item = &'a Path>,
    dirs: impl IntoIterator<Item = &'a Path>,
) -> CertPaths {
    let candidate = |path: &&Path| path.try_exists().unwrap_or(true);
    CertPaths {
        file: files.into_iter().find(candidate).map(Path::to_path_buf),
        dirs: dirs
            .into_iter()
            .filter(candidate)
            .map(Path::to_path_buf)
            .collect(),
    }
}

/// Load certificates from the given paths.
///
/// If both are `None`, returns an empty [`CertificateResult`].
///
/// If `file` is `Some`, it must be a path to an existing, accessible file from
/// which certificates can be loaded. The PEM parser ignores parts of the file
/// which are not considered part of a certificate; malformed certificates may
/// be silently skipped.
///
/// If `dir` is defined, a directory must exist at this path. The directory is
/// not scanned recursively and may be empty; entries that are not readable
/// (e.g. root-only files) and PEM sections other than certificates (e.g. the
/// CRLs `openssl rehash` links as `<hash>.r0`) are skipped.
///
/// On Unix, each file is read at most once: directory entries that resolve to a file
/// already read (for example the symlinks created by `openssl rehash`, or a link to
/// `file`) are skipped.
pub fn load_certs_from_paths(file: Option<&Path>, dir: Option<&Path>) -> CertificateResult {
    let dir = match dir {
        Some(d) => vec![d],
        None => Vec::new(),
    };

    load_certs_from_paths_internal(file, dir.as_ref())
}

fn load_certs_from_paths_internal(
    file: Option<&Path>,
    dir: &[impl AsRef<Path>],
) -> CertificateResult {
    let mut out = read_cert_paths(file, dir, load_pem_certs);
    sort_and_deduplicate(&mut out.certs);
    out
}

fn sort_and_deduplicate(certs: &mut Vec<CertificateDer<'static>>) {
    certs.sort_unstable_by(|a, b| a.cmp(b));
    certs.dedup();
}

/// Reads the bundle `file` first, then every directory entry with [`load_dir_entry`].
fn read_cert_paths(
    file: Option<&Path>,
    dirs: &[impl AsRef<Path>],
    read_bundle: impl FnOnce(&Path, &mut CertificateResult),
) -> CertificateResult {
    let mut out = CertificateResult::default();
    let mut seen = SeenFiles::default();
    if let Some(cert_file) = file {
        if let Ok(metadata) = fs::metadata(cert_file) {
            seen.first_visit(&metadata);
        }
        // An explicit file is expected to exist and be readable: surface errors.
        read_bundle(cert_file, &mut out);
    }

    for dir in dirs {
        load_pem_certs_from_dir(dir.as_ref(), &mut out, &mut seen);
    }
    // Unreadable entries must not pass for an empty store that permits a fallback.
    if out.certs.is_empty()
        && let Some(index) = out.unreadable
    {
        out.source_error.get_or_insert(index);
    }
    out
}

/// Files already read, by identity: certificate directories hold several links per
/// certificate (hash names, readable names) and often one to the bundle file too.
#[derive(Default)]
struct SeenFiles {
    /// `(device, inode)` of each file read.
    #[cfg(unix)]
    ids: std::collections::BTreeSet<(u64, u64)>,
}

impl SeenFiles {
    /// Records the file and returns whether it was not seen before.
    ///
    /// Always `true` where std exposes no stable file identity.
    #[cfg_attr(
        not(unix),
        expect(
            clippy::unused_self,
            clippy::needless_pass_by_ref_mut,
            reason = "only Unix exposes a stable file identity to record"
        )
    )]
    fn first_visit(&mut self, metadata: &fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            self.ids.insert((metadata.dev(), metadata.ino()))
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            true
        }
    }
}

/// Load certificates from a certificate directory (what OpenSSL calls CAdir).
///
/// Failing to list the directory is a source error; a bad entry is recorded
/// as a plain error and does not stop the other entries from loading.
fn load_pem_certs_from_dir(dir: &Path, out: &mut CertificateResult, seen: &mut SeenFiles) {
    let dir_reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(err) => {
            out.source_io_error(err, dir, "opening directory");
            return;
        }
    };

    for entry in dir_reader {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                out.source_io_error(err, dir, "reading directory entries");
                continue;
            }
        };

        let path = entry.path();

        // `openssl rehash` used to create this directory uses symlinks, so
        // resolve them.
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Dangling symlink
                continue;
            }
            Err(e) => {
                out.io_error(e, &path, "failed to open file");
                continue;
            }
        };

        if metadata.is_file() && seen.first_visit(&metadata) {
            load_dir_entry(&path, out);
        }
    }
}

/// A CAdir holds certificates next to CRLs, keys and other files: only
/// CERTIFICATE sections are read, and an unreadable entry is a soft error.
fn load_dir_entry(path: &Path, out: &mut CertificateResult) {
    match CertificateDer::pem_file_iter(path) {
        Err(pem::Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
            out.io_error(error, path, "skipping unreadable certificate file");
        }
        entries => push_pem_certs(entries, path, out),
    }
}

fn load_pem_certs(path: &Path, out: &mut CertificateResult) {
    push_pem_certs(CertificateDer::pem_file_iter(path), path, out);
}

fn push_pem_certs(
    entries: Result<impl Iterator<Item = Result<CertificateDer<'static>, pem::Error>>, pem::Error>,
    path: &Path,
    out: &mut CertificateResult,
) {
    let entries = match entries {
        Ok(entries) => entries,
        Err(err) => {
            out.pem_error(err, path);
            return;
        }
    };
    for result in entries {
        match result {
            Ok(cert) => out.certs.push(cert),
            Err(err) => out.pem_error(err, path),
        }
    }
}

/// An error encountered while loading certificates from the platform store.
#[derive(Debug)]
pub struct Error {
    /// Human-readable context describing what was being attempted.
    pub context: &'static str,
    /// The underlying error kind.
    pub kind: ErrorKind,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match &self.kind {
            ErrorKind::Io { inner, .. } => inner,
            ErrorKind::Os(err) => &**err,
            ErrorKind::Pem(err) => err,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.context)?;
        f.write_str(": ")?;
        match &self.kind {
            ErrorKind::Io { inner, path } => write!(f, "{inner} at '{}'", path.display()),
            ErrorKind::Os(err) => err.fmt(f),
            ErrorKind::Pem(err) => err.fmt(f),
        }
    }
}

/// The kinds of errors that can occur while loading native certificates.
#[non_exhaustive]
#[derive(Debug)]
pub enum ErrorKind {
    /// An I/O error while reading a certificate file or directory.
    Io {
        /// The underlying I/O error.
        inner: io::Error,
        /// The path being read.
        path: PathBuf,
    },
    /// A platform (OS keychain / cert store) error.
    Os(Box<dyn StdError + Send + Sync + 'static>),
    /// A PEM parsing error.
    Pem(pem::Error),
}

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";
const ENV_CERT_DIR: &str = "SSL_CERT_DIR";
const ENV_EXTRA_CERT_FILE: &str = "SSL_CERT_EXTRA_FILE";
const ENV_EXTRA_CERT_DIR: &str = "SSL_CERT_EXTRA_DIR";

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::{
        sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    #[cfg(unix)]
    use fs::{File, Permissions};

    use super::*;

    #[test]
    fn cold_async_anchor_reads_share_one_load_and_warm_reads_need_no_runtime() {
        static LOADS: AtomicUsize = AtomicUsize::new(0);
        static LOADER_THREAD: OnceLock<thread::ThreadId> = OnceLock::new();
        static ANCHORS: LazyLock<SharedTrustAnchors> = LazyLock::new(|| {
            LOADS.fetch_add(1, Ordering::Relaxed);
            LOADER_THREAD.set(thread::current().id()).unwrap();
            Arc::from([CertificateDer::from(vec![1])])
        });
        assert!(LazyLock::get(&ANCHORS).is_none());
        let (first, concurrent) = tokio_test::block_on(rama_core::futures::future::join(
            acquire_trust_anchors(&ANCHORS),
            acquire_trust_anchors(&ANCHORS),
        ));
        let first = first.unwrap();
        assert_ne!(*LOADER_THREAD.get().unwrap(), thread::current().id());
        assert!(Arc::ptr_eq(&first, &concurrent.unwrap()));
        assert!(Arc::ptr_eq(&first, LazyLock::force(&ANCHORS)));

        let mut warm = tokio_test::task::spawn(acquire_trust_anchors(&ANCHORS));
        let warm = tokio_test::assert_ready!(warm.poll()).unwrap();
        assert!(Arc::ptr_eq(&first, &warm));
        assert_eq!(LOADS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn bundled_root_certs_non_empty() {
        assert!(
            !bundled_root_certs().is_empty(),
            "bundled webpki root certificates should not be empty"
        );
    }

    #[test]
    fn from_env_missing_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("no/such/file"), &mut result);
        match &result.errors.first().unwrap().kind {
            ErrorKind::Io { inner, .. } => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            other => panic!("unexpected error {other:?}"),
        }
    }

    /// Each read of this file records one PEM error, which makes reads countable.
    #[cfg(unix)]
    const MALFORMED_PEM: &str = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n";

    /// A fresh directory under the system temp dir, removed on drop.
    pub(super) struct TestDir(pub(super) PathBuf);

    impl TestDir {
        pub(super) fn new(name: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "rama-crypto-native-certs-{}-{name}",
                std::process::id()
            ));
            _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[cfg(unix)]
    fn dir_symlinks_to_same_file_read_once() {
        let dir = TestDir::new("symlinks");
        fs::write(dir.0.join("Example_Root.pem"), MALFORMED_PEM).unwrap();
        symlink("Example_Root.pem", dir.0.join("01234567.0")).unwrap();
        symlink(dir.0.join("Example_Root.pem"), dir.0.join("89abcdef.0")).unwrap();

        let result = load_certs_from_paths_internal(None, &[&dir.0]);
        assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    }

    #[test]
    #[cfg(unix)]
    fn dir_entry_for_cert_file_skipped() {
        let file_dir = TestDir::new("bundle");
        let cert_dir = TestDir::new("bundle-links");
        let file = file_dir.0.join("ca-bundle.crt");
        fs::write(&file, MALFORMED_PEM).unwrap();
        symlink(&file, cert_dir.0.join("ca-bundle.crt")).unwrap();

        let result = load_certs_from_paths_internal(Some(&file), &[&cert_dir.0]);
        assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    }

    #[test]
    #[cfg(unix)]
    fn dir_copies_with_same_content_all_read() {
        let dir = TestDir::new("copies");
        fs::write(dir.0.join("a.pem"), MALFORMED_PEM).unwrap();
        fs::write(dir.0.join("b.pem"), MALFORMED_PEM).unwrap();

        let result = load_certs_from_paths_internal(None, &[&dir.0]);
        assert_eq!(result.errors.len(), 2, "{:?}", result.errors);
    }

    #[test]
    fn from_env_missing_dir() {
        let mut result = CertificateResult::default();
        load_pem_certs_from_dir(
            Path::new("no/such/directory"),
            &mut result,
            &mut SeenFiles::default(),
        );
        match &result.errors.first().unwrap().kind {
            ErrorKind::Io { inner, .. } => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn cert_paths_detects_env_overrides() {
        assert!(
            !CertPaths {
                file: None,
                dirs: Vec::new()
            }
            .has_overrides()
        );
        assert!(
            CertPaths {
                file: Some(PathBuf::from("ca.pem")),
                dirs: Vec::new()
            }
            .has_overrides()
        );
        assert!(
            CertPaths {
                file: None,
                dirs: vec![PathBuf::from("certs")]
            }
            .has_overrides()
        );
    }

    #[test]
    fn filesystem_read_failures_do_not_enable_bundled_roots() {
        let path = Path::new("trust-store");
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            let mut result = CertificateResult::default();
            result.io_error(io::Error::from(kind), path, "read trust source");
            assert!(native_base(&result, false).is_empty());
            let mut result = CertificateResult::default();
            result.pem_error(pem::Error::Io(io::Error::from(kind)), path);
            assert!(native_base(&result, false).is_empty());
        }
        let mut missing = CertificateResult::default();
        missing.io_error(
            io::Error::from(io::ErrorKind::NotFound),
            path,
            "read trust source",
        );
        assert_eq!(native_base(&missing, false), bundled_root_certs());
    }

    #[test]
    #[cfg(unix)]
    fn inaccessible_ancestors_survive_native_path_discovery() {
        let dir = TestDir::new("inaccessible-native-ancestor");
        let ancestor = dir.0.join("private");
        fs::create_dir(&ancestor).unwrap();
        let bundle = ancestor.join("bundle.pem");
        let certs = ancestor.join("certs");
        fs::write(&bundle, b"").unwrap();
        fs::create_dir(&certs).unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(0o0)).unwrap();
        let inaccessible = bundle.try_exists().is_err();
        let paths = discover_cert_paths([bundle.as_path()], [certs.as_path()]);
        let result = paths.load();
        fs::set_permissions(&ancestor, Permissions::from_mode(0o700)).unwrap();
        if !inaccessible {
            return;
        }
        assert_eq!(paths.file.as_deref(), Some(bundle.as_path()));
        assert_eq!(paths.dirs, [certs]);
        assert!(result.unreadable.is_some());
        assert!(native_base(&result, false).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_directory_and_symlink_target_do_not_enable_bundled_roots() {
        let entries = TestDir::new("inaccessible-target");
        let locked = TestDir::new("inaccessible-directory");
        let target = locked.0.join("root.pem");
        fs::write(&target, b"certificate").unwrap();
        symlink(&target, entries.0.join("root.pem")).unwrap();
        fs::set_permissions(&locked.0, Permissions::from_mode(0o000)).unwrap();
        let inaccessible = fs::read_dir(&locked.0).is_err();
        let directory = load_certs_from_paths_internal(None, &[&locked.0]);
        let symlink = load_certs_from_paths_internal(None, &[&entries.0]);
        fs::set_permissions(&locked.0, Permissions::from_mode(0o700)).unwrap();
        if !inaccessible {
            eprintln!("directory permission checks unavailable for this user");
            return;
        }
        for result in [directory, symlink] {
            assert!(result.certs.is_empty());
            assert!(result.source_error.is_some());
            assert!(native_base(&result, false).is_empty());
        }
    }

    #[test]
    #[cfg(unix)]
    fn static_roots_fall_back_only_for_an_empty_readable_store() {
        let dir = TestDir::new("static-fallback");
        let empty = load_certs_from_paths_internal(None, &[&dir.0]);
        assert_eq!(native_base(&empty, false), bundled_root_certs());
        assert!(native_base(&empty, true).is_empty());

        let locked = dir.0.join("private-root.pem");
        fs::write(
            &locked,
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();
        let unreadable = File::open(&locked).is_err();
        let result = load_certs_from_paths_internal(None, &[&dir.0]);
        fs::set_permissions(&locked, Permissions::from_mode(0o600)).unwrap();
        if unreadable {
            assert!(native_base(&result, false).is_empty());
            assert!(result.source_error.is_some());
        }
    }

    #[test]
    #[cfg(unix)]
    fn from_env_with_non_regular_and_empty_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("/dev/null"), &mut result);
        assert_eq!(result.certs.len(), 0);
        assert!(result.errors.is_empty());
    }
}
