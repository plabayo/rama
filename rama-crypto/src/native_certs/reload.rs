use super::{
    CertPaths, CertificateDer, CertificateResult, ENV_EXTRA_CERT_DIR, ENV_EXTRA_CERT_FILE,
};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

#[cfg(any(target_os = "macos", windows))]
use super::notifications::StoreNotifications;

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
    let mut result = CertificateResult::default();
    let mut seen = super::SeenFiles::default();
    if let Some(file) = &paths.file {
        super::load_pem_certs(file, &mut result, false);
        if let Ok(metadata) = fs::metadata(file) {
            seen.first_visit(&metadata);
            if result.certs.is_empty()
                && result.errors.is_empty()
                && metadata.len() != 0
                && fs::read(file)?
                    .iter()
                    .any(|byte| !byte.is_ascii_whitespace())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "no PEM certificates in nonempty native trust file '{}'",
                        file.display()
                    ),
                )
                .into());
            }
        }
    }
    for dir in &paths.dirs {
        super::load_pem_certs_from_dir(dir, &mut result, &mut seen);
    }
    checked_load(result)
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

/// Tracks changes in the native store and configured files between probes.
/// Each instance maintains its own cursor over store notifications and file metadata.
pub struct NativeCertsChanges {
    interval: Duration,
    probed_at: Option<Instant>,
    files: Vec<(PathBuf, FileState)>,
    #[cfg(any(target_os = "macos", windows))]
    notifications: Option<StoreNotifications>,
}

impl NativeCertsChanges {
    /// Set the minimum interval between filesystem checks.
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            probed_at: None,
            files: Vec::new(),
            #[cfg(any(target_os = "macos", windows))]
            notifications: None,
        }
    }

    fn probe_due(&self) -> bool {
        self.probed_at
            .is_none_or(|last| last.elapsed() >= self.interval)
    }

    /// Probe the backing sources and consume any detected change. May block.
    pub fn changed(&mut self) -> bool {
        if !self.probe_due() {
            #[cfg(any(target_os = "macos", windows))]
            return self
                .notifications
                .as_mut()
                .and_then(StoreNotifications::poll)
                .unwrap_or(false);
            #[cfg(not(any(target_os = "macos", windows)))]
            return false;
        }
        let base = CertPaths::from_env();
        #[cfg(any(target_os = "macos", windows))]
        let notified = if base.has_overrides() {
            self.notifications = None;
            false
        } else {
            self.notifications
                .get_or_insert_with(StoreNotifications::new)
                .poll()
                .unwrap_or(true)
        };
        #[cfg(not(any(target_os = "macos", windows)))]
        let notified = false;

        #[cfg(all(unix, not(target_os = "macos")))]
        let base = if base.has_overrides() {
            base
        } else {
            super::unix::system_paths()
        };
        let extra = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
        self.probe_files(&base, &extra, Instant::now()) || notified
    }

    fn probe_files(&mut self, base: &CertPaths, extra: &CertPaths, now: Instant) -> bool {
        let mut files = Vec::new();
        record_paths(base, &mut files);
        record_paths(extra, &mut files);

        let changed = self.probed_at.is_some() && files != self.files;
        self.probed_at = Some(now);
        self.files = files;
        changed
    }
}

fn record_paths(paths: &CertPaths, files: &mut Vec<(PathBuf, FileState)>) {
    if let Some(file) = &paths.file {
        files.push((file.clone(), file_state(file)));
    }
    for dir in &paths.dirs {
        files.push((dir.clone(), file_state(dir)));
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let first = files.len();
        files.extend(entries.map(|entry| match entry {
            Ok(entry) => {
                let path = entry.path();
                let state = file_state(&path);
                (path, state)
            }
            Err(error) => (dir.clone(), FileState::Unavailable(error.kind())),
        }));
        files[first..].sort_unstable();
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum FileState {
    Present {
        modified: Option<SystemTime>,
        len: u64,
        #[cfg(unix)]
        dev: u64,
        #[cfg(unix)]
        inode: u64,
        #[cfg(unix)]
        changed: (i64, i64),
    },
    Unavailable(io::ErrorKind),
}

fn file_state(path: &Path) -> FileState {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    match fs::metadata(path) {
        Ok(metadata) => FileState::Present {
            modified: metadata.modified().ok(),
            len: metadata.len(),
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        },
        Err(error) => FileState::Unavailable(error.kind()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::native_certs::tests::TestDir;

    #[test]
    fn explicit_empty_file_differs_from_invalid_pem() {
        let dir = TestDir::new("reload-empty");
        let file = dir.0.join("bundle.pem");
        let paths = CertPaths {
            file: Some(file.clone()),
            dirs: Vec::new(),
        };
        drop(checked_load_paths(&paths).unwrap_err());
        fs::write(&file, "broken trust bundle").unwrap();
        drop(checked_load_paths(&paths).unwrap_err());
        fs::write(&file, " \n").unwrap();
        assert!(checked_load_paths(&paths).unwrap().is_empty());
    }

    #[test]
    fn a_successful_empty_system_store_clears_live_roots() {
        use crate::pem::PemEncode as _;

        let dir = TestDir::new("reload-empty-system");
        let bundle = dir.0.join("system.pem");
        let extra_file = dir.0.join("extra.pem");
        let system = CertPaths {
            file: Some(bundle.clone()),
            dirs: Vec::new(),
        };
        let extra = CertPaths {
            file: Some(extra_file.clone()),
            dirs: Vec::new(),
        };
        let unset = CertPaths {
            file: None,
            dirs: Vec::new(),
        };
        let refresh = |extra: &CertPaths, fallback| {
            load_from_sources(&unset, extra, fallback, || checked_load_paths(&system))
        };

        fs::write(&bundle, b"").unwrap();
        let (initial, bundled) = refresh(&unset, true).unwrap();
        assert!(bundled);
        assert!(initial.contains(&super::super::bundled_root_certs()[0]));

        let roots = super::super::bundled_root_certs();
        fs::write(&bundle, roots[0].to_pem()).unwrap();
        fs::write(&extra_file, roots[1].to_pem()).unwrap();
        let (live, bundled) = refresh(&extra, bundled).unwrap();
        assert!(!bundled);
        assert_eq!(live.len(), 2);
        assert!(live.contains(&roots[0]));
        assert!(live.contains(&roots[1]));

        fs::write(&bundle, b"").unwrap();
        let (extra_only, bundled) = refresh(&extra, bundled).unwrap();
        assert!(!bundled);
        assert_eq!(extra_only, &[roots[1].clone()]);
        let (empty, bundled) = refresh(&unset, bundled).unwrap();
        assert!(!bundled);
        assert!(empty.is_empty());

        fs::remove_file(&bundle).unwrap();
        let error = refresh(&extra, bundled)
            .unwrap_err()
            .downcast::<crate::native_certs::Error>()
            .unwrap();
        assert!(matches!(
            error.kind,
            crate::native_certs::ErrorKind::Io { inner, .. }
                if inner.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn observes_atomically_replaced_bundle_and_in_place_directory_changes() {
        let dir = TestDir::new("reload-metadata");
        let bundle = dir.0.join("bundle.pem");
        let replacement = dir.0.join("replacement.pem");
        let extra_dir = dir.0.join("extra");
        let extra_anchor = extra_dir.join("anchor.pem");
        fs::create_dir(&extra_dir).unwrap();
        fs::write(&bundle, b"first").unwrap();
        fs::write(&extra_anchor, b"first").unwrap();
        let base = CertPaths {
            file: Some(bundle.clone()),
            dirs: Vec::new(),
        };
        let extra = CertPaths {
            file: None,
            dirs: vec![extra_dir],
        };
        let mut changes = NativeCertsChanges::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(changes.probe_due());
        assert!(!changes.probe_files(&base, &extra, now));
        fs::write(&replacement, b"other").unwrap();
        fs::rename(&replacement, &bundle).unwrap();
        assert!(!changes.probe_due());
        assert!(changes.probe_files(&base, &extra, now));
        assert!(!changes.probe_files(&base, &extra, now));
        fs::write(&extra_anchor, b"different").unwrap();
        assert!(changes.probe_files(&base, &extra, now));
    }
}
