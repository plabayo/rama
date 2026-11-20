#[cfg(any(target_os = "macos", windows))]
use super::notifications::StoreNotifications;
use super::{CertPaths, ENV_EXTRA_CERT_DIR, ENV_EXTRA_CERT_FILE};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

/// Tracks changes in the native store and configured files between probes.
/// Each instance maintains its own cursor over store notifications and file metadata.
pub struct NativeCertsChanges {
    interval: Duration,
    include_native: bool,
    probed_at: Option<Instant>,
    files: Vec<(PathBuf, FileState)>,
    #[cfg(any(target_os = "macos", windows))]
    notifications: Option<StoreNotifications>,
}

impl NativeCertsChanges {
    /// Set the minimum interval between filesystem checks.
    pub const fn new(interval: Duration) -> Self {
        Self::with_scope(interval, true)
    }

    /// Track only the files and directories configured by `SSL_CERT_EXTRA_FILE`
    /// and `SSL_CERT_EXTRA_DIR`, checked at most once per interval.
    pub const fn extra_only(interval: Duration) -> Self {
        Self::with_scope(interval, false)
    }

    const fn with_scope(interval: Duration, include_native: bool) -> Self {
        Self {
            interval,
            include_native,
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
        let extra = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
        self.probe_sources(&extra, CertPaths::from_env, Instant::now())
    }

    fn probe_sources(
        &mut self,
        extra: &CertPaths,
        native_paths: impl FnOnce() -> CertPaths,
        now: Instant,
    ) -> bool {
        if !self.include_native {
            return self.probe_files(None, extra, now);
        }
        let base = native_paths();
        #[cfg(any(target_os = "macos", windows))]
        let notified = self.check_store(&base);
        #[cfg(not(any(target_os = "macos", windows)))]
        let notified = false;

        #[cfg(all(unix, not(target_os = "macos")))]
        let base = if base.has_overrides() {
            base
        } else {
            super::unix::system_paths()
        };
        self.probe_files(Some(&base), extra, now) || notified
    }

    #[cfg(any(target_os = "macos", windows))]
    fn check_store(&mut self, base: &CertPaths) -> bool {
        if base.has_overrides() {
            self.notifications = None;
            return false;
        }

        if let Some(changed) = self
            .notifications
            .as_mut()
            .and_then(StoreNotifications::poll)
        {
            return changed;
        }

        // Retry incomplete watches once per interval. Refresh across any gap
        // even when registration succeeds, since intervening events were lost.
        let mut watch = StoreNotifications::new();
        let changed = watch.poll().unwrap_or(true) || self.probed_at.is_some();
        self.notifications = Some(watch);
        changed
    }

    fn probe_files(&mut self, base: Option<&CertPaths>, extra: &CertPaths, now: Instant) -> bool {
        let mut files = Vec::new();
        if let Some(base) = base {
            record_paths(base, &mut files);
        }
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
mod tests;
