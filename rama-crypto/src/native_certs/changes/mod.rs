#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use rama_core::telemetry::tracing::warn;

#[cfg(any(target_os = "macos", windows))]
use super::notifications::StoreNotifications;
use super::{CertPaths, ENV_EXTRA_CERT_DIR, ENV_EXTRA_CERT_FILE};

mod wake;
pub use wake::NativeCertsWake;

/// Longest wait while store notifications can only be polled.
#[cfg(target_os = "macos")]
const DEGRADED_POLL: Duration = Duration::from_millis(250);

/// Slack for an operating system wait that ends a clock tick before its timeout.
const WAIT_TICK: Duration = Duration::from_millis(16);

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

    /// Initialize observation for the selected trust scope.
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

    /// Check whether the next trust probe is due.
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
        self.probe()
    }

    /// Probe the backing sources now, whether or not a probe is due.
    fn probe(&mut self) -> bool {
        let extra = CertPaths::from_env_vars(ENV_EXTRA_CERT_FILE, ENV_EXTRA_CERT_DIR);
        self.probe_sources(&extra, CertPaths::from_env, Instant::now())
    }

    /// Block until the next probe is due, a native store notification arrives,
    /// or `wake` is woken, then probe like [`Self::changed`].
    pub fn wait_changed(&mut self, wake: &NativeCertsWake) -> bool {
        #[cfg(target_os = "macos")]
        let wait =
            |changes: &mut Self, timeout| wake.os.wait(changes.notifications.as_mut(), timeout);
        #[cfg(windows)]
        let wait =
            |changes: &mut Self, timeout| wake.os.wait(changes.notifications.as_ref(), timeout);
        #[cfg(not(any(target_os = "macos", windows)))]
        let wait = |_: &mut Self, timeout| wake.os.wait(timeout);
        self.wait_changed_with(wake, wait)
    }

    /// Wait for trust changes using the supplied wait mechanism.
    fn wait_changed_with(
        &mut self,
        wake: &NativeCertsWake,
        wait: impl FnMut(&mut Self, Duration) -> io::Result<bool>,
    ) -> bool {
        let timeout = self.probed_at.map_or(Duration::ZERO, |last| {
            self.interval.saturating_sub(last.elapsed())
        });
        #[cfg(target_os = "macos")]
        let timeout = match self.notifications.as_mut() {
            Some(notifications) => {
                notifications.retry_wait();
                // Without a wait descriptor only polling observes notifications.
                if notifications.wait_degraded() {
                    timeout.min(DEGRADED_POLL)
                } else {
                    timeout
                }
            }
            None => timeout,
        };
        self.wait_then_probe(wake, timeout, wait)
    }

    /// Wait for a notification or probe deadline, then check the sources.
    fn wait_then_probe(
        &mut self,
        wake: &NativeCertsWake,
        timeout: Duration,
        mut wait: impl FnMut(&mut Self, Duration) -> io::Result<bool>,
    ) -> bool {
        let started = Instant::now();
        let mut timed_out = false;
        loop {
            match wait(self, timeout.saturating_sub(started.elapsed())) {
                Ok(true) if !wake.consumed() => {
                    #[cfg(any(target_os = "macos", windows))]
                    if self
                        .notifications
                        .as_mut()
                        .and_then(StoreNotifications::poll)
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
                Ok(woken) => {
                    timed_out = !woken;
                    break;
                }
                Err(error) => {
                    // A wait that cannot block must neither spin nor delay a stop request.
                    warn!(%error, "could not wait for native trust store changes; backing off until the next probe");
                    wake.backoff(timeout.saturating_sub(started.elapsed()));
                    break;
                }
            }
        }
        // A wait that ends a clock tick early would leave `changed` skipping the probe.
        let until_due = self.probed_at.map_or(Duration::ZERO, |last| {
            self.interval.saturating_sub(last.elapsed())
        });
        if timed_out && until_due <= WAIT_TICK {
            return self.probe();
        }
        self.changed()
    }

    /// Probe the configured trust sources for changes.
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
    /// Check the native trust store for changes.
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

    /// Check the configured root files for changes.
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
