//! MaxMind DB reader over positional reads, with hot reload.

use core::fmt;
use core::net::IpAddr;
use core::num::NonZeroUsize;
use core::time::Duration;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rama_core::io::{BlockCache, BlockCacheConfig, FileIdentity, ReadAt, ReadAtFiles};
use rama_core::telemetry::tracing;
use rama_utils::macros::generate_set_and_with;

use super::decoder::Decoder;
use super::tree::Tree;
use super::{Metadata, metadata_tail_start, parse_metadata};
use crate::address::ip::geo::GeoIpError;
use crate::address::ip::geo::location::{GeoLocation, decode_owned};

mod window;
use window::{Window, source_error};

#[cfg(test)]
mod tests;

/// Default interval between two checks of the database path.
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_mins(1);

/// First wait before retrying a file that failed to load.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Source type held by every loaded version.
type DynReadAt = Box<dyn ReadAt + Send + Sync>;

/// Configuration of an [`MmdbFileReader`].
#[derive(Debug, Clone)]
pub struct MmdbFileConfig {
    cache: BlockCacheConfig,
    check_interval: Duration,
    jump_table: bool,
    handles: Option<NonZeroUsize>,
}

impl Default for MmdbFileConfig {
    fn default() -> Self {
        Self {
            cache: BlockCacheConfig::default(),
            check_interval: DEFAULT_CHECK_INTERVAL,
            jump_table: true,
            handles: None,
        }
    }
}

impl MmdbFileConfig {
    generate_set_and_with! {
        /// Block cache of each loaded version (default: no cache).
        pub fn cache(mut self, cache: BlockCacheConfig) -> Self {
            self.cache = cache;
            self
        }
    }

    generate_set_and_with! {
        /// How often a lookup checks whether the path names a different file
        /// (default 60 s). Zero checks on every lookup.
        pub fn check_interval(mut self, check_interval: Duration) -> Self {
            self.check_interval = check_interval;
            self
        }
    }

    generate_set_and_with! {
        /// Whether to build the 16-bit jump table per loaded version (default
        /// on); see [`MmdbReader::without_jump_table`] for its cost.
        ///
        /// [`MmdbReader::without_jump_table`]: super::MmdbReader::without_jump_table
        pub fn jump_table(mut self, jump_table: bool) -> Self {
            self.jump_table = jump_table;
            self
        }
    }

    generate_set_and_with! {
        /// File handles per loaded version; `None` uses the default of
        /// [`ReadAtFiles::open`].
        pub fn handles(mut self, handles: Option<NonZeroUsize>) -> Self {
            self.handles = handles;
            self
        }
    }
}

/// A MaxMind DB reader that reads the file through positional reads.
///
/// Nothing is mapped and nothing beyond the metadata, the jump table and the
/// optional [`BlockCache`] is held in memory, so modifying the file is never
/// undefined behaviour, unlike for a memory map. Lookups return owned
/// [`GeoLocation`]s.
///
/// # Reload
///
/// A reader opened on a path follows the file that path names:
///
/// - At most once per [check interval](MmdbFileConfig::with_check_interval)
///   a lookup stats the path (following symlinks). If the file identity
///   (see [`FileIdentity`]) differs from the loaded one, the file is
///   reopened.
/// - A read that comes up short within the size seen at open, or a stale
///   handle, also triggers a reopen.
///
/// One lookup reopens, others keep using the loaded version and never wait.
/// A new file is validated before it replaces the loaded version; if it fails
/// the loaded version stays, a warning is logged once for that file, and it
/// is retried only when the path names a different file or after a back-off
/// (1 s, doubling, capped at the check interval). Each version owns its own
/// handles, jump table and cache, and stays alive while any lookup that
/// loaded it is running. Usually two versions overlap briefly during a swap;
/// lookups that run across several swaps keep each version they loaded, so
/// more than two can be alive at once.
///
/// Update the file by renaming a complete new file over it, as `geoipupdate`
/// and Kubernetes volume updates do. Rewriting the file in place is not
/// supported: until the change is noticed lookups may return `None` or wrong
/// values, though never undefined behaviour. Changes are noticed only after
/// the check interval plus any attribute caching of the filesystem (up to
/// 60 s on NFS). A process that does no lookups does not check, so it
/// keeps the replaced file (and its disk blocks) open until it does.
///
/// On Windows the rename must be one that may replace an open file:
/// `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, which many runtimes use
/// for their rename or move, fails with `ERROR_ACCESS_DENIED` while this
/// reader holds the file open. [`std::fs::rename`] falls back to a POSIX
/// semantics rename (NTFS, Windows 10 1809 and later), which works. With
/// other tools, first rename the old file away, then the new one into place.
/// See [`FileIdentity`] for which replacements are visible.
///
/// # Blocking
///
/// Lookups read the file with blocking positional reads; see the blocking
/// section of [`ReadAt`] for why that is accepted on async workers.
#[derive(Debug, Clone)]
pub struct MmdbFileReader {
    shared: Arc<Shared>,
    lang: Box<str>,
}

#[derive(Debug)]
struct Shared {
    /// Path to follow, `None` for a fixed source.
    path: Option<Box<Path>>,
    config: MmdbFileConfig,
    current: ArcSwap<Version>,
    reload: Mutex<ReloadState>,
    epoch: Instant,
    /// Nanoseconds since `epoch` at which the next path check is due.
    next_check_nanos: AtomicU64,
    stats: ReloadStats,
}

/// One loaded file: everything that must not outlive or mix with another.
struct Version {
    cache: BlockCache<DynReadAt>,
    size: usize,
    metadata: Metadata,
    tree: Tree,
    identity: Option<FileIdentity>,
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version")
            .field("size", &self.size)
            .field("metadata", &self.metadata)
            .field("tree", &self.tree)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Why a reload was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// The periodic check saw a different file at the path.
    PathChanged,
    /// A read of the loaded file failed as if the file changed.
    SourceChanged,
}

#[derive(Debug, Default)]
struct ReloadState {
    failed: Option<FailedReload>,
}

/// The last file that failed to load and when to try it again.
#[derive(Debug)]
struct FailedReload {
    identity: Option<FileIdentity>,
    backoff: Duration,
    retry_at_nanos: u64,
}

/// Reload counters, read by tests.
#[derive(Debug, Default)]
struct ReloadStats {
    checks: AtomicU64,
    attempts: AtomicU64,
    swaps: AtomicU64,
    warnings: AtomicU64,
}

impl MmdbFileReader {
    /// Open the database at `path` with the default [`MmdbFileConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Io`] if the file cannot be opened or is not a
    /// regular file, or another [`GeoIpError`] if it is not a valid database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoIpError> {
        Self::open_with_config(path, MmdbFileConfig::default())
    }

    /// Open the database at `path` with `config`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`].
    pub fn open_with_config(
        path: impl AsRef<Path>,
        config: MmdbFileConfig,
    ) -> Result<Self, GeoIpError> {
        let path = path.as_ref();
        let version = Version::open(path, &config)?;
        Ok(Self::new(Some(path.into()), config, version))
    }

    /// Read the database from any [`ReadAt`] source, such as an in-memory
    /// buffer. The source is never reloaded.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError`] if the source cannot be read or is not a valid
    /// database.
    pub fn from_read_at(
        src: impl ReadAt + Send + Sync + 'static,
        config: MmdbFileConfig,
    ) -> Result<Self, GeoIpError> {
        let version = Version::load(Box::new(src), None, &config)?;
        Ok(Self::new(None, config, version))
    }

    fn new(path: Option<Box<Path>>, config: MmdbFileConfig, version: Version) -> Self {
        let epoch = Instant::now();
        let next_check_nanos = AtomicU64::new(nanos(config.check_interval));
        Self {
            shared: Arc::new(Shared {
                path,
                config,
                current: ArcSwap::from_pointee(version),
                reload: Mutex::default(),
                epoch,
                next_check_nanos,
                stats: ReloadStats::default(),
            }),
            lang: Box::from("en"),
        }
    }

    /// Set the preferred language code used to resolve localised names
    /// (default `"en"`), falling back to English.
    #[must_use]
    pub fn with_language(mut self, lang: impl Into<Box<str>>) -> Self {
        self.lang = lang.into();
        self
    }

    /// The path this reader follows, if it was opened from one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.shared.path.as_deref()
    }

    /// The [`Metadata`] of the currently loaded version.
    #[must_use]
    pub fn metadata(&self) -> Metadata {
        self.shared.current.load().metadata.clone()
    }

    /// Look up `ip`, returning its record if present.
    ///
    /// IPv4-mapped IPv6 inputs are canonicalised to IPv4 first. This is
    /// best-effort: corruption, I/O errors and a file that changed under the
    /// reader all yield `None`. Use [`Self::try_lookup`] to observe them.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        self.try_lookup(ip).ok().flatten()
    }

    /// Like [`Self::lookup`], but reports errors.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Corrupt`] if the database is structurally
    /// invalid for `ip`, [`GeoIpError::SourceChanged`] if the file changed
    /// and no newer version could be loaded by this call, or
    /// [`GeoIpError::Io`] for another read error.
    pub fn try_lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, GeoIpError> {
        self.shared.check_path();
        let version = self.shared.current.load();
        match version.lookup(ip, &self.lang) {
            Err(GeoIpError::SourceChanged)
                if self.shared.reload(&version, Trigger::SourceChanged) =>
            {
                self.shared.current.load().lookup(ip, &self.lang)
            }
            result => result,
        }
    }
}

impl Shared {
    fn now_nanos(&self) -> u64 {
        nanos(self.epoch.elapsed())
    }

    /// Reload when the check interval passed and the path names another file.
    fn check_path(&self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let now = self.now_nanos();
        let due = self.next_check_nanos.load(Ordering::Relaxed);
        if now < due {
            return;
        }
        let next = now.saturating_add(nanos(self.config.check_interval));
        // one lookup per interval wins the check; the others skip it
        if self
            .next_check_nanos
            .compare_exchange(due, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.stats.checks.fetch_add(1, Ordering::Relaxed);
        // load before the stat, so a stat older than the loaded version
        // cannot look like a change
        let current = self.current.load_full();
        if path_identity(path) != current.identity {
            self.reload(&current, Trigger::PathChanged);
        }
    }

    /// Try to replace `seen` with a fresh load of the path; single flight.
    ///
    /// Returns whether a version newer than `seen` is now current.
    fn reload(&self, seen: &Arc<Version>, trigger: Trigger) -> bool {
        let Some(path) = self.path.as_deref() else {
            return false;
        };
        let Some(mut state) = self.reload.try_lock() else {
            return false;
        };
        if !Arc::ptr_eq(&self.current.load(), seen) {
            return true;
        }
        let now = self.now_nanos();
        let observed = path_identity(path);
        if trigger == Trigger::PathChanged && observed == seen.identity {
            return false;
        }
        if let Some(failed) = &state.failed
            && failed.identity == observed
            && now < failed.retry_at_nanos
        {
            return false;
        }

        self.stats.attempts.fetch_add(1, Ordering::Relaxed);
        match Version::open(path, &self.config) {
            Ok(next) => {
                tracing::info!(
                    path = %path.display(),
                    old_build_epoch = seen.metadata.build_epoch,
                    new_build_epoch = next.metadata.build_epoch,
                    old_node_count = seen.metadata.node_count,
                    new_node_count = next.metadata.node_count,
                    "reloaded MaxMind DB"
                );
                self.current.store(Arc::new(next));
                state.failed = None;
                self.stats.swaps.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(error) => {
                let cap = self.config.check_interval.max(INITIAL_BACKOFF);
                match &mut state.failed {
                    Some(failed) if failed.identity == observed => {
                        failed.backoff = failed.backoff.saturating_mul(2).min(cap);
                        failed.retry_at_nanos = now.saturating_add(nanos(failed.backoff));
                        tracing::debug!(
                            path = %path.display(),
                            %error,
                            retry_in = ?failed.backoff,
                            "MaxMind DB still fails to load; keeping the loaded version"
                        );
                    }
                    failed => {
                        tracing::warn!(
                            path = %path.display(),
                            old_identity = ?seen.identity,
                            new_identity = ?observed,
                            %error,
                            "failed to reload MaxMind DB; keeping the loaded version"
                        );
                        self.stats.warnings.fetch_add(1, Ordering::Relaxed);
                        let backoff = INITIAL_BACKOFF.min(cap);
                        *failed = Some(FailedReload {
                            identity: observed,
                            backoff,
                            retry_at_nanos: now.saturating_add(nanos(backoff)),
                        });
                    }
                }
                false
            }
        }
    }
}

impl Version {
    fn open(path: &Path, config: &MmdbFileConfig) -> Result<Self, GeoIpError> {
        let files = match config.handles {
            Some(handles) => ReadAtFiles::open_with_handles(path, handles),
            None => ReadAtFiles::open(path),
        }?;
        let identity = files.identity();
        Self::load(Box::new(files), Some(identity), config)
    }

    /// Validate `src` and build its tree before it can serve lookups.
    fn load(
        src: DynReadAt,
        identity: Option<FileIdentity>,
        config: &MmdbFileConfig,
    ) -> Result<Self, GeoIpError> {
        let cache = BlockCache::new(src, &config.cache)?;
        let size = usize::try_from(cache.len())
            .ok()
            .ok_or(GeoIpError::Unsupported(
                "database larger than the address space",
            ))?;
        let tail_start = metadata_tail_start(size);
        let mut tail = vec![0u8; size - tail_start];
        cache
            .get_ref()
            .read_exact_at(&mut tail, tail_start as u64)
            .map_err(source_error)?;
        let (metadata, marker) = parse_metadata(&tail)?;
        let window = Window::new(&cache, size);
        let tree = window.finish(Tree::new(
            &window,
            size,
            &metadata,
            tail_start + marker,
            config.jump_table,
        ))?;
        drop(window);
        Ok(Self {
            cache,
            size,
            metadata,
            tree,
            identity,
        })
    }

    fn lookup(&self, ip: IpAddr, lang: &str) -> Result<Option<GeoLocation>, GeoIpError> {
        let window = Window::new(&self.cache, self.tree.data_end());
        let found = self.tree.find(&window, ip).map(|record| {
            record.map(|record| {
                let decoder = Decoder::new(&window, self.tree.data_section());
                decode_owned(&decoder, record, lang)
            })
        });
        window.finish(found)
    }
}

/// Identity of the file `path` names now, following symlinks.
fn path_identity(path: &Path) -> Option<FileIdentity> {
    FileIdentity::of_path(path).ok()
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
