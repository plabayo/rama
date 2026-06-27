//! Bucket-rotating keylog sink.
//!
//! Configurable rotation period (in hours or minutes) and optional
//! retention. Each line is written into a file named
//! `<prefix>.<bucket-suffix>` where the suffix encodes the start of
//! the bucket the line belongs to. Hour-grained periods produce
//! `YYYY-MM-DD-HH`; minute-grained periods produce `YYYY-MM-DD-HH-MM`.
//!
//! Rotation only happens on bucket transitions, between lines —
//! every `write_all` ends on a clean line boundary by construction.
//! If `retention` is set, the writer also deletes sibling files whose
//! parsed bucket is older than `now - retention` on each rotation.
//! The actively-open file is never swept.

use rama_core::error::BoxErrorExt as _;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use jiff::{Timestamp, tz::TimeZone};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use rama_utils::fs::{CreatedFilePermissions, OpenOptionsSync};

use super::sink::KeyLogSink;

/// Default filename prefix.
pub const DEFAULT_PREFIX: &str = "sslkeylog";

/// Bound on the writer queue. Keylog is debug plumbing — if the disk
/// can't keep up we drop lines (a few sessions won't decrypt) rather
/// than let an unbounded queue grow RAM without limit. ~16k lines at
/// ~150 B each caps the backlog around a few MB.
const WRITE_QUEUE_CAPACITY: usize = 16 * 1024;

/// Bucket size for [`RotatingFileKeyLogSink`].
///
/// Constructors reject zero — there's no meaningful "rotate every
/// 0 minutes" config and a zero bucket size would diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPeriod {
    /// One bucket spans this many UTC minutes. Filenames embed
    /// minutes (`YYYY-MM-DD-HH-MM`).
    Minutes(u32),
    /// One bucket spans this many UTC hours. Filenames embed only
    /// the hour (`YYYY-MM-DD-HH`).
    Hours(u32),
}

impl RotationPeriod {
    /// One-hour rotation.
    pub const HOURLY: Self = Self::Hours(1);
    /// One-minute rotation.
    pub const MINUTELY: Self = Self::Minutes(1);

    fn validate(self) -> Result<Self, BoxError> {
        let n = match self {
            Self::Minutes(n) | Self::Hours(n) => n,
        };
        if n == 0 {
            return Err(BoxError::from_static_str("RotationPeriod must be non-zero"));
        }
        Ok(self)
    }

    fn bucket_size_seconds(self) -> i64 {
        match self {
            Self::Minutes(n) => i64::from(n) * 60,
            Self::Hours(n) => i64::from(n) * 3600,
        }
    }

    fn strftime_pattern(self) -> &'static str {
        match self {
            Self::Minutes(_) => "%Y-%m-%d-%H-%M",
            Self::Hours(_) => "%Y-%m-%d-%H",
        }
    }

    fn bucket_from_timestamp(self, ts: Timestamp) -> i64 {
        ts.as_second().div_euclid(self.bucket_size_seconds())
    }

    fn current_bucket(self) -> i64 {
        self.bucket_from_timestamp(Timestamp::now())
    }

    fn bucket_to_suffix(self, bucket: i64) -> String {
        // For any realistic wall-clock value `from_second` is safe
        // (jiff covers years -9999..=9999). If the math ever blows
        // past that range we still need *some* distinct filename;
        // fall back to the raw bucket integer so the writer keeps
        // making progress rather than panicking.
        match Timestamp::from_second(bucket * self.bucket_size_seconds()) {
            Ok(ts) => ts
                .to_zoned(TimeZone::UTC)
                .strftime(self.strftime_pattern())
                .to_string(),
            Err(_) => format!("bucket-{bucket}"),
        }
    }

    fn parse_bucket_suffix(self, suffix: &str) -> Option<i64> {
        let parsed = jiff::fmt::strtime::parse(self.strftime_pattern(), suffix).ok()?;
        let civil = parsed.to_datetime().ok()?;
        let ts = civil.to_zoned(TimeZone::UTC).ok()?.timestamp();
        Some(self.bucket_from_timestamp(ts))
    }
}

/// Sink that rotates between bucket-named files.
///
/// Disk I/O happens on a single background writer thread, so callers
/// never block. Rotation is performed by the writer between lines.
#[derive(Debug, Clone)]
pub struct RotatingFileKeyLogSink {
    tx: flume::Sender<String>,
    /// Cumulative count of lines dropped because the bounded queue was
    /// full (disk too slow). Shared across clones.
    dropped: Arc<AtomicU64>,
    dir: PathBuf,
    prefix: String,
    period: RotationPeriod,
}

impl RotatingFileKeyLogSink {
    /// Open with [`DEFAULT_PREFIX`] and no retention sweep.
    pub fn try_open(dir: impl Into<PathBuf>, period: RotationPeriod) -> Result<Self, BoxError> {
        Self::try_open_with(dir, DEFAULT_PREFIX, period, None)
    }

    /// Full constructor.
    ///
    /// `retention = None` keeps rotated files forever. `Some(d)`
    /// sweeps any sibling file whose bucket is older than `now - d`
    /// on every rotation. Sweep granularity is one bucket — retention
    /// is rounded down to whole buckets before comparing.
    pub fn try_open_with(
        dir: impl Into<PathBuf>,
        prefix: &str,
        period: RotationPeriod,
        retention: Option<Duration>,
    ) -> Result<Self, BoxError> {
        let period = period.validate()?;
        let dir: PathBuf = dir.into();
        std::fs::create_dir_all(&dir)
            .context("create dir for rotating keylog")
            .with_context_debug_field("dir", || dir.clone())?;
        rama_utils::fs::safe_path_in_sync(&dir, format!("{prefix}.probe"))
            .context("validate rotating keylog prefix")
            .with_context_debug_field("dir", || dir.clone())
            .context_str_field("prefix", prefix)?;

        let retention_buckets = retention.map(|d| {
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            secs.div_euclid(period.bucket_size_seconds()).max(1)
        });

        let (tx, rx) = flume::bounded::<String>(WRITE_QUEUE_CAPACITY);
        let dir_thread = dir.clone();
        let prefix_thread = prefix.to_owned();
        std::thread::spawn(move || {
            writer_loop(&dir_thread, &prefix_thread, period, retention_buckets, &rx);
        });
        Ok(Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            dir,
            prefix: prefix.to_owned(),
            period,
        })
    }

    /// Directory the sink writes into.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Filename prefix.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Rotation period.
    #[must_use]
    pub fn period(&self) -> RotationPeriod {
        self.period
    }

    /// Cumulative number of lines dropped because the writer queue was
    /// full (disk too slow to keep up).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl KeyLogSink for RotatingFileKeyLogSink {
    fn write_line(&self, line: &str) {
        // Non-blocking: this runs on the TLS handshake callback, which
        // must never block on disk I/O. If the bounded queue is full we
        // drop the line and count it (rate-limited warn) — a full queue
        // means the disk can't keep up, and dropping is preferable to
        // unbounded RAM growth or stalling the handshake.
        match self.tx.try_send(line.to_owned()) {
            Ok(()) => {}
            Err(flume::TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    tracing::warn!(
                        dropped_total = n,
                        "RotatingFileKeyLogSink: write queue full; dropping keylog line(s) (disk too slow?)",
                    );
                }
            }
            Err(flume::TrySendError::Disconnected(_)) => {
                tracing::error!(
                    "RotatingFileKeyLogSink[tx]: writer thread gone; dropping keylog line",
                );
            }
        }
    }
}

fn writer_loop(
    dir: &Path,
    prefix: &str,
    period: RotationPeriod,
    retention_buckets: Option<i64>,
    rx: &flume::Receiver<String>,
) {
    tracing::trace!(
        ?dir,
        %prefix,
        ?period,
        ?retention_buckets,
        "RotatingFileKeyLogSink[rx]: writer thread up",
    );
    let mut current: Option<(i64, File, PathBuf)> = None;

    while let Ok(line) = rx.recv() {
        let bucket = period.current_bucket();
        let need_rotate = current.as_ref().is_none_or(|(b, _, _)| *b != bucket);

        if need_rotate {
            // Drop previous file before opening the new one so any
            // OS-level buffered bytes flush via `File`'s Drop impl.
            current = None;
            let new_path = match make_path(dir, prefix, period, bucket) {
                Ok(path) => path,
                Err(err) => {
                    tracing::error!(
                        ?dir,
                        %prefix,
                        error = %err,
                        "RotatingFileKeyLogSink[rx]: unsafe bucket path; dropping line",
                    );
                    continue;
                }
            };
            match OpenOptionsSync::new()
                .append(true)
                .create(true)
                .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
                .open(&new_path)
            {
                Ok(file) => {
                    if let Some(retain) = retention_buckets {
                        let oldest_kept = bucket - retain + 1;
                        sweep_older_than(dir, prefix, period, oldest_kept, &new_path);
                    }
                    current = Some((bucket, file, new_path));
                }
                Err(err) => {
                    tracing::error!(
                        path = ?new_path,
                        error = %err,
                        "RotatingFileKeyLogSink[rx]: open new bucket failed; dropping line",
                    );
                    continue;
                }
            }
        }

        if let Some((_, file, path)) = current.as_mut()
            && let Err(err) = file.write_all(line.as_bytes())
        {
            tracing::error!(
                path = ?path,
                error = %err,
                "RotatingFileKeyLogSink[rx]: write_all failed: {err:?}",
            );
        }
    }
}

fn make_path(
    dir: &Path,
    prefix: &str,
    period: RotationPeriod,
    bucket: i64,
) -> std::io::Result<PathBuf> {
    rama_utils::fs::safe_path_in_sync(dir, format!("{prefix}.{}", period.bucket_to_suffix(bucket)))
}

fn sweep_older_than(
    dir: &Path,
    prefix: &str,
    period: RotationPeriod,
    oldest_kept_bucket: i64,
    active_path: &Path,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::debug!(?dir, %err, "RotatingFileKeyLogSink: sweep read_dir failed");
            return;
        }
    };
    let needle = format!("{prefix}.");
    for entry in entries.flatten() {
        let path = entry.path();
        if path == active_path {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(&needle) else {
            continue;
        };
        let Some(bucket) = period.parse_bucket_suffix(suffix) else {
            continue;
        };
        if bucket < oldest_kept_bucket
            && let Err(err) = std::fs::remove_file(&path)
        {
            tracing::debug!(?path, %err, "RotatingFileKeyLogSink: sweep remove failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_zero_is_rejected() {
        RotationPeriod::Hours(0).validate().unwrap_err();
        RotationPeriod::Minutes(0).validate().unwrap_err();
        RotationPeriod::Hours(1).validate().unwrap();
        RotationPeriod::Minutes(15).validate().unwrap();
    }

    #[test]
    fn hourly_bucket_round_trip() {
        // 2026-05-19T12:07:00Z → bucket = epoch / 3600 → 488 664.
        let ts = Timestamp::from_second(1_779_192_420).unwrap();
        let p = RotationPeriod::HOURLY;
        let bucket = p.bucket_from_timestamp(ts);
        let suffix = p.bucket_to_suffix(bucket);
        assert_eq!(suffix, "2026-05-19-12");
        assert_eq!(p.parse_bucket_suffix(&suffix).unwrap(), bucket);
    }

    #[test]
    fn minutely_bucket_round_trip_carries_minute() {
        // 2026-05-19T12:07:00Z; with 5-minute bucket, start = 12:05.
        let ts = Timestamp::from_second(1_779_192_420).unwrap();
        let p = RotationPeriod::Minutes(5);
        let bucket = p.bucket_from_timestamp(ts);
        let suffix = p.bucket_to_suffix(bucket);
        assert_eq!(suffix, "2026-05-19-12-05");
        assert_eq!(p.parse_bucket_suffix(&suffix).unwrap(), bucket);
    }

    #[test]
    fn parse_bucket_suffix_rejects_garbage() {
        let p = RotationPeriod::HOURLY;
        assert!(p.parse_bucket_suffix("not-a-date").is_none());
        assert!(p.parse_bucket_suffix("2026-13-99-25").is_none());
        assert!(p.parse_bucket_suffix("").is_none());
        // Wrong granularity: a minute-shaped suffix won't parse as hour.
        assert!(p.parse_bucket_suffix("2026-05-19-12-05").is_none());
    }

    #[test]
    fn bounded_queue_drops_when_full_without_blocking() {
        // Tiny-capacity sink whose receiver is held but never drained,
        // so the queue fills and further writes drop instead of block.
        let (tx, _rx) = flume::bounded::<String>(2);
        let sink = RotatingFileKeyLogSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            dir: PathBuf::from("/nonexistent"),
            prefix: DEFAULT_PREFIX.to_owned(),
            period: RotationPeriod::HOURLY,
        };
        for _ in 0..5 {
            sink.write_line("CLIENT_RANDOM a b\n");
        }
        assert_eq!(
            sink.dropped(),
            3,
            "3 lines dropped after the 2-slot queue filled"
        );
        // Keep `_rx` alive so the channel is Full (not Disconnected).
        drop(_rx);
    }

    #[test]
    fn writes_land_in_current_bucket_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let period = RotationPeriod::HOURLY;
        let sink = RotatingFileKeyLogSink::try_open(dir.path(), period).expect("open");
        sink.write_line("CLIENT_RANDOM a b\n");
        sink.write_line("CLIENT_RANDOM c d\n");
        drop(sink);

        let expected_path = make_path(dir.path(), DEFAULT_PREFIX, period, period.current_bucket())
            .expect("valid keylog path");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(content) = std::fs::read_to_string(&expected_path)
                && content == "CLIENT_RANDOM a b\nCLIENT_RANDOM c d\n"
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "writer never drained");
            std::thread::sleep(Duration::from_millis(10));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&expected_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn rejects_prefix_that_escapes_log_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = RotatingFileKeyLogSink::try_open_with(
            dir.path(),
            "../sslkeylog",
            RotationPeriod::HOURLY,
            None,
        )
        .expect_err("prefix traversal should be rejected");
        assert!(
            err.to_string().contains("validate rotating keylog prefix"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn sweep_removes_files_older_than_window_keeps_recent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let period = RotationPeriod::HOURLY;
        let now = period.current_bucket();
        let touch = |bucket: i64| {
            let path = make_path(dir.path(), DEFAULT_PREFIX, period, bucket).expect("valid path");
            std::fs::write(&path, b"stub\n").unwrap();
            path
        };
        // Retention = 8 hours → keep buckets in [now-7 .. now], sweep older.
        let retention_buckets = 8;
        let stale = touch(now - 9);
        let edge = touch(now - 8);
        let kept_recent = touch(now - 3);
        let unrelated = dir.path().join("not-our-prefix.2026-01-01-00");
        std::fs::write(&unrelated, b"keep\n").unwrap();
        let foreign_suffix = dir.path().join(format!("{DEFAULT_PREFIX}.unparseable"));
        std::fs::write(&foreign_suffix, b"keep\n").unwrap();

        let active = make_path(dir.path(), DEFAULT_PREFIX, period, now).expect("valid path");
        sweep_older_than(
            dir.path(),
            DEFAULT_PREFIX,
            period,
            now - retention_buckets + 1,
            &active,
        );

        assert!(!stale.exists(), "stale (bucket - 9) should have been swept");
        assert!(!edge.exists(), "edge (bucket - 8) should have been swept");
        assert!(kept_recent.exists(), "recent (bucket - 3) must remain");
        assert!(unrelated.exists(), "unrelated prefix must not be touched");
        assert!(
            foreign_suffix.exists(),
            "unparseable suffix must not be touched",
        );
    }

    #[test]
    fn sweep_never_deletes_active_file_even_if_old() {
        // Synthetic: active path is for an old bucket. Sweep must
        // still leave it alone — invariant prevents self-deletion if
        // the system clock jumps backward.
        let dir = tempfile::tempdir().expect("tempdir");
        let period = RotationPeriod::HOURLY;
        let active = make_path(dir.path(), DEFAULT_PREFIX, period, 0).expect("valid path"); // 1970-01-01-00
        std::fs::write(&active, b"active\n").unwrap();
        sweep_older_than(dir.path(), DEFAULT_PREFIX, period, i64::MAX, &active);
        assert!(active.exists());
    }

    #[test]
    fn retention_none_means_no_sweep_at_end_to_end_open() {
        // Pre-create a very old file; opening without retention must
        // leave it alone even after a write (which triggers rotation).
        let dir = tempfile::tempdir().expect("tempdir");
        let period = RotationPeriod::HOURLY;
        let ancient = make_path(dir.path(), DEFAULT_PREFIX, period, 0).expect("valid path");
        std::fs::write(&ancient, b"ancient\n").unwrap();

        let sink = RotatingFileKeyLogSink::try_open_with(dir.path(), DEFAULT_PREFIX, period, None)
            .expect("open");
        sink.write_line("now\n");
        drop(sink);

        // Give the writer thread a moment to land its line.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let active = make_path(dir.path(), DEFAULT_PREFIX, period, period.current_bucket())
            .expect("valid path");
        loop {
            if std::fs::read_to_string(&active)
                .map(|s| s.contains("now"))
                .unwrap_or(false)
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ancient.exists(), "no retention → no sweep");
    }
}
