use std::{
    collections::hash_map::Entry,
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

use ahash::HashMap;
use parking_lot::RwLock;
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;

use super::sink::KeyLogSink;

/// Sink that appends every line to a single file.
///
/// One background writer thread per unique normalized path; opening
/// the same path twice returns a clone of the existing handle, so
/// concurrent users share the writer (no interleaved writes).
#[derive(Debug, Clone)]
pub struct FileKeyLogSink {
    path: PathBuf,
    tx: flume::Sender<String>,
}

impl FileKeyLogSink {
    /// Open (or join an existing handle for) the file at `path`.
    pub fn try_open(path: &str) -> Result<Self, BoxError> {
        let path: PathBuf = path
            .parse()
            .context("parse path str as Path")
            .context_str_field("path", path)?;
        let path = normalize_path(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("create parent dir(s) for keylog file")
                .with_context_debug_field("parent", || parent.to_owned())?;
        }

        let mapping = GLOBAL_SINKS.get_or_init(Default::default);
        if let Some(existing) = mapping.read().get(&path).cloned() {
            return Ok(existing);
        }
        let mut w = mapping.write();
        match w.entry(path.clone()) {
            Entry::Occupied(e) => Ok(e.get().clone()),
            Entry::Vacant(e) => {
                let sink = Self::open_uncached(path)?;
                e.insert(sink.clone());
                Ok(sink)
            }
        }
    }

    /// Honour `SSLKEYLOGFILE`: if set and non-empty, open that file;
    /// otherwise return `Ok(None)`.
    pub fn try_from_env() -> Result<Option<Self>, BoxError> {
        match std::env::var("SSLKEYLOGFILE") {
            Ok(p) if !p.is_empty() => Self::try_open(&p).map(Some),
            _ => Ok(None),
        }
    }

    /// Path this sink writes to (after normalization).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_uncached(path: PathBuf) -> Result<Self, BoxError> {
        tracing::trace!(file.path = ?path, "FileKeyLogSink: opening");
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .context("open keylog file")
            .with_context_debug_field("path", || path.clone())?;

        let (tx, rx) = flume::unbounded::<String>();
        let path_for_thread = path.clone();
        std::thread::spawn(move || {
            tracing::trace!(
                file.path = ?path_for_thread,
                "FileKeyLogSink[rx]: writer thread up",
            );
            while let Ok(line) = rx.recv() {
                if let Err(err) = file.write_all(line.as_bytes()) {
                    tracing::error!(
                        file.path = ?path_for_thread,
                        "FileKeyLogSink[rx]: write_all failed: {err:?}",
                    );
                }
            }
        });
        Ok(Self { path, tx })
    }
}

impl KeyLogSink for FileKeyLogSink {
    fn write_line(&self, line: &str) {
        if let Err(err) = self.tx.send(line.to_owned()) {
            tracing::error!(
                file.path = ?self.path,
                error = %err,
                "FileKeyLogSink[tx]: failed to enqueue: {err:?}",
            );
        }
    }
}

static GLOBAL_SINKS: OnceLock<RwLock<HashMap<PathBuf, FileKeyLogSink>>> = OnceLock::new();

// copied from
// <https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61>
#[must_use]
#[expect(
    clippy::unreachable,
    reason = "vendored from cargo: Component::Prefix is consumed by the peek+next above, so it cannot reappear in the iteration loop"
)]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_land_in_target_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys.txt");
        let sink = FileKeyLogSink::try_open(path.to_str().unwrap()).expect("open");
        sink.write_line("CLIENT_RANDOM aaa bbb\n");
        sink.write_line("CLIENT_RANDOM ccc ddd\n");
        // Drop the sink to close the channel and let the writer drain.
        drop(sink);
        // The bg writer drains the channel on rx.recv()==Err; give it a moment.
        // Polling is robust against scheduler timing.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Ok(content) = std::fs::read_to_string(&path)
                && content == "CLIENT_RANDOM aaa bbb\nCLIENT_RANDOM ccc ddd\n"
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "writer never drained");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn try_open_same_path_returns_shared_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shared.txt");
        let s1 = FileKeyLogSink::try_open(path.to_str().unwrap()).expect("first open");
        let s2 = FileKeyLogSink::try_open(path.to_str().unwrap()).expect("second open");
        // Same tx channel = same writer thread = no interleave.
        assert!(s1.tx.same_channel(&s2.tx));
    }

    #[test]
    fn normalize_path_collapses_dot_dirs() {
        let p = normalize_path(Path::new("/tmp/./foo/../bar/baz.txt"));
        assert_eq!(p, PathBuf::from("/tmp/bar/baz.txt"));
    }
}
