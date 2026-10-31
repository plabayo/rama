use std::fs::File;
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

use super::{FileIdentity, ReadAt};

/// Opening all handles is retried this often when the path changes meanwhile.
const OPEN_ATTEMPTS: usize = 3;

/// Upper bound on the handle list reserved up front, whatever count is asked.
const MAX_PREALLOCATED_HANDLES: usize = 64;

/// Handles opened per file by default on Windows.
#[cfg(windows)]
const MAX_DEFAULT_HANDLES: usize = 8;

/// Round-robin source for [`THREAD_SLOT`].
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

std::thread_local! {
    /// Per-thread handle choice, so threads spread evenly over the handles.
    static THREAD_SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
}

/// A regular file opened for [`ReadAt`] from many threads.
///
/// Windows serializes all reads on one handle, so there the file is opened
/// several times (by default `min(available_parallelism, 8)`) and each thread
/// sticks to one handle. Elsewhere one handle suffices.
///
/// On Windows the handles share read and delete access but not write access:
/// a writer that opens the file in place fails, and the handles keep reading
/// a file that was replaced or removed. Replacing it needs a rename that may
/// replace an open file: `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, which
/// many runtimes use for their rename or move, fails with `ERROR_ACCESS_DENIED`
/// while a handle is open. [`std::fs::rename`] then falls back to a POSIX
/// semantics rename (NTFS, Windows 10 1809 and later), which works. With
/// other tools, first rename the old file away, then the new one into place.
#[derive(Debug)]
pub struct ReadAtFiles {
    files: Box<[File]>,
    identity: FileIdentity,
}

impl ReadAtFiles {
    /// Open `path` with the default number of handles for this platform.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of opening `path`, [`io::ErrorKind::InvalidInput`]
    /// if it is not a regular file, or [`io::ErrorKind::Other`] if the path
    /// kept naming different files while the handles were opened.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_handles(path, default_handles())
    }

    /// Open `path` with `handles` handles.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`].
    pub fn open_with_handles(path: impl AsRef<Path>, handles: NonZeroUsize) -> io::Result<Self> {
        let path = path.as_ref();
        // checked before opening too: Windows refuses to open a directory
        // this way with an error of its own
        if !std::fs::metadata(path)?.is_file() {
            return Err(not_a_file());
        }
        for _ in 0..OPEN_ATTEMPTS {
            let first = open_one(path)?;
            let metadata = first.metadata()?;
            // the path may have changed between the stat and the open
            if !metadata.is_file() {
                return Err(not_a_file());
            }
            let identity = FileIdentity::of_file_with_metadata(&first, &metadata);
            let mut files = Vec::with_capacity(handles.get().min(MAX_PREALLOCATED_HANDLES));
            files.push(first);
            for _ in 1..handles.get() {
                let file = open_one(path)?;
                // a rename between two opens leaves handles on different files
                if FileIdentity::of_file(&file)? != identity {
                    break;
                }
                files.push(file);
            }
            if files.len() == handles.get() {
                return Ok(Self {
                    files: files.into_boxed_slice(),
                    identity,
                });
            }
        }
        Err(io::Error::other("file kept changing while it was opened"))
    }

    /// The identity of the file, taken from the first handle when it was opened.
    #[must_use]
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The number of open handles.
    #[must_use]
    pub fn handles(&self) -> usize {
        self.files.len()
    }

    fn file(&self) -> &File {
        match self.files.as_ref() {
            [file] => file,
            files => {
                let slot = THREAD_SLOT.with(|slot| *slot);
                &files[slot % files.len()]
            }
        }
    }
}

impl ReadAt for ReadAtFiles {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file().read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        self.file().size()
    }
}

fn not_a_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "positional reads need a regular file",
    )
}

#[cfg(windows)]
fn default_handles() -> NonZeroUsize {
    let parallelism = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    NonZeroUsize::new(parallelism.min(MAX_DEFAULT_HANDLES)).unwrap_or(NonZeroUsize::MIN)
}

#[cfg(not(windows))]
fn default_handles() -> NonZeroUsize {
    NonZeroUsize::MIN
}

#[cfg(windows)]
fn open_one(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
}

#[cfg(not(windows))]
fn open_one(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use rama_utils::octets::kib;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 253) as u8).collect()
    }

    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn pool_reads_from_many_threads() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("pool.bin");
        let data = pattern(kib(64));
        std::fs::write(&path, &data).unwrap();

        let files = ReadAtFiles::open_with_handles(&path, NonZeroUsize::new(4).unwrap()).unwrap();
        assert_eq!(files.handles(), 4);
        assert_eq!(files.size().unwrap(), data.len() as u64);
        assert_eq!(files.identity().size(), data.len() as u64);

        std::thread::scope(|s| {
            for t in 0..8usize {
                let (files, data) = (&files, &data);
                s.spawn(move || {
                    for i in 0..200usize {
                        let offset = (t * 7919 + i * 104_729) % (data.len() - 100);
                        let mut buf = [0u8; 100];
                        files.read_exact_at(&mut buf, offset as u64).unwrap();
                        assert_eq!(&buf[..], &data[offset..offset + 100]);
                    }
                });
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn rejects_directories_and_missing_paths() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let err = ReadAtFiles::open(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = ReadAtFiles::open(dir.path().join("missing")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn replace_and_remove_while_open() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("live.bin");
        std::fs::write(&path, b"old data").unwrap();
        let files = ReadAtFiles::open(&path).unwrap();

        let next = dir.path().join("live.next");
        std::fs::write(&next, b"new data").unwrap();
        std::fs::rename(&next, &path).unwrap();
        let mut buf = [0u8; 8];
        files.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"old data");

        std::fs::remove_file(&path).unwrap();
        files.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"old data");
    }

    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn same_size_replacements_have_distinct_identities() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("swap.bin");
        let next = dir.path().join("swap.next");
        std::fs::write(&path, b"data-0").unwrap();
        let mut opened = vec![ReadAtFiles::open(&path).unwrap()];
        // back to back, so last write times often coincide
        for i in 1..=4u8 {
            std::fs::write(&next, [b'd', b'a', b't', b'a', b'-', b'0' + i]).unwrap();
            std::fs::rename(&next, &path).unwrap();
            let files = ReadAtFiles::open(&path).unwrap();
            assert_eq!(files.identity(), FileIdentity::of_path(&path).unwrap());
            opened.push(files);
        }
        // the open handles keep every file alive, so no file ID is reused
        for (i, a) in opened.iter().enumerate() {
            for b in &opened[i + 1..] {
                assert_ne!(a.identity(), b.identity());
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn in_place_writers_fail_on_windows() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("locked.bin");
        std::fs::write(&path, b"data").unwrap();
        let _files = ReadAtFiles::open(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_err();
    }
}
