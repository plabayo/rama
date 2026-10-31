//! Positional reads from a shared source.
//!
//! [`ReadAt`] reads at an explicit offset through `&self`, so one source
//! serves many threads without a cursor or a lock. [`ReadAtFiles`] opens a
//! file for that use and [`BlockCache`] keeps hot blocks of any source in
//! memory.

use std::fs::{File, Metadata};
use std::io;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

#[cfg(unix)]
use std::os::unix::fs::{FileExt, MetadataExt as _};
#[cfg(windows)]
use std::os::windows::fs::{FileExt as _, MetadataExt as _};
#[cfg(not(any(unix, windows)))]
use std::time::SystemTime;

mod block_cache;
#[doc(inline)]
pub use block_cache::{BlockCache, BlockCacheConfig};

mod files;
#[doc(inline)]
pub use files::ReadAtFiles;

#[cfg(windows)]
mod windows;

/// Positional reads through `&self`, safe to call from many threads at once.
///
/// # Blocking
///
/// A read from a file is a blocking syscall (`pread` on Unix, `ReadFile` on
/// Windows). While the file is cached in the OS page cache it costs microseconds,
/// the same class of stall as a page fault on a memory map, so calling it from
/// an async task is accepted. Should cold-disk latency ever matter, move the
/// reads to `spawn_blocking`, to a dedicated reader thread, or to an async
/// positional read API (io_uring, IOCP) behind this same trait.
pub trait ReadAt {
    /// Fill all of `buf` with the bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] if the source ends before
    /// `buf` is full, or any I/O error of the source. The contents of `buf`
    /// are unspecified on error.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// The current size of the source in bytes.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the source if its size cannot be queried.
    fn size(&self) -> io::Result<u64>;
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let src = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..start.checked_add(buf.len())?))
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_slice().read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        self.as_slice().size()
    }
}

impl ReadAt for Bytes {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_ref().read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        self.as_ref().size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Arc<T> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
}

/// On Unix the read does not move the file cursor.
///
/// On Windows each read moves the cursor of the handle, and the OS serializes
/// all reads on one handle; use [`ReadAtFiles`] to read a file from many
/// threads in parallel.
#[cfg(any(unix, windows))]
impl ReadAt for File {
    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        read_exact_at_with(buf, offset, |buf, offset| self.seek_read(buf, offset))
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// Fill `buf` through a positional read that may return short counts.
///
/// Retries [`io::ErrorKind::Interrupted`] and maps a 0-byte read to
/// [`io::ErrorKind::UnexpectedEof`], as `seek_read` signals the end that way.
#[cfg(any(windows, test))]
fn read_exact_at_with(
    mut buf: &mut [u8],
    mut offset: u64,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(buf, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) => {
                buf = buf
                    .get_mut(n..)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                offset = offset
                    .checked_add(n as u64)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Which file a path or handle names, and whether it changed.
///
/// On Unix it is device, inode, size, modification and change time; on
/// Windows volume serial number, 128-bit file ID, size and last write time;
/// elsewhere size and modification time. Two snapshots differ when any field
/// differs, so a replacement with an older timestamp is a change too.
///
/// Build it with [`Self::of_path`] or [`Self::of_file`]. [`Self::from_metadata`]
/// has no file ID on Windows, so there it tells files apart by size and last
/// write time only, and that time advances in timer ticks (about 15.6 ms): a
/// same-size replacement renamed in within one tick looks unchanged. Only
/// compare identities built the same way.
///
/// A same-size in-place rewrite within one timestamp tick is not visible on
/// any platform, nor is a same-size replacement within one tick on a Windows
/// file system without file IDs (such as FAT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    size: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mtime: (i64, i64),
    #[cfg(unix)]
    ctime: (i64, i64),
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(windows)]
    file_id: Option<windows::FileId>,
    #[cfg(not(any(unix, windows)))]
    modified: Option<SystemTime>,
}

impl FileIdentity {
    /// Snapshot the identity of the file `path` names now, following symlinks.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of opening or querying `path`.
    pub fn of_path(path: impl AsRef<Path>) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Self::of_file(&windows::open_for_identity(path.as_ref())?)
        }
        #[cfg(not(windows))]
        {
            Ok(Self::from_metadata(&std::fs::metadata(path)?))
        }
    }

    /// Snapshot the identity of the open file `file`.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of querying `file`.
    pub fn of_file(file: &File) -> io::Result<Self> {
        Ok(Self::of_file_with_metadata(file, &file.metadata()?))
    }

    /// [`Self::of_file`] for metadata already queried from `file`.
    #[cfg_attr(not(windows), expect(unused_variables))]
    pub(super) fn of_file_with_metadata(file: &File, metadata: &Metadata) -> Self {
        #[cfg(windows)]
        {
            Self {
                file_id: windows::file_id(file),
                ..Self::from_metadata(metadata)
            }
        }
        #[cfg(not(windows))]
        {
            Self::from_metadata(metadata)
        }
    }

    /// Snapshot the identity fields of `metadata`.
    ///
    /// On Windows this leaves out the file ID, which metadata does not carry;
    /// see the type docs.
    #[must_use]
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            size: metadata.len(),
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
            #[cfg(unix)]
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            #[cfg(unix)]
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            #[cfg(windows)]
            last_write_time: metadata.last_write_time(),
            #[cfg(windows)]
            file_id: None,
            #[cfg(not(any(unix, windows)))]
            modified: metadata.modified().ok(),
        }
    }

    /// The file size in bytes at the time of the snapshot.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl From<&Metadata> for FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self::from_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_utils::octets::kib;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn slice_reads_and_eof() {
        let data = pattern(100);
        let mut buf = [0u8; 10];
        data.read_exact_at(&mut buf, 90).unwrap();
        assert_eq!(&buf[..], &data[90..100]);
        let err = data.read_exact_at(&mut buf, 91).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let err = data.read_exact_at(&mut buf, u64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        data.read_exact_at(&mut [], 100).unwrap();
        assert_eq!(data.size().unwrap(), 100);
    }

    #[test]
    fn forwarding_impls_agree() {
        let data = pattern(64);
        let boxed: Box<[u8]> = data.clone().into_boxed_slice();
        let shared: Arc<[u8]> = Arc::from(data.as_slice());
        let bytes = Bytes::from(data.clone());
        let dynamic: Box<dyn ReadAt + Send + Sync> = Box::new(data.clone());
        let sources: [&dyn ReadAt; 6] = [&data, &boxed, &shared, &bytes, &dynamic, &&data];
        for src in sources {
            let mut buf = [0u8; 8];
            src.read_exact_at(&mut buf, 3).unwrap();
            assert_eq!(&buf[..], &data[3..11]);
            assert_eq!(src.size().unwrap(), 64);
        }
    }

    #[test]
    fn short_reads_and_interrupts_are_retried() {
        let data = pattern(50);
        let mut calls = 0;
        let mut buf = [0u8; 20];
        read_exact_at_with(&mut buf, 5, |out, offset| {
            calls += 1;
            if calls % 2 == 1 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            // at most 3 bytes per call
            let n = out.len().min(3);
            let start = offset as usize;
            out[..n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        })
        .unwrap();
        assert_eq!(&buf[..], &data[5..25]);
        assert!(calls > 7);
    }

    #[test]
    fn zero_byte_read_is_eof() {
        let mut buf = [0u8; 4];
        let err = read_exact_at_with(&mut buf, 0, |_, _| Ok(0)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn overlong_read_count_is_an_error() {
        let mut buf = [0u8; 4];
        let err = read_exact_at_with(&mut buf, 0, |out, _| Ok(out.len() + 1)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn other_errors_propagate() {
        let mut buf = [0u8; 4];
        let err = read_exact_at_with(&mut buf, 0, |_, _| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(any(unix, windows))]
    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn file_reads_from_many_threads() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        let data = pattern(kib(256));
        std::fs::write(&path, &data).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(file.size().unwrap(), data.len() as u64);

        std::thread::scope(|s| {
            for t in 0..8u64 {
                let (file, data) = (&file, &data);
                s.spawn(move || {
                    let mut state = 0x9E37_79B9_7F4A_7C15 ^ t;
                    for _ in 0..500 {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        let len = (state % 9000) as usize;
                        let offset = (state >> 20) as usize % (data.len() - len);
                        let mut buf = vec![0u8; len];
                        ReadAt::read_exact_at(file, &mut buf, offset as u64).unwrap();
                        assert_eq!(buf, data[offset..offset + len]);
                    }
                });
            }
        });

        let mut buf = [0u8; 2];
        let err = ReadAt::read_exact_at(&file, &mut buf, data.len() as u64 - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[cfg(any(unix, windows))]
    #[test]
    #[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
    fn identity_tracks_replacement() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("id.bin");
        std::fs::write(&path, b"one").unwrap();
        let first = FileIdentity::from(&std::fs::metadata(&path).unwrap());
        assert_eq!(
            first,
            FileIdentity::from(&std::fs::metadata(&path).unwrap())
        );
        assert_eq!(first.size(), 3);

        let next = dir.path().join("id.next");
        std::fs::write(&next, b"two!").unwrap();
        std::fs::rename(&next, &path).unwrap();
        assert_ne!(
            first,
            FileIdentity::from(&std::fs::metadata(&path).unwrap())
        );
    }
}
