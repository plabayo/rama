//! Windows file IDs for [`FileIdentity`](super::FileIdentity).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileIdInfo, GetFileInformationByHandleEx,
};

// `ULONGLONG VolumeSerialNumber; FILE_ID_128 FileId;` in winbase.h
const _: () = assert!(size_of::<FILE_ID_INFO>() == 24 && align_of::<FILE_ID_INFO>() == 8);

/// Size of [`FILE_ID_INFO`] as the `DWORD` the API takes (24, so lossless).
const FILE_ID_INFO_SIZE: u32 = size_of::<FILE_ID_INFO>() as u32;

/// Volume serial number and 128-bit file ID of a file.
pub(super) type FileId = (u64, [u8; 16]);

/// Open `path` (following symlinks) only to query its attributes.
///
/// No access rights are requested and every share mode is granted, as
/// `std::fs::metadata` does, so this never blocks readers, writers or renames.
pub(super) fn open_for_identity(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        // needed to open a directory; no effect on a regular file
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// The file ID of `file`, or `None` where the file system has none (such as FAT).
///
/// "The file identifier and the volume serial number uniquely identify a file
/// on a single computer." (`FILE_ID_INFO`, Microsoft Learn)
pub(super) fn file_id(file: &File) -> Option<FileId> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY:
    // Operation: FFI call to `GetFileInformationByHandleEx(hFile, FileIdInfo,
    // lpFileInformation, dwBufferSize)`.
    // Contract (Microsoft Learn): `hFile` is a handle to the file; for the
    // `FileIdInfo` class the API writes a `FILE_ID_INFO` into the buffer of
    // `dwBufferSize` bytes at `lpFileInformation`.
    // - `file` is borrowed for the whole call, so its handle is open (I/O safety
    //   of `AsRawHandle`).
    // - `info` is a local `FILE_ID_INFO` (layout from `windows-sys`), exclusively
    //   borrowed through the raw pointer for the call, aligned for that type and
    //   writable for `FILE_ID_INFO_SIZE` bytes.
    // - Every bit pattern is a valid `FILE_ID_INFO` (integers only), so `info` is
    //   initialized whether or not the call wrote it.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            FILE_ID_INFO_SIZE,
        )
    };
    (ok != 0).then_some((info.VolumeSerialNumber, info.FileId.Identifier))
}
