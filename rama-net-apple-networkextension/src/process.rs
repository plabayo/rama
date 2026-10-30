// Shared process socket inspection also works outside NetworkExtension hosts.
#[doc(inline)]
pub use rama_net::process::{ProcessSocket, listening_sockets};

use std::{
    ffi::{OsString, c_int, c_void},
    io,
    mem::size_of,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    ptr,
};

/// Top level sysctl namespace for kernel related information.
///
/// This constant is used as the first component in a sysctl MIB (Management
/// Information Base) array when querying kernel state.
///
/// # See also
///
/// - `sysctl(3)`
/// - Darwin headers: `<sys/sysctl.h>`
pub const CTL_KERN: libc::c_int = 1;

/// Maximum size (in bytes) of the combined argument (`argv`) and environment
/// (`envp`) buffer for a process.
///
/// This value is typically queried via `sysctl` and used to allocate a buffer
/// large enough to hold process arguments when calling `KERN_PROCARGS2`.
/// # See also
///
/// - `KERN_PROCARGS2`
/// - `sysctl(3)`
pub const KERN_ARGMAX: libc::c_int = 8;

/// Sysctl selector used to retrieve the raw argument and environment block
/// of a process.
///
/// # See also
///
/// - `sysctl(3)`
/// - Apple DTS notes on process argument retrieval
pub const KERN_PROCARGS2: libc::c_int = 49;

/// Maximum buffer size to use with `proc_pidpath`.
///
/// This value is defined as `4 * MAXPATHLEN` to safely accommodate:
///
/// - long filesystem paths
/// - symbolic links
/// - internal kernel path expansions
///
/// # See also
///
/// - `proc_pidpath` (libproc)
/// - `<libproc.h>`
pub const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * libc::MAXPATHLEN as usize;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuditToken {
    val: [u32; 8],
}

// Apple's `audit_token_t` is 32 bytes on every shipping macOS. If the
// SDK ever changes the layout, this assert breaks the build before
// our struct silently returns a wrong PID. Any change here also needs
// matching updates to the C shim `src/process_shim.c`.
const _: () = assert!(size_of::<AuditToken>() == 32);

impl AuditToken {
    pub const BYTE_LEN: usize = size_of::<Self>();

    #[must_use]
    pub const fn from_raw_words(val: [u32; 8]) -> Self {
        Self { val }
    }

    /// Inverse of [`Self::as_bytes`]: `bytes` holds the eight words in native byte order.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        let mut val = [0_u32; 8];
        let (words, _) = bytes.as_chunks::<{ size_of::<u32>() }>();
        for (word, chunk) in val.iter_mut().zip(words) {
            *word = u32::from_ne_bytes(*chunk);
        }
        Some(Self { val })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        // SAFETY: `&*p` with `p: *const [u8; BYTE_LEN]` needs `p` non-null, aligned,
        // dereferenceable for `BYTE_LEN` initialized bytes, and unmutated for the borrow.
        // - `p` derives from `&self`, so it is non-null and live for the returned
        //   lifetime (tied to `&self`); `AuditToken` has no `UnsafeCell`, so nothing
        //   mutates it while borrowed.
        // - `[u8; N]` has alignment 1 and `BYTE_LEN == size_of::<Self>()`.
        // - `Self` is `repr(C)` with the single field `[u32; 8]` (Reference: `repr(C)`
        //   layout; arrays have no padding), so all 32 bytes are initialized and every
        //   byte value is a valid `u8`.
        unsafe { &*(self as *const Self).cast::<[u8; Self::BYTE_LEN]>() }
    }

    /// Resolve the audit token to a process id via libbsm.
    ///
    /// We don't extract `val[N]` directly: Apple treats
    /// `audit_token_t`'s internal layout as opaque and only commits
    /// to the `audit_token_to_*` macros/functions in `<bsm/libbsm.h>`.
    /// Calling those macros requires C — they read fields whose
    /// indices Apple may renumber. We therefore compile a tiny C shim
    /// (`__rama_audit_token_to_pid`, see `build.rs`) that takes
    /// `(const uint8_t*, size_t)` and uses `audit_token_to_pid()`
    /// internally; that keeps the libbsm header as the single source
    /// of truth for the layout, and the Rust→C call passes only
    /// pointer + length so there is no aggregate-passing ABI
    /// dependency either. Returns `-1` on a malformed input length.
    #[must_use]
    pub fn pid(&self) -> i32 {
        let bytes = self.as_bytes();
        // SAFETY: `__rama_audit_token_to_pid(const uint8_t *bytes, size_t len)` (this
        // crate's `src/process_shim.c`) only reads `len` bytes from a non-null `bytes`
        // and keeps no pointer after returning. `bytes` is a live `&[u8; 32]`, so it is
        // non-null and readable for exactly `bytes.len()` bytes for the whole call.
        unsafe { __rama_audit_token_to_pid(bytes.as_ptr(), bytes.len()) }
    }
}

unsafe extern "C" {
    // `int32_t __rama_audit_token_to_pid(const uint8_t *bytes, size_t len)`.
    fn __rama_audit_token_to_pid(bytes: *const u8, len: usize) -> i32;
}

#[link(name = "proc")]
unsafe extern "C" {
    // `<libproc.h>`: `int proc_pidpath(int pid, void *buffer, uint32_t buffersize)`.
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

// The `buffersize` argument of `proc_pidpath` is a `uint32_t`.
const _: () = assert!(PROC_PIDPATHINFO_MAXSIZE <= u32::MAX as usize);

fn last_os_error_as_absent() -> io::Result<Option<PathBuf>> {
    match io::Error::last_os_error().raw_os_error() {
        Some(code) if code == libc::ESRCH || code == libc::ENOENT => Ok(None),
        _ => Err(io::Error::last_os_error()),
    }
}

fn last_os_error_as_empty_vec() -> io::Result<Vec<String>> {
    match io::Error::last_os_error().raw_os_error() {
        Some(code) if code == libc::ESRCH || code == libc::ENOENT => Ok(Vec::new()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Query the executable path for a process ID on macOS.
///
/// The target process is externally managed by the kernel, so the returned
/// path may already be stale by the time the caller observes it. Treat the
/// result as a best-effort, racy snapshot — not a security boundary.
pub fn pid_path(pid: i32) -> io::Result<Option<PathBuf>> {
    if pid <= 0 {
        return Ok(None);
    }

    let mut buf = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `proc_pidpath` writes at most `buffersize` bytes to `buffer` and keeps
    // no pointer after returning. `buf` is a live, exclusively borrowed allocation
    // of `buf.len()` bytes; the const assert above makes `buf.len() as u32` lossless.
    let written = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written <= 0 {
        return last_os_error_as_absent();
    }

    let written = usize::try_from(written).unwrap_or(0).min(buf.len());
    let len = buf[..written]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(written);
    buf.truncate(len);
    Ok(Some(PathBuf::from(OsString::from_vec(buf))))
}

/// Read the sysctl value named by `mib` into `out`.
///
/// Returns the number of bytes the kernel wrote, never more than `out.len()`.
fn sysctl_read(mib: &mut [c_int], out: &mut [u8]) -> io::Result<usize> {
    let mib_len =
        u32::try_from(mib.len()).map_err(|_overflow| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut out_len = out.len();
    // SAFETY: `sysctl(3)` reads `namelen` ints from `name`, writes at most `*oldlenp`
    // bytes to `oldp` and stores the written length in `*oldlenp`; a null `newp` with
    // `newlen == 0` sets nothing. `mib` is a live slice of `mib_len` ints, `out` is a
    // live, exclusively borrowed slice of `out_len` bytes, and `out_len` is a live
    // local; none is retained after the call.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib_len,
            out.as_mut_ptr().cast(),
            &mut out_len,
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        Ok(out_len.min(out.len()))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Query the argument vector for a process ID on macOS.
///
/// The target process is externally managed by the kernel, so its PROCARGS2
/// buffer may be malformed, truncated, or already stale by the time the
/// caller observes it (the parser is defensive against all of those). Treat
/// the result as a best-effort, racy snapshot — not a security boundary.
///
/// # Cost
///
/// Each call queries `KERN_ARGMAX` (typically 1 MiB on macOS) and then
/// allocates a `Vec<u8>` of that size to fetch the per-PID PROCARGS2
/// buffer. That's fine for low-frequency lookups (e.g. one per flow at
/// admission time), but **do not** call this on a per-packet hot path
/// — at line-rate flow churn the 1 MiB allocation per call dominates.
/// Cache the result per-PID at the caller if you need it more than
/// once for the same process.
pub fn pid_arguments(pid: i32) -> io::Result<Vec<String>> {
    if pid <= 0 {
        return Ok(Vec::new());
    }

    let mut argmax = [0_u8; size_of::<c_int>()];
    sysctl_read(&mut [CTL_KERN, KERN_ARGMAX], &mut argmax)?;
    let argmax = c_int::from_ne_bytes(argmax);
    if argmax <= 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0_u8; argmax as usize];
    let buf_len = match sysctl_read(&mut [CTL_KERN, KERN_PROCARGS2, pid], &mut buf) {
        Ok(len) => len,
        Err(err) => {
            return match err.raw_os_error() {
                Some(code) if code == libc::ESRCH || code == libc::ENOENT => {
                    last_os_error_as_empty_vec()
                }
                _ => Err(err),
            };
        }
    };
    let buf = &buf[..buf_len];

    let Some(argc) = buf.first_chunk::<{ size_of::<c_int>() }>() else {
        return Ok(Vec::new());
    };
    let argc = (c_int::from_ne_bytes(*argc).max(0) as usize).min(4096);
    if argc == 0 {
        return Ok(Vec::new());
    }

    let mut cursor = size_of::<c_int>();
    while cursor < buf_len && buf[cursor] != 0 {
        cursor += 1;
    }
    while cursor < buf_len && buf[cursor] == 0 {
        cursor += 1;
    }

    let mut args = Vec::with_capacity(argc);
    while cursor < buf_len && args.len() < argc {
        let start = cursor;
        while cursor < buf_len && buf[cursor] != 0 {
            cursor += 1;
        }
        if start == cursor {
            break;
        }

        args.push(String::from_utf8_lossy(&buf[start..cursor]).into_owned());
        while cursor < buf_len && buf[cursor] == 0 {
            cursor += 1;
        }
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::{AuditToken, pid_arguments, pid_path};

    #[test]
    fn audit_token_rejects_invalid_byte_length() {
        assert!(AuditToken::from_bytes(&[]).is_none());
        assert!(AuditToken::from_bytes(&[0_u8; AuditToken::BYTE_LEN - 1]).is_none());
    }

    #[test]
    fn audit_token_roundtrips_bytes() {
        let token = AuditToken::from_raw_words([1, 2, 3, 4, 5, 6, 7, 8]);
        let decoded = AuditToken::from_bytes(token.as_bytes()).expect("decode audit token");
        assert_eq!(token, decoded);
        assert_eq!(&token.as_bytes()[4..8], &2_u32.to_ne_bytes());
    }

    #[test]
    fn audit_token_pid_accepts_exact_length() {
        // The shim returns -1 only for a wrong length; a zeroed token is well-formed.
        assert_ne!(AuditToken::from_raw_words([0; 8]).pid(), -1);
    }

    #[test]
    fn non_positive_pids_are_absent() {
        assert!(pid_path(0).unwrap().is_none());
        assert!(pid_path(-1).unwrap().is_none());
        assert!(pid_arguments(0).unwrap().is_empty());
    }

    #[test]
    fn current_process_path_is_available() {
        let current = std::process::id() as i32;
        let path = pid_path(current)
            .expect("read process path")
            .expect("current process path");
        assert!(
            path.is_absolute(),
            "path should be absolute: {}",
            path.display()
        );
    }

    #[test]
    fn current_process_arguments_are_available() {
        let current = std::process::id() as i32;
        let args = pid_arguments(current).expect("read process arguments");
        assert!(!args.is_empty(), "current process should expose argv");
        assert!(!args[0].is_empty(), "argv[0] should not be empty");
    }
}
