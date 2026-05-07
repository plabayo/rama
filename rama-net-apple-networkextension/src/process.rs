use std::{
    ffi::{OsString, c_int, c_void},
    io,
    mem::{MaybeUninit, size_of},
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
// matching updates to the C wrapper at
// `rama_apple_ne_ffi.c::rama_apple_audit_token_to_pid`.
const _: () = assert!(size_of::<AuditToken>() == 32);

impl AuditToken {
    pub const BYTE_LEN: usize = size_of::<Self>();

    #[must_use]
    pub const fn from_raw_words(val: [u32; 8]) -> Self {
        Self { val }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }

        let mut token = MaybeUninit::<Self>::uninit();
        // SAFETY: `bytes` length is exactly the size of `Self`, and destination is valid.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "copy-then-assume-init is a single initialization sequence; the SAFETY comment above covers both ops"
        )]
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                token.as_mut_ptr().cast::<u8>(),
                Self::BYTE_LEN,
            );
            Some(token.assume_init())
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        // SAFETY: `AuditToken` is a plain old data repr(C) wrapper over `[u32; 8]`.
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
        // SAFETY: `bytes` points to `Self::BYTE_LEN` valid bytes; the
        // shim re-validates the length internally and only reads
        // through that span.
        unsafe { __rama_audit_token_to_pid(bytes.as_ptr(), bytes.len()) }
    }
}

unsafe extern "C" {
    fn __rama_audit_token_to_pid(bytes: *const u8, len: usize) -> i32;
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

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
/// # Safety
///
/// This function performs no unchecked memory access — all raw pointers handed
/// to `proc_pidpath` originate from local `Vec` allocations of known size, and
/// `pid` is a plain `i32`.
///
/// The `unsafe` marker is preserved as a discoverability
/// signal: the target process is externally managed by the kernel, so the
/// returned path may already be stale by the time the caller observes it. Treat
/// the result as a best-effort, racy snapshot — not a security boundary.
pub unsafe fn pid_path(pid: i32) -> io::Result<Option<PathBuf>> {
    if pid <= 0 {
        return Ok(None);
    }

    let mut buf = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: buffer is writable for `buf.len()` bytes.
    let written = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written <= 0 {
        return last_os_error_as_absent();
    }

    let len = buf
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(written as usize)
        .min(written as usize);
    Ok(Some(PathBuf::from(OsString::from_vec(buf[..len].to_vec()))))
}

fn sysctl_read(mib: &mut [c_int], out: *mut c_void, out_len: &mut usize) -> io::Result<()> {
    // SAFETY: caller supplies a valid MIB slice and output buffer/len pair.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            out,
            out_len,
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Query the argument vector for a process ID on macOS.
///
/// # Safety
///
/// This function performs no unchecked memory access — all raw pointers handed
/// to `sysctl` originate from local `Vec` allocations of known size, and `pid`
/// is a plain `i32`.
///
/// The `unsafe` marker is preserved as a discoverability
/// signal: the target process is externally managed by the kernel, so its
/// PROCARGS2 buffer may be malformed, truncated, or already stale by the time
/// the caller observes it (the parser is defensive against all of those).
/// Treat the result as a best-effort, racy snapshot — not a security boundary.
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
pub unsafe fn pid_arguments(pid: i32) -> io::Result<Vec<String>> {
    if pid <= 0 {
        return Ok(Vec::new());
    }

    let mut argmax = 0_i32;
    let mut argmax_len = size_of::<i32>();
    sysctl_read(
        &mut [CTL_KERN, KERN_ARGMAX],
        (&mut argmax as *mut i32).cast(),
        &mut argmax_len,
    )?;

    if argmax <= 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0_u8; argmax as usize];
    let mut buf_len = buf.len();
    if let Err(err) = sysctl_read(
        &mut [CTL_KERN, KERN_PROCARGS2, pid],
        buf.as_mut_ptr().cast(),
        &mut buf_len,
    ) {
        return match err.raw_os_error() {
            Some(code) if code == libc::ESRCH || code == libc::ENOENT => {
                last_os_error_as_empty_vec()
            }
            _ => Err(err),
        };
    }

    if buf_len < size_of::<i32>() {
        return Ok(Vec::new());
    }

    // The unsafe read below dereferences via `buf.as_ptr()`, so the relevant
    // invariant is on `buf.len()` (the allocation size), not `buf_len` (the
    // bytes the kernel reported). They satisfy `buf.len() >= buf_len`, but
    // make that explicit so a future change to either side trips this in dev.
    debug_assert!(buf.len() >= size_of::<i32>());
    // SAFETY: `buf` is at least `size_of::<i32>()` bytes long.
    let argc =
        (unsafe { ptr::read_unaligned(buf.as_ptr().cast::<i32>()) }.max(0) as usize).min(4096);
    if argc == 0 {
        return Ok(Vec::new());
    }

    let mut cursor = size_of::<i32>();
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
    }

    #[test]
    fn current_process_path_is_available() {
        let current = std::process::id() as i32;
        // SAFETY: querying our own pid is always safe — `proc_pidpath`
        // accepts any valid pid and the current process necessarily exists.
        let path = unsafe { pid_path(current) }
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
        // SAFETY: same as above — querying our own pid is always valid.
        let args = unsafe { pid_arguments(current) }.expect("read process arguments");
        assert!(!args.is_empty(), "current process should expose argv");
        assert!(!args[0].is_empty(), "argv[0] should not be empty");
    }
}
