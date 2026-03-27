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

    #[must_use]
    pub fn pid(&self) -> i32 {
        // SAFETY: Apple documents `audit_token_to_pid` for valid `audit_token_t` values.
        unsafe { audit_token_to_pid(*self) }
    }
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
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
/// The target process is externally managed and may exit or change between
/// inspection steps. Callers must treat the returned data as a best-effort
/// snapshot only.
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
/// The target process is externally managed and may exit or change between
/// inspection steps. Callers must treat the returned data as a best-effort
/// snapshot only.
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

    // SAFETY: `buf` is at least `size_of::<i32>()` bytes long.
    let argc = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<i32>()) }.max(0) as usize;
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
        let args = unsafe { pid_arguments(current) }.expect("read process arguments");
        assert!(!args.is_empty(), "current process should expose argv");
        assert!(!args[0].is_empty(), "argv[0] should not be empty");
    }
}
