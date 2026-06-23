//! Lexical path sanitization used to guard against path-traversal attacks.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Error returned when a path is rejected as unsafe.
///
/// Produced by [`sanitize_path`] and the safe-open helpers in this module
/// ([`safe_open`](crate::fs::safe_open), [`safe_open_in`](crate::fs::safe_open_in),
/// [`OpenOptions`](crate::fs::OpenOptions)). Converts into an
/// [`std::io::Error`] with [`std::io::ErrorKind::InvalidInput`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsafePathError {
    /// The path contained a parent-directory (`..`) component, which can be
    /// used to escape the intended directory ("dot-dot" traversal).
    ParentDir,
    /// An absolute path (or one carrying a root/drive/UNC prefix) was supplied
    /// where only a relative path is permitted (e.g. when confined to a root).
    Absolute,
    /// A component matched a reserved device name (e.g. Windows `CON`, `NUL`,
    /// `COM1`), which has special and surprising filesystem semantics.
    ReservedName,
    /// The fully resolved path escaped the configured root directory, e.g.
    /// through a symbolic link pointing outside of it.
    EscapesRoot,
}

impl fmt::Display for UnsafePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::ParentDir => "path contains a parent-directory (`..`) component",
            Self::Absolute => "path is absolute but only a relative path is allowed",
            Self::ReservedName => "path contains a reserved device name",
            Self::EscapesRoot => "path escapes the permitted root directory",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for UnsafePathError {}

impl From<UnsafePathError> for std::io::Error {
    fn from(err: UnsafePathError) -> Self {
        Self::new(std::io::ErrorKind::InvalidInput, err)
    }
}

/// Validate `path` and return a cleaned, lexically-equivalent path that is safe
/// from "dot-dot" traversal.
///
/// `.` (current-dir) components are dropped and `..` (parent-dir) components are
/// rejected ([`UnsafePathError::ParentDir`]). Components that smuggle in a path
/// prefix (e.g. a Windows drive letter in `foo/c:/bar`) and reserved device
/// names (Windows `CON`, `NUL`, `COM1`, ...) are rejected too.
///
/// Absolute paths are permitted: a leading root/prefix is preserved. The
/// guarantee is only that the result never points *above* its own starting
/// point. When the path must stay within a known directory, use
/// [`safe_open_in`](crate::fs::safe_open_in) /
/// [`OpenOptions::jail`](crate::fs::OpenOptions::jail), which additionally
/// reject absolute paths and resolve symlinks against the root.
///
/// Note: this works on already-decoded paths. Percent-decoding (e.g. of an HTTP
/// target like `%2e%2e%2f`) is the caller's responsibility and must happen
/// *before* calling this function.
pub fn sanitize_path(path: impl AsRef<Path>) -> Result<PathBuf, UnsafePathError> {
    sanitize(path.as_ref(), false)
}

/// Like [`sanitize_path`] but additionally requires the path to be relative,
/// rejecting absolute paths and drive/UNC prefixes ([`UnsafePathError::Absolute`]).
///
/// Returns the cleaned relative path with `.` components dropped; join it onto
/// a trusted root directory to confine filesystem access to within that root.
/// This is the lexical primitive shared by safe filesystem mapping of
/// untrusted relative paths (e.g. a static file server).
pub fn sanitize_relative_path(path: impl AsRef<Path>) -> Result<PathBuf, UnsafePathError> {
    sanitize(path.as_ref(), true)
}

fn sanitize(path: &Path, relative_only: bool) -> Result<PathBuf, UnsafePathError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                if relative_only {
                    return Err(UnsafePathError::Absolute);
                }
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(UnsafePathError::ParentDir),
            Component::Normal(name) => {
                check_normal_component(name)?;
                out.push(name);
            }
        }
    }
    Ok(out)
}

/// Validate a single `Normal` path component.
fn check_normal_component(name: &OsStr) -> Result<(), UnsafePathError> {
    // A normal component must not itself decompose into anything other than a
    // single normal component. This rejects a smuggled prefix/root such as a
    // Windows drive letter in `foo/c:/bar` (rama #204).
    if !Path::new(name)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(UnsafePathError::Absolute);
    }

    // Reserved device names only have special semantics on Windows, where a
    // valid Unix filename like `CON` would resolve to a device.
    #[cfg(windows)]
    if is_reserved_device_name(name) {
        return Err(UnsafePathError::ReservedName);
    }

    Ok(())
}

/// Whether `name` matches a reserved Windows device name (e.g. `CON`, `NUL`,
/// `COM1`, `LPT9`), independent of the current platform.
///
/// Accepts any OS-string-like value (`&str`, `String`, `&OsStr`, `&Path`, ...),
/// mirroring how the path helpers in this module take [`AsRef<Path>`](Path).
///
/// This answers a property of the *name*, not of the running OS: on a Windows
/// host such a name resolves to a device rather than a file, so it must be
/// rejected when mapping untrusted input to the filesystem (see
/// the normal-component validator, which only consults it on Windows). Exposed so
/// other crates can reuse the exact same check instead of duplicating it.
#[must_use]
pub fn is_reserved_device_name(name: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref();
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        is_reserved_dos_name(|| name.encode_wide())
    }
    #[cfg(not(windows))]
    {
        let name = name.to_string_lossy();
        is_reserved_dos_name(|| name.encode_utf16())
    }
}

/// Check whether a component name matches a reserved Windows DOS device name.
/// See: <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions>
///
/// We explicitly check for the Unicode superscript characters `¹` (0x00B9),
/// `²` (0x00B2) and `³` (0x00B3) because legacy Win32 file parsing resolves
/// them natively as the port numbers 1/2/3.
///
/// Uses an iterator and a stack array to avoid allocating. The closure is used
/// because the input is iterated twice and must yield the same iterator each
/// time it is called.
fn is_reserved_dos_name<F, I>(mut get_iter: F) -> bool
where
    F: FnMut() -> I,
    I: Iterator<Item = u16>,
{
    const CON: [u16; 3] = [b'C' as u16, b'O' as u16, b'N' as u16];
    const PRN: [u16; 3] = [b'P' as u16, b'R' as u16, b'N' as u16];
    const AUX: [u16; 3] = [b'A' as u16, b'U' as u16, b'X' as u16];
    const NUL: [u16; 3] = [b'N' as u16, b'U' as u16, b'L' as u16];
    const CONIN: [u16; 6] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'I' as u16,
        b'N' as u16,
        b'$' as u16,
    ];
    const CONOUT: [u16; 7] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'O' as u16,
        b'U' as u16,
        b'T' as u16,
        b'$' as u16,
    ];

    const COM: [u16; 3] = [b'C' as u16, b'O' as u16, b'M' as u16];
    const LPT: [u16; 3] = [b'L' as u16, b'P' as u16, b'T' as u16];

    const ZERO: u16 = b'0' as u16;
    const NINE: u16 = b'9' as u16;
    const SUPERSCRIPT_ONE: u16 = 0x00B9;
    const SUPERSCRIPT_TWO: u16 = 0x00B2;
    const SUPERSCRIPT_THREE: u16 = 0x00B3;

    fn is_whitespace(c: u16) -> bool {
        c <= 0x7F && ((c as u8).is_ascii_whitespace() || c == 0x000B)
    }

    // In a first pass over the string, obtain the length of the basename.
    let trimmed_len = get_iter()
        .enumerate()
        // We want the base name, so stop at '.' or ':' characters.
        .take_while(|&(_idx, c)| c != b'.' as u16 && c != b':' as u16)
        // We want to trim whitespace from the end, so ignore whitespace chars.
        .filter(|&(_idx, c)| !is_whitespace(c))
        // Get the last non-whitespace char before the first '.'/':' character.
        .last()
        // Convert index of that char into length of string.
        .map(|(idx, _)| idx + 1)
        .unwrap_or(0);

    // If the trimmed base name is longer than 7, it cannot be a reserved name.
    if trimmed_len > 7 {
        return false;
    }

    // At this point, we can store the string in an array, which is more convenient to work with.
    let mut buf = [0u16; 7];
    get_iter()
        .take(trimmed_len)
        .enumerate()
        .for_each(|(i, c)| buf[i] = c);

    for b in &mut buf {
        if *b <= 0x7F {
            *b = (*b as u8).to_ascii_uppercase() as u16;
        }
        if *b == SUPERSCRIPT_ONE {
            *b = b'1' as u16;
        }
        if *b == SUPERSCRIPT_TWO {
            *b = b'2' as u16;
        }
        if *b == SUPERSCRIPT_THREE {
            *b = b'3' as u16;
        }
    }
    let name = &buf[..trimmed_len];

    // Check basic fixed-length strings
    if name == CON || name == PRN || name == AUX || name == NUL || name == CONIN || name == CONOUT {
        return true;
    }

    // COMx / LPTx
    if name.len() == 4 {
        let prefix = &name[..3];
        let suffix = name[3];

        if (prefix == COM || prefix == LPT) && matches!(suffix, ZERO..=NINE) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(path: &str) -> Result<PathBuf, UnsafePathError> {
        sanitize_path(path)
    }

    #[test]
    fn accepts_plain_relative_paths() {
        assert_eq!(clean("a/b/c").unwrap(), PathBuf::from("a/b/c"));
        assert_eq!(clean("foo.txt").unwrap(), PathBuf::from("foo.txt"));
        assert_eq!(
            clean("dir/file.bin").unwrap(),
            PathBuf::from("dir/file.bin")
        );
    }

    #[test]
    fn drops_current_dir_components() {
        assert_eq!(clean("./a/./b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(clean("a/./b/c").unwrap(), PathBuf::from("a/b/c"));
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        for payload in [
            "..",
            "../",
            "../etc/passwd",
            "../../../../etc/passwd",
            "foo/../bar",
            "foo/../../bar",
            "a/b/../../../c",
            "dir/..",
        ] {
            assert_eq!(
                clean(payload),
                Err(UnsafePathError::ParentDir),
                "expected `{payload}` to be rejected as traversal",
            );
        }
    }

    #[test]
    fn preserves_absolute_paths_without_a_root() {
        // Without a configured root, absolute paths are allowed (but never
        // permitted to walk upward via `..`).
        #[cfg(unix)]
        {
            assert_eq!(clean("/etc/hosts").unwrap(), PathBuf::from("/etc/hosts"));
            assert_eq!(
                clean("/var/./www/index.html").unwrap(),
                PathBuf::from("/var/www/index.html"),
            );
            assert_eq!(clean("/a/../b"), Err(UnsafePathError::ParentDir));
        }
    }

    #[test]
    fn rejects_absolute_paths_when_relative_only() {
        #[cfg(unix)]
        {
            assert_eq!(
                sanitize_relative_path("/etc/passwd"),
                Err(UnsafePathError::Absolute),
            );
            assert_eq!(sanitize_relative_path("/"), Err(UnsafePathError::Absolute),);
        }
        assert_eq!(sanitize_relative_path("a/b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(
            sanitize_relative_path("../a"),
            Err(UnsafePathError::ParentDir),
        );
    }

    #[test]
    fn error_converts_to_invalid_input_io_error() {
        let io_err: std::io::Error = UnsafePathError::ParentDir.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
    }

    // -- reserved Windows device names (tested on all platforms) -------------

    fn is_reserved(name: &str) -> bool {
        is_reserved_device_name(name)
    }

    #[test]
    fn detects_reserved_dos_names() {
        for name in [
            "CON", "con", "Con", "PRN", "AUX", "NUL", "nul", "COM1", "COM9", "com1", "LPT1",
            "LPT9", "CONIN$", "CONOUT$", "CON.txt", "NUL.log", "com1.dat", "LPT3.bin", "CON  ",
            "CON.", "CON:",
            // The suffix range is `0..=9`, so `COM0`/`LPT0` are rejected too
            // (conservative — they are not strictly reserved on Windows).
            "COM0", "LPT0",
        ] {
            assert!(is_reserved(name), "expected `{name}` to be reserved");
        }
        // Superscript port numbers resolve to COM1/COM2/COM3.
        assert!(is_reserved("COM\u{00B9}"));
        assert!(is_reserved("COM\u{00B2}"));
        assert!(is_reserved("COM\u{00B3}"));
    }

    #[test]
    fn allows_non_reserved_names() {
        for name in [
            "CONSOLE",
            "COM",
            "COM10",
            "LPT",
            "LPT10",
            "NULL",
            "file.txt",
            "console.log",
            "communication",
            "prnt",
            "auxiliary",
        ] {
            assert!(!is_reserved(name), "expected `{name}` to be allowed");
        }
    }
}
