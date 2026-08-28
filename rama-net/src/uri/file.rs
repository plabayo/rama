//! `file:` URI paths, as defined by
//! [RFC 8089](https://datatracker.ietf.org/doc/html/rfc8089).

use std::path::{Path, PathBuf};

use super::{PathRef, Uri};
use crate::address::{AuthorityRef, Domain, Host};

/// Why a `file:` URI does not name a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileUriError {
    /// The uri is not a `file:` uri.
    NotAFileUri,
    /// The uri carries no path at all.
    MissingPath,
    /// A local file URI path must be absolute.
    RelativePath,
    /// A percent-escape in a segment decodes to a path separator, which
    /// would traverse out of the segment it was written in.
    SeparatorInSegment,
    /// A segment contains a NUL byte, which filesystem APIs cannot open.
    NulInSegment,
    /// The authority names a host other than this machine, so the path
    /// lives on that host and not in the local filesystem.
    NonLocalAuthority,
}

impl std::fmt::Display for FileUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFileUri => f.write_str("not a file: uri"),
            Self::MissingPath => f.write_str("file: uri has no path"),
            Self::RelativePath => f.write_str("file: uri path is not absolute"),
            Self::SeparatorInSegment => {
                f.write_str("file: uri path segment decodes to a path separator")
            }
            Self::NulInSegment => f.write_str("file: uri path segment contains a NUL byte"),
            Self::NonLocalAuthority => f.write_str("file: uri authority names a non-local host"),
        }
    }
}

impl std::error::Error for FileUriError {}

/// The filesystem path a `file:` [`Uri`] refers to.
///
/// - `file:///etc/hosts` → `/etc/hosts`
/// - `file://localhost/etc/hosts` → `/etc/hosts`
/// - `file:///C:/Users/x` (windows) → `C:/Users/x`
/// - `file://server/share/x` (windows) → `\\server\share\x`
///
/// Per RFC 8089 §2 only an empty authority or `localhost` names this
/// machine. Any other authority names a *different* host: on windows that
/// is the UNC form of Appendix E.3.2 and maps to `\\host\path`, and
/// everywhere else there is no such path, so it is refused rather than
/// read from the local filesystem.
///
/// Percent-escapes are decoded per segment; a segment that decodes to a
/// path separator is rejected rather than silently traversing. Callers
/// should [`Uri::canonicalize`] first so `.`/`..` are resolved, and open
/// the result through [`rama_utils::fs`] rather than [`std::fs`].
pub fn file_uri_path(uri: &Uri) -> Result<PathBuf, FileUriError> {
    if uri.scheme() != Some(&crate::Protocol::FILE) {
        return Err(FileUriError::NotAFileUri);
    }
    let remote_host = match uri.authority() {
        Some(authority) if !is_local_authority(authority) => Some(unc_host(authority)?),
        _ => None,
    };

    let decoded = decode_path(uri.path().ok_or(FileUriError::MissingPath)?)?;
    if decoded.is_empty() {
        return Err(FileUriError::MissingPath);
    }
    if remote_host.is_none() && !is_absolute_local_path(&decoded) {
        return Err(FileUriError::RelativePath);
    }

    match remote_host {
        Some(host) => Ok(PathBuf::from(format!(
            "\\\\{host}{}",
            to_unc_separators(&decoded)
        ))),
        None => Ok(Path::new(trim_windows_drive_prefix(&decoded)).to_path_buf()),
    }
}

fn is_absolute_local_path(path: &str) -> bool {
    #[cfg(not(windows))]
    {
        path.starts_with('/')
    }
    #[cfg(windows)]
    {
        let bytes = path.as_bytes();
        path.starts_with('/')
            || bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'/' | b'\\')
    }
}

/// The host of a UNC path, or a refusal where UNC paths do not exist.
///
/// Only windows has a filesystem path that names another host; elsewhere
/// reading the local path instead would serve a different file than the one
/// asked for.
fn unc_host(authority: AuthorityRef<'_>) -> Result<String, FileUriError> {
    if cfg!(not(windows)) || authority.userinfo().is_some() || !authority.port().is_unset() {
        return Err(FileUriError::NonLocalAuthority);
    }
    Ok(authority.host().to_string())
}

/// UNC paths are `\\`-separated.
fn to_unc_separators(path: &str) -> String {
    path.replace('/', "\\")
}

/// RFC 8089 §2: the local host is written as an empty authority or as
/// `localhost`. Userinfo and a port have no meaning for a local file, so
/// their presence means the uri was meant for something else.
fn is_local_authority(authority: AuthorityRef<'_>) -> bool {
    if authority.userinfo().is_some() || !authority.port().is_unset() {
        return false;
    }
    let host = authority.host();
    // host equality is canonical, so `LOCALHOST` compares equal too
    host.is_empty() || host == Host::Name(Domain::tld_localhost()).view()
}

/// On windows `file:///C:/x` parses with path `/C:/x`; the leading slash
/// is dropped to get `C:/x`. On unix it IS the absolute-path indicator.
fn trim_windows_drive_prefix(path: &str) -> &str {
    #[cfg(windows)]
    {
        let bytes = path.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[2] == b':'
            && bytes[1].is_ascii_alphabetic()
        {
            return &path[1..];
        }
        path
    }
    #[cfg(not(windows))]
    path
}

fn decode_path(path: PathRef<'_>) -> Result<String, FileUriError> {
    let rooted = path.as_encoded_str().as_ref().starts_with('/');
    let mut decoded = String::new();
    if rooted {
        decoded.push('/');
    }

    for (index, segment) in path.segments().enumerate() {
        let segment = segment.as_decoded_str();
        if segment.contains('/') || cfg!(windows) && segment.contains('\\') {
            return Err(FileUriError::SeparatorInSegment);
        }
        if segment.contains('\0') {
            return Err(FileUriError::NulInSegment);
        }
        if index > 0 {
            decoded.push('/');
        }
        decoded.push_str(&segment);
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(raw: &str) -> Uri {
        raw.parse().unwrap()
    }

    #[test]
    fn decodes_each_segment() {
        assert_eq!(
            file_uri_path(&uri("file:///tmp/a%20b/report.txt")).unwrap(),
            PathBuf::from("/tmp/a b/report.txt"),
        );
    }

    #[test]
    fn rejects_unopenable_bytes_inside_segment() {
        assert_eq!(
            file_uri_path(&uri("file:///tmp/a%2Fb/report.txt")),
            Err(FileUriError::SeparatorInSegment),
        );
        assert_eq!(
            file_uri_path(&uri("file:///tmp/a%00b/report.txt")),
            Err(FileUriError::NulInSegment),
        );
    }

    #[test]
    fn rejects_other_schemes_and_empty_paths() {
        assert_eq!(
            file_uri_path(&uri("http://example.com/x")),
            Err(FileUriError::NotAFileUri),
        );
        assert_eq!(
            file_uri_path(&uri("file://")),
            Err(FileUriError::MissingPath)
        );
        for raw in ["file:relative/path", "file:./pac.js", "file:../pac.js"] {
            assert_eq!(
                file_uri_path(&uri(raw)),
                Err(FileUriError::RelativePath),
                "{raw}",
            );
        }
    }

    #[test]
    fn local_authority_forms_are_accepted() {
        for raw in [
            "file:///etc/hosts",
            "file:/etc/hosts",
            "file://localhost/etc/hosts",
            "file://LOCALHOST/etc/hosts",
        ] {
            assert_eq!(
                file_uri_path(&uri(raw)),
                Ok(PathBuf::from("/etc/hosts")),
                "{raw}"
            );
        }
    }

    #[test]
    fn rejects_an_authority_that_names_no_openable_path() {
        for raw in [
            // neither userinfo nor a port mean anything for a file path,
            // on any platform
            "file://user@localhost/etc/passwd",
            "file://localhost:80/etc/passwd",
            "file://user@fileserver.corp/share/x",
            "file://fileserver.corp:445/share/x",
        ] {
            assert_eq!(
                file_uri_path(&uri(raw)),
                Err(FileUriError::NonLocalAuthority),
                "{raw}"
            );
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn a_remote_authority_is_refused_where_unc_paths_do_not_exist() {
        for raw in [
            // a remote host owns this path, and reading the local one
            // instead would serve a different file than the one asked for
            "file://fileserver.corp/etc/passwd",
            "file://backup-host/share/pac.js",
            // loopback by ip is not one of the two RFC 8089 spellings
            "file://127.0.0.1/etc/passwd",
            // only the `localhost` name itself, not a subdomain of it
            "file://evil.localhost/etc/passwd",
        ] {
            assert_eq!(
                file_uri_path(&uri(raw)),
                Err(FileUriError::NonLocalAuthority),
                "{raw}"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn a_remote_authority_is_the_unc_path_it_spells() {
        // RFC 8089 appendix E.3.2: `file://host/share/x` is `\\host\share\x`
        for (raw, expected) in [
            (
                "file://fileserver.corp/share/pac.js",
                r"\\fileserver.corp\share\pac.js",
            ),
            ("file://server/share", r"\\server\share"),
            // a percent-escape still decodes, and still may not smuggle a
            // separator into a segment
            ("file://server/a%20b/c", r"\\server\a b\c"),
        ] {
            assert_eq!(
                file_uri_path(&uri(raw)),
                Ok(std::path::PathBuf::from(expected)),
                "{raw}"
            );
        }

        assert_eq!(
            file_uri_path(&uri("file://server/a%2Fb")),
            Err(FileUriError::SeparatorInSegment),
        );
    }

    #[test]
    fn dot_segments_are_resolved_by_canonicalize() {
        let path = file_uri_path(&uri("file:///tmp/sub/../pac.js").canonicalize()).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/pac.js"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_letter_loses_its_leading_slash() {
        assert_eq!(
            file_uri_path(&uri("file:///C:/Users/x")).unwrap(),
            PathBuf::from("C:/Users/x"),
        );
    }
}
