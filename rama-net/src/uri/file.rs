//! `file:` URI paths, as defined by
//! [RFC 8089](https://datatracker.ietf.org/doc/html/rfc8089).

use std::path::{Path, PathBuf};

use super::{PathRef, Uri};

/// Why a `file:` URI does not name a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileUriError {
    /// The uri is not a `file:` uri.
    NotAFileUri,
    /// The uri carries no path at all.
    MissingPath,
    /// A percent-escape in a segment decodes to a path separator, which
    /// would traverse out of the segment it was written in.
    SeparatorInSegment,
}

impl std::fmt::Display for FileUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFileUri => f.write_str("not a file: uri"),
            Self::MissingPath => f.write_str("file: uri has no path"),
            Self::SeparatorInSegment => {
                f.write_str("file: uri path segment decodes to a path separator")
            }
        }
    }
}

impl std::error::Error for FileUriError {}

/// The filesystem path a `file:` [`Uri`] refers to.
///
/// - `file:///etc/hosts` → `/etc/hosts`
/// - `file:///C:/Users/x` (windows) → `C:/Users/x`
///
/// Percent-escapes are decoded per segment; a segment that decodes to a
/// path separator is rejected rather than silently traversing. Callers
/// should [`Uri::canonicalize`] first so `.`/`..` are resolved, and open
/// the result through [`rama_utils::fs`] rather than [`std::fs`].
pub fn file_uri_path(uri: &Uri) -> Result<PathBuf, FileUriError> {
    if uri.scheme() != Some(&crate::Protocol::FILE) {
        return Err(FileUriError::NotAFileUri);
    }
    let decoded = decode_path(uri.path().ok_or(FileUriError::MissingPath)?)?;
    if decoded.is_empty() {
        return Err(FileUriError::MissingPath);
    }
    Ok(Path::new(trim_windows_drive_prefix(&decoded)).to_path_buf())
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
    fn rejects_encoded_separator_inside_segment() {
        assert_eq!(
            file_uri_path(&uri("file:///tmp/a%2Fb/report.txt")),
            Err(FileUriError::SeparatorInSegment),
        );
    }

    #[test]
    fn rejects_other_schemes_and_empty_paths() {
        assert_eq!(
            file_uri_path(&uri("http://example.com/x")),
            Err(FileUriError::NotAFileUri),
        );
        assert_eq!(
            file_uri_path(&uri("file://host")),
            Err(FileUriError::MissingPath)
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
