//! `file://` URI handler — mirrors curl's behavior: read the local
//! file at the URI's path and stream its bytes to stdout.

use rama::{
    error::{BoxError, BoxErrorExt, ErrorContext},
    net::uri::{PathRef, Uri},
};
use std::path::{Path, PathBuf};

/// Read the file referenced by `uri` and write its bytes to stdout.
///
/// Path extraction:
/// - `file:///etc/hosts` → `/etc/hosts`
/// - `file:///C:/Users/x` (Windows) → `C:/Users/x` (leading slash stripped)
///
/// Errors:
/// - Empty path → invalid `file:` URI.
/// - Missing file → `io::ErrorKind::NotFound`, surfaced as
///   `Couldn't open file <path>` (matching curl's exit-37 message).
pub async fn run(uri: &Uri) -> Result<(), BoxError> {
    // Canonicalize first so `.`/`..` segments (incl. percent-encoded ones) are
    // resolved and clamped to root per RFC 3986 before touching the filesystem;
    // `safe_open` is then the defensive backstop against any residual traversal.
    let uri = uri.clone().canonicalize();
    let path = extract_path(&uri)?;

    let mut file = rama::fs::safe_open(&path)
        .await
        .with_context(|| format!("Couldn't open file {}", path.display()))?;

    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut file, &mut stdout)
        .await
        .context("write file:// contents to stdout")?;
    Ok(())
}

fn extract_path(uri: &Uri) -> Result<PathBuf, BoxError> {
    let raw = decode_file_path(uri.path().context("file:// URI has no path")?)?;
    let raw = raw.as_str();

    if raw.is_empty() {
        return Err(BoxError::from_static_str("file:// URI has an empty path"));
    }

    // On Windows, `file:///C:/x` parses with path `/C:/x` — curl
    // strips the leading slash to get `C:/x`. On Unix the leading
    // slash IS the absolute-path indicator, so it stays.
    #[cfg(windows)]
    let trimmed = {
        let bytes = raw.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[2] == b':'
            && bytes[1].is_ascii_alphabetic()
        {
            &raw[1..]
        } else {
            raw
        }
    };
    #[cfg(not(windows))]
    let trimmed = raw;

    Ok(Path::new(trimmed).to_path_buf())
}

fn decode_file_path(path: PathRef<'_>) -> Result<String, BoxError> {
    let encoded = path.as_encoded_str();
    let rooted = encoded.as_ref().starts_with('/');
    let mut decoded = String::new();

    if rooted {
        decoded.push('/');
    }

    for (index, segment) in path.segments().enumerate() {
        let segment = segment.as_decoded_str();
        if segment.contains('/') || cfg!(windows) && segment.contains('\\') {
            return Err(BoxError::from_static_str(
                "file:// URI path segment decodes to a path separator",
            ));
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
    use super::extract_path;

    use rama::net::uri::Uri;

    #[test]
    fn extract_path_decodes_each_segment() {
        let uri: Uri = "file:///tmp/a%20b/report.txt".parse().unwrap();

        assert_eq!(
            extract_path(&uri).unwrap(),
            std::path::PathBuf::from("/tmp/a b/report.txt"),
        );
    }

    #[test]
    fn extract_path_rejects_encoded_separator_inside_segment() {
        let uri: Uri = "file:///tmp/a%2Fb/report.txt".parse().unwrap();

        let _ = extract_path(&uri).unwrap_err();
    }
}
