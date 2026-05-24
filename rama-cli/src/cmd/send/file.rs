//! `file://` URI handler — mirrors curl's behavior: read the local
//! file at the URI's path and stream its bytes to stdout.

use rama::{
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    net::uri::Uri,
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
    let path = extract_path(uri)?;

    let mut file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("Couldn't open file {}", path.display()))?;

    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut file, &mut stdout)
        .await
        .context("write file:// contents to stdout")?;
    Ok(())
}

fn extract_path(uri: &Uri) -> Result<PathBuf, BoxError> {
    let raw = uri.path().context("file:// URI has no path")?.as_raw_str();

    if raw.is_empty() {
        return Err(OpaqueError::from_static_str("file:// URI has an empty path").into_box_error());
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
