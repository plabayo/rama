use crate::headers::ETag;
use std::time::SystemTime;

/// Generate a strong [`ETag`] from file metadata (size + mtime with nanosecond precision).
///
/// Returns `None` for pre-epoch modification times, which are unsupported. The exact format is
/// an implementation detail and may change between versions; clients must treat ETags as opaque
/// values (RFC 9110 §8.8.3).
pub(super) fn etag_from_metadata(size: u64, modified: SystemTime) -> Option<ETag> {
    let duration = modified.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    // NOTE: changing this format busts every client's cache, but is not a semver break since
    // ETags are opaque per RFC 9110 §8.8.3.
    let value = format!(
        "\"{:x}.{:08x}-{:x}\"",
        duration.as_secs(),
        duration.subsec_nanos(),
        size
    );
    value.parse().ok()
}
