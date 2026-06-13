use crate::header::HeaderValue;
use crate::headers::ETag;
use httpdate::HttpDate;
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

#[derive(Clone)]
pub(super) struct LastModified(pub(super) HttpDate);

impl From<SystemTime> for LastModified {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

pub(super) struct IfModifiedSince(HttpDate);

impl IfModifiedSince {
    /// Check if the supplied time means the resource has been modified.
    pub(super) fn is_modified(&self, last_modified: &LastModified) -> bool {
        self.0 < last_modified.0
    }

    /// convert a header value into a IfModifiedSince, invalid values are silently ignored
    pub(super) fn from_header_value(value: &HeaderValue) -> Option<Self> {
        std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .map(|time| Self(time.into()))
    }
}

pub(super) struct IfUnmodifiedSince(HttpDate);

impl IfUnmodifiedSince {
    /// Check if the supplied time passes the precondition.
    pub(super) fn precondition_passes(&self, last_modified: &LastModified) -> bool {
        self.0 >= last_modified.0
    }

    /// Convert a header value into an IfUnmodifiedSince, invalid values are silently ignored
    pub(super) fn from_header_value(value: &HeaderValue) -> Option<Self> {
        std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .map(|time| Self(time.into()))
    }
}
