use crate::header::HeaderValue;
use httpdate::HttpDate;
use std::time::SystemTime;

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

    /// Convert a header value into a IfModifiedSince, invalid values are silently ignored
    pub(super) fn from_header_value(value: &HeaderValue) -> Option<Self> {
        std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .map(|time| Self(time.into()))
    }
}
