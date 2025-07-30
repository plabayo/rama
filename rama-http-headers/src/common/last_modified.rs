use crate::util::HttpDate;
use std::time::SystemTime;

/// `Last-Modified` header, defined in
/// [RFC7232](https://datatracker.ietf.org/doc/html/rfc7232#section-2.2)
///
/// The `Last-Modified` header field in a response provides a timestamp
/// indicating the date and time at which the origin server believes the
/// selected representation was last modified, as determined at the
/// conclusion of handling the request.
///
/// # ABNF
///
/// ```text
/// Expires = HTTP-date
/// ```
///
/// # Example values
///
/// * `Sat, 29 Oct 1994 19:43:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::LastModified;
/// use std::time::{Duration, SystemTime};
///
/// let modified = LastModified::from(
///     SystemTime::now() - Duration::from_secs(60 * 60 * 24)
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LastModified(pub(super) HttpDate);

derive_header! {
    LastModified(_),
    name: LAST_MODIFIED
}

impl From<SystemTime> for LastModified {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<LastModified> for SystemTime {
    fn from(date: LastModified) -> Self {
        date.0.into()
    }
}
