use std::time::SystemTime;

use crate::util::HttpDate;

/// `Date` header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.2)
///
/// The `Date` header field represents the date and time at which the
/// message was originated.
///
/// ## ABNF
///
/// ```text
/// Date = HTTP-date
/// ```
///
/// ## Example values
///
/// * `Tue, 15 Nov 1994 08:12:31 GMT`
///
/// # Example
///
/// ```
/// use rama_http_headers::Date;
/// use std::time::SystemTime;
///
/// let date = Date::from(SystemTime::now());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(HttpDate);

derive_header! {
    Date(_),
    name: DATE
}

impl From<SystemTime> for Date {
    fn from(time: SystemTime) -> Self {
        Self(time.into())
    }
}

impl From<Date> for SystemTime {
    fn from(date: Date) -> Self {
        date.0.into()
    }
}
