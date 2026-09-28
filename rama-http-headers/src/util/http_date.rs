use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::header::HeaderValue;

use super::IterExt;

/// A timestamp with HTTP formatting and parsing
//   Prior to 1995, there were three different formats commonly used by
//   servers to communicate timestamps.  For compatibility with old
//   implementations, all three are defined here.  The preferred format is
//   a fixed-length and single-zone subset of the date and time
//   specification used by the Internet Message Format [RFC5322].
//
//     HTTP-date    = IMF-fixdate / obs-date
//
//   An example of the preferred format is
//
//     Sun, 06 Nov 1994 08:49:37 GMT    ; IMF-fixdate
//
//   Examples of the two obsolete formats are
//
//     Sunday, 06-Nov-94 08:49:37 GMT   ; obsolete RFC 850 format
//     Sun Nov  6 08:49:37 1994         ; ANSI C's asctime() format
//
//   A recipient that parses a timestamp value in an HTTP header field
//   MUST accept all three HTTP-date formats.  When a sender generates a
//   header field that contains one or more timestamps defined as
//   HTTP-date, the sender MUST generate those timestamps in the
//   IMF-fixdate format.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpDate(httpdate::HttpDate);

impl HttpDate {
    pub(crate) fn from_val(val: &HeaderValue) -> Option<Self> {
        val.to_str().ok()?.parse().ok()
    }
}

impl super::TryFromValues for HttpDate {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .and_then(Self::from_val)
            .ok_or_else(crate::Error::invalid)
    }
}

impl TryFrom<HttpDate> for HeaderValue {
    type Error = BoxError;

    fn try_from(date: HttpDate) -> Result<Self, Self::Error> {
        (&date).try_into()
    }
}

impl TryFrom<&HttpDate> for HeaderValue {
    type Error = BoxError;

    fn try_from(date: &HttpDate) -> Result<Self, Self::Error> {
        let s = date.to_string();
        let bytes = Bytes::from(s);
        Self::from_maybe_shared(bytes).context("parse HttpDate as header value")
    }
}

impl FromStr for HttpDate {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, BoxError> {
        Ok(Self(s.parse().context("invalid http date")?))
    }
}

impl fmt::Debug for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// `9999-12-31T23:59:59Z`, the last instant an HTTP-date can represent.
const MAX_HTTP_DATE_SECS: u64 = 253_402_300_799;

impl HttpDate {
    /// `None` for times an HTTP-date cannot represent (before 1970 or after 9999).
    ///
    /// Prefer this over the clamping [`From`] impl for validators such as `Last-Modified`.
    #[must_use]
    pub fn try_from_system_time(sys: SystemTime) -> Option<Self> {
        let since_epoch = sys.duration_since(UNIX_EPOCH).ok()?;
        (since_epoch.as_secs() <= MAX_HTTP_DATE_SECS).then(|| Self(sys.into()))
    }
}

impl From<SystemTime> for HttpDate {
    /// Times outside `1970..=9999` are clamped to the nearest representable date.
    fn from(sys: SystemTime) -> Self {
        let clamped = match sys.duration_since(UNIX_EPOCH) {
            Err(_) => UNIX_EPOCH,
            Ok(since_epoch) if since_epoch.as_secs() > MAX_HTTP_DATE_SECS => UNIX_EPOCH
                .checked_add(Duration::from_secs(MAX_HTTP_DATE_SECS))
                .unwrap_or(UNIX_EPOCH),
            Ok(_) => sys,
        };
        Self(clamped.into())
    }
}

impl From<HttpDate> for SystemTime {
    fn from(date: HttpDate) -> Self {
        Self::from(date.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderValue, HttpDate, SystemTime};

    use std::time::{Duration, UNIX_EPOCH};

    // The old tests had Sunday, but 1994-11-07 is a Monday.
    // See https://github.com/pyfisch/httpdate/pull/6#issuecomment-846881001
    fn nov_07() -> HttpDate {
        HttpDate((UNIX_EPOCH + Duration::new(784198117, 0)).into())
    }

    #[test]
    fn test_display_is_imf_fixdate() {
        assert_eq!("Mon, 07 Nov 1994 08:48:37 GMT", &nov_07().to_string());
    }

    #[test]
    fn test_imf_fixdate() {
        assert_eq!(
            "Mon, 07 Nov 1994 08:48:37 GMT".parse::<HttpDate>().unwrap(),
            nov_07()
        );
    }

    #[test]
    fn test_rfc_850() {
        assert_eq!(
            "Monday, 07-Nov-94 08:48:37 GMT"
                .parse::<HttpDate>()
                .unwrap(),
            nov_07()
        );
    }

    #[test]
    fn test_asctime() {
        assert_eq!(
            "Mon Nov  7 08:48:37 1994".parse::<HttpDate>().unwrap(),
            nov_07()
        );
    }

    #[test]
    fn test_no_date() {
        "this-is-no-date".parse::<HttpDate>().unwrap_err();
    }

    #[test]
    fn test_try_from_system_time_rejects_unrepresentable() {
        let last = UNIX_EPOCH
            .checked_add(Duration::from_secs(253_402_300_799))
            .unwrap();
        assert!(HttpDate::try_from_system_time(UNIX_EPOCH).is_some());
        assert!(HttpDate::try_from_system_time(last).is_some());
        let before_epoch = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        let past_9999 = last.checked_add(Duration::from_secs(1)).unwrap();
        assert!(HttpDate::try_from_system_time(before_epoch).is_none());
        assert!(HttpDate::try_from_system_time(past_9999).is_none());
    }

    #[test]
    fn test_out_of_range_system_time_is_clamped() {
        let before_epoch = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            HttpDate::from(before_epoch).to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );

        for secs in [253_402_300_800, 300_000_000_000] {
            let far_future = UNIX_EPOCH.checked_add(Duration::from_secs(secs)).unwrap();
            let date = HttpDate::from(far_future);
            assert_eq!(date.to_string(), "Fri, 31 Dec 9999 23:59:59 GMT");
            _ = HeaderValue::try_from(date).unwrap();
            _ = SystemTime::from(date);
        }

        let last = UNIX_EPOCH
            .checked_add(Duration::new(253_402_300_799, 999_999_999))
            .unwrap();
        assert_eq!(
            HttpDate::from(last).to_string(),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }

    #[test]
    fn test_parse_extremes() {
        for value in [
            "Fri, 31 Dec 9999 23:59:59 GMT",
            "Thu, 01 Jan 1970 00:00:00 GMT",
        ] {
            let date: HttpDate = value.parse().unwrap();
            assert_eq!(date.to_string(), value);
            _ = SystemTime::from(date);
        }
        for value in [
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Sat, 01 Jan 10000 00:00:00 GMT",
            "Mon, 99 Nov 1994 08:48:37 GMT",
            "Mon, 07 Nov 1994 99:48:37 GMT",
            "Tue, 07 Nov 1994 08:48:37 GMT",
            "Mon Nov  7 08:48:37 99999",
            "Monday, 07-Nov-94 08:48:37 GMT\u{0}",
        ] {
            assert!(value.parse::<HttpDate>().is_err(), "value: {value:?}");
        }
    }
}
