use std::time::Duration;

use crate::util::Seconds;

/// `Access-Control-Max-Age` header, as defined on
/// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age).
///
/// The `Access-Control-Max-Age` header indicates how long the results of a
/// preflight request can be cached in a preflight result cache.
///
/// # ABNF
///
/// ```text
/// Access-Control-Max-Age = \"Access-Control-Max-Age\" \":\" delta-seconds
/// ```
///
/// # Example values
///
/// * `531`
///
/// # Examples
///
/// ```
/// use rama_http_headers::AccessControlMaxAge;
///
/// let max_age = AccessControlMaxAge::from_seconds(531);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessControlMaxAge(Seconds);

derive_header! {
    AccessControlMaxAge(_),
    name: ACCESS_CONTROL_MAX_AGE
}

impl AccessControlMaxAge {
    #[must_use]
    #[inline(always)]
    pub fn from_seconds(secs: u64) -> Self {
        Self(Seconds::new(secs))
    }

    #[must_use]
    #[inline(always)]
    pub fn try_from_duration(dur: Duration) -> Option<Self> {
        Seconds::try_from_duration(dur).map(Self)
    }

    #[must_use]
    #[inline(always)]
    pub fn from_duration_rounded(dur: Duration) -> Self {
        Self(Seconds::from_duration_rounded(dur))
    }

    #[must_use]
    pub fn as_secs(self) -> u64 {
        self.0.into()
    }
}

impl From<Seconds> for AccessControlMaxAge {
    fn from(value: Seconds) -> Self {
        Self(value)
    }
}

impl From<AccessControlMaxAge> for Duration {
    fn from(acma: AccessControlMaxAge) -> Self {
        acma.0.into()
    }
}
