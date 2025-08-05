use std::fmt;
use std::time::Duration;

use rama_http_types::HeaderValue;

use crate::Error;
use crate::util::IterExt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seconds(u64);

impl Seconds {
    #[must_use]
    pub fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub fn from_val(val: &HeaderValue) -> Option<Self> {
        let secs = val.to_str().ok()?.parse().ok()?;

        Some(Self::new(secs))
    }

    #[must_use]
    pub fn from_duration(duration: Duration) -> Self {
        Self::new(duration.as_secs())
    }

    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::from_secs(self.0)
    }

    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl super::TryFromValues for Seconds {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .and_then(Self::from_val)
            .ok_or_else(Error::invalid)
    }
}

impl<'a> From<&'a Seconds> for HeaderValue {
    fn from(secs: &'a Seconds) -> Self {
        secs.as_u64().into()
    }
}

impl From<Duration> for Seconds {
    fn from(dur: Duration) -> Self {
        debug_assert!(dur.subsec_nanos() == 0);
        Self::from_duration(dur)
    }
}

impl From<Seconds> for Duration {
    fn from(secs: Seconds) -> Self {
        secs.as_duration()
    }
}

impl From<Seconds> for u64 {
    fn from(secs: Seconds) -> Self {
        secs.as_u64()
    }
}

impl fmt::Debug for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}s", self.as_u64())
    }
}

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.as_u64(), f)
    }
}
