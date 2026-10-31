use std::{
    fmt,
    str::{self, FromStr},
};

use rama_core::bytes::Bytes;
use rama_http_types::header::{HeaderValue, InvalidHeaderValue};

use super::IterExt;
use crate::Error;

/// A value that is both a valid `HeaderValue` and `String`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderValueString {
    // Safety invariant: `value.as_bytes()` is valid UTF-8.
    value: HeaderValue,
}

impl HeaderValueString {
    pub fn from_val(val: &HeaderValue) -> Result<Self, Error> {
        // `to_str` succeeds only for visible ASCII, which is valid UTF-8.
        if val.to_str().is_ok() {
            Ok(Self { value: val.clone() })
        } else {
            Err(Error::invalid())
        }
    }

    #[must_use]
    pub fn from_string(src: String) -> Option<Self> {
        // Keeps the `value` invariant: the bytes come unchanged from a `str`.
        let bytes = Bytes::from(src);
        HeaderValue::from_maybe_shared(bytes)
            .ok()
            .map(|value| Self { value })
    }

    #[must_use]
    pub const fn from_static(src: &'static str) -> Self {
        // Keeps the `value` invariant: the bytes come unchanged from a `str`.
        Self {
            value: HeaderValue::from_static(src),
        }
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: `str::from_utf8_unchecked` requires valid UTF-8, which the
        // `value` safety invariant gives.
        unsafe { str::from_utf8_unchecked(self.value.as_bytes()) }
    }
}

impl fmt::Debug for HeaderValueString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for HeaderValueString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl super::TryFromValues for HeaderValueString {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .map(Self::from_val)
            .unwrap_or_else(|| Err(Error::invalid()))
    }
}

impl<'a> From<&'a HeaderValueString> for HeaderValue {
    fn from(src: &'a HeaderValueString) -> Self {
        src.value.clone()
    }
}

impl FromStr for HeaderValueString {
    type Err = InvalidHeaderValue;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        // Keeps the `value` invariant: the bytes come unchanged from a `str`.
        src.parse().map(|value| Self { value })
    }
}
