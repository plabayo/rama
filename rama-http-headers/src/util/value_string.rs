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
    /// Care must be taken to only set this value when it is also
    /// a valid `String`, since `as_str` will convert to a `&str`
    /// in an unchecked manner.
    value: HeaderValue,
}

impl HeaderValueString {
    pub fn from_val(val: &HeaderValue) -> Result<Self, Error> {
        if val.to_str().is_ok() {
            Ok(Self { value: val.clone() })
        } else {
            Err(Error::invalid())
        }
    }

    #[must_use]
    pub fn from_string(src: String) -> Option<Self> {
        // A valid `str` (the argument)...
        let bytes = Bytes::from(src);
        HeaderValue::from_maybe_shared(bytes)
            .ok()
            .map(|value| Self { value })
    }

    #[must_use]
    pub const fn from_static(src: &'static str) -> Self {
        // A valid `str` (the argument)...
        Self {
            value: HeaderValue::from_static(src),
        }
    }

    pub fn as_str(&self) -> &str {
        // HeaderValueString is only created from HeaderValues
        // that have validated they are also UTF-8 strings.
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
        // A valid `str` (the argument)...
        src.parse().map(|value| Self { value })
    }
}
