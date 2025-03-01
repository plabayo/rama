use http::header::HeaderValue;
use std::fmt::{Display, Formatter};
use std::{
    fmt,
    str::{self, FromStr},
};

/// A value that is both a valid `HeaderValue` and `String`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderValueString {
    /// Care must be taken to only set this value when it is also
    /// a valid `String`, since `as_str` will convert to a `&str`
    /// in an unchecked manner.
    value: HeaderValue,
}

impl HeaderValueString {
    pub(crate) fn as_str(&self) -> &str {
        // HeaderValueString is only created from HeaderValues
        // that have validated they are also UTF-8 strings.
        unsafe { str::from_utf8_unchecked(self.value.as_bytes()) }
    }
}

impl fmt::Debug for HeaderValueString {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl Display for HeaderValueString {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl<'a> From<&'a HeaderValueString> for HeaderValue {
    fn from(src: &'a HeaderValueString) -> HeaderValue {
        src.value.clone()
    }
}

#[derive(Debug)]
pub struct FromStrError(&'static str);

impl FromStr for HeaderValueString {
    type Err = FromStrError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        // A valid `str` (the argument)...
        src.parse()
            .map(|value| HeaderValueString { value })
            .map_err(|_| FromStrError("failed to parse header value from string"))
    }
}

impl Display for FromStrError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl std::error::Error for FromStrError {}
