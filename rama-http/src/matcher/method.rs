use crate::{Method, Request};
use rama_core::extensions::Extensions;
use std::{
    fmt,
    fmt::{Debug, Formatter},
};

/// A matcher that matches one or more HTTP methods.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MethodMatcher(u16);

impl MethodMatcher {
    /// Match `CONNECT` requests.
    pub const CONNECT: Self = Self::from_bits(0b0_0000_0001);
    /// Match `DELETE` requests.
    pub const DELETE: Self = Self::from_bits(0b0_0000_0010);
    /// Match `GET` requests.
    pub const GET: Self = Self::from_bits(0b0_0000_0100);
    /// Match `HEAD` requests.
    pub const HEAD: Self = Self::from_bits(0b0_0000_1000);
    /// Match `OPTIONS` requests.
    pub const OPTIONS: Self = Self::from_bits(0b0_0001_0000);
    /// Match `PATCH` requests.
    pub const PATCH: Self = Self::from_bits(0b0_0010_0000);
    /// Match `POST` requests.
    pub const POST: Self = Self::from_bits(0b0_0100_0000);
    /// Match `PUT` requests.
    pub const PUT: Self = Self::from_bits(0b0_1000_0000);
    /// Match `TRACE` requests.
    pub const TRACE: Self = Self::from_bits(0b1_0000_0000);

    const fn bits(self) -> u16 {
        let bits = self;
        bits.0
    }

    const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// An empty matcher that matches no methods — the identity element for [`or`].
    pub(crate) const NONE: Self = Self::from_bits(0);
    pub(crate) const ALL_KNOWN: Self = Self::CONNECT
        .or_method(Self::DELETE)
        .or_method(Self::GET)
        .or_method(Self::HEAD)
        .or_method(Self::OPTIONS)
        .or_method(Self::PATCH)
        .or_method(Self::POST)
        .or_method(Self::PUT)
        .or_method(Self::TRACE);

    /// Returns `true` if `self` contains all bits set in `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.bits() & other.bits() == other.bits()
    }

    /// Performs the OR operation between the [`MethodMatcher`] in `self` with `other`.
    #[must_use]
    pub const fn or_method(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Performs the AND operation between the [`MethodMatcher`] in `self` with `other`.
    ///
    /// Useful for intersecting two method sets (e.g. inside an `All` compound matcher).
    #[must_use]
    pub const fn and_method(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns the complement: all known methods NOT in `self`.
    ///
    /// Used when a method matcher is negated — e.g. `NOT GET` → every known method except GET.
    #[must_use]
    pub const fn complement(self) -> Self {
        Self(Self::ALL_KNOWN.bits() & !self.bits())
    }

    /// Returns an iterator over the [`Method`] variants represented by this matcher.
    ///
    /// Yields methods in declaration order (CONNECT, DELETE, GET, HEAD, OPTIONS,
    /// PATCH, POST, PUT, TRACE) for only the bits that are set.
    pub fn iter(self) -> impl Iterator<Item = Method> {
        [
            (Self::CONNECT, Method::CONNECT),
            (Self::DELETE, Method::DELETE),
            (Self::GET, Method::GET),
            (Self::HEAD, Method::HEAD),
            (Self::OPTIONS, Method::OPTIONS),
            (Self::PATCH, Method::PATCH),
            (Self::POST, Method::POST),
            (Self::PUT, Method::PUT),
            (Self::TRACE, Method::TRACE),
        ]
        .into_iter()
        .filter_map(move |(m, method)| self.contains(m).then_some(method))
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for MethodMatcher {
    /// returns true on a match, false otherwise
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        Self::try_from(req.method())
            .ok()
            .map(|method| self.contains(method))
            .unwrap_or_default()
    }
}

/// Error type used when converting a [`Method`] to a [`MethodMatcher`] fails.
#[derive(Debug)]
pub struct NoMatchingMethodMatcher {
    method: Method,
}

impl NoMatchingMethodMatcher {
    /// Get the [`Method`] that couldn't be converted to a [`MethodMatcher`].
    pub fn method(&self) -> &Method {
        &self.method
    }
}

impl fmt::Display for NoMatchingMethodMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "no `MethodMatcher` for `{}`", self.method.as_str())
    }
}

impl std::error::Error for NoMatchingMethodMatcher {}

impl TryFrom<&Method> for MethodMatcher {
    type Error = NoMatchingMethodMatcher;

    fn try_from(m: &Method) -> Result<Self, Self::Error> {
        match m {
            &Method::CONNECT => Ok(Self::CONNECT),
            &Method::DELETE => Ok(Self::DELETE),
            &Method::GET => Ok(Self::GET),
            &Method::HEAD => Ok(Self::HEAD),
            &Method::OPTIONS => Ok(Self::OPTIONS),
            &Method::PATCH => Ok(Self::PATCH),
            &Method::POST => Ok(Self::POST),
            &Method::PUT => Ok(Self::PUT),
            &Method::TRACE => Ok(Self::TRACE),
            other => Err(Self::Error {
                method: other.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_http_method() {
        assert_eq!(
            MethodMatcher::try_from(&Method::CONNECT).unwrap(),
            MethodMatcher::CONNECT
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::DELETE).unwrap(),
            MethodMatcher::DELETE
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::GET).unwrap(),
            MethodMatcher::GET
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::HEAD).unwrap(),
            MethodMatcher::HEAD
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::OPTIONS).unwrap(),
            MethodMatcher::OPTIONS
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::PATCH).unwrap(),
            MethodMatcher::PATCH
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::POST).unwrap(),
            MethodMatcher::POST
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::PUT).unwrap(),
            MethodMatcher::PUT
        );

        assert_eq!(
            MethodMatcher::try_from(&Method::TRACE).unwrap(),
            MethodMatcher::TRACE
        );
    }
}
