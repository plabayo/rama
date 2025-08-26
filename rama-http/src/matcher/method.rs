use crate::{Method, Request};
use rama_core::{Context, context::Extensions};
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

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.bits() & other.bits() == other.bits()
    }

    /// Performs the OR operation between the [`MethodMatcher`] in `self` with `other`.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for MethodMatcher {
    /// returns true on a match, false otherwise
    fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context, req: &Request<Body>) -> bool {
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
