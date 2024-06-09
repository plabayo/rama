use crate::{
    http::{Request, Version},
    service::{context::Extensions, Context},
};
use std::fmt::{self, Debug, Formatter};

/// A matcher that matches one or more HTTP methods.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct VersionMatcher(u16);

impl VersionMatcher {
    /// A matcher that matches HTTP/0.9 requests.
    pub const HTTP_09: Self = Self::from_bits(0b0_0000_0010);

    /// A matcher that matches HTTP/1.0 requests.
    pub const HTTP_10: Self = Self::from_bits(0b0_0000_0100);

    /// A matcher that matches HTTP/1.1 requests.
    pub const HTTP_11: Self = Self::from_bits(0b0_0000_1000);

    /// A matcher that matches HTTP/2.0 (h2) requests.
    pub const HTTP_2: Self = Self::from_bits(0b0_0001_0000);

    /// A matcher that matches HTTP/3.0 (h3) requests.
    pub const HTTP_3: Self = Self::from_bits(0b0_0010_0000);

    const fn bits(&self) -> u16 {
        let bits = self;
        bits.0
    }

    const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub(crate) const fn contains(&self, other: Self) -> bool {
        self.bits() & other.bits() == other.bits()
    }

    /// Performs the OR operation between the [`VersionMatcher`] in `self` with `other`.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for VersionMatcher {
    /// returns true on a match, false otherwise
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        VersionMatcher::try_from(req.version())
            .ok()
            .map(|version| self.contains(version))
            .unwrap_or_default()
    }
}

/// Error type used when converting a [`Version`] to a [`VersionMatcher`] fails.
#[derive(Debug)]
pub struct NoMatchingVersionMatcher {
    version: Version,
}

impl NoMatchingVersionMatcher {
    /// Get the [`Version`] that couldn't be converted to a [`VersionMatcher`].
    pub fn version(&self) -> &Version {
        &self.version
    }
}

impl fmt::Display for NoMatchingVersionMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "no `VersionMatcher` for `{:?}`", self.version)
    }
}

impl std::error::Error for NoMatchingVersionMatcher {}

impl TryFrom<Version> for VersionMatcher {
    type Error = NoMatchingVersionMatcher;

    fn try_from(m: Version) -> Result<Self, Self::Error> {
        match m {
            Version::HTTP_09 => Ok(VersionMatcher::HTTP_09),
            Version::HTTP_10 => Ok(VersionMatcher::HTTP_10),
            Version::HTTP_11 => Ok(VersionMatcher::HTTP_11),
            Version::HTTP_2 => Ok(VersionMatcher::HTTP_2),
            Version::HTTP_3 => Ok(VersionMatcher::HTTP_3),
            other => Err(Self::Error { version: other }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::Matcher;

    #[test]
    fn test_version_matcher() {
        let matcher = VersionMatcher::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_version_matcher_any() {
        let matcher = VersionMatcher::HTTP_11
            .or(VersionMatcher::HTTP_10)
            .or(VersionMatcher::HTTP_11);

        let req = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));

        let req = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));

        let req = Request::builder()
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_version_matcher_fail() {
        let matcher = VersionMatcher::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }
}
