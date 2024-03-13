use crate::{
    http::{Request, Version},
    service::{context::Extensions, Context},
};
use std::fmt::{self, Debug, Formatter};

/// A filter that matches one or more HTTP methods.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct VersionFilter(u16);

impl VersionFilter {
    /// A filter that matches HTTP/0.9 requests.
    pub const HTTP_09: Self = Self::from_bits(0b0_0000_0010);

    /// A filter that matches HTTP/1.0 requests.
    pub const HTTP_10: Self = Self::from_bits(0b0_0000_0100);

    /// A filter that matches HTTP/1.1 requests.
    pub const HTTP_11: Self = Self::from_bits(0b0_0000_1000);

    /// A filter that matches HTTP/2.0 (h2) requests.
    pub const HTTP_2: Self = Self::from_bits(0b0_0001_0000);

    /// A filter that matches HTTP/3.0 (h3) requests.
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

    /// Performs the OR operation between the [`VersionFilter`] in `self` with `other`.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for VersionFilter {
    /// returns true on a match, false otherwise
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        VersionFilter::try_from(req.version())
            .ok()
            .map(|version| self.contains(version))
            .unwrap_or_default()
    }
}

/// Error type used when converting a [`Version`] to a [`VersionFilter`] fails.
#[derive(Debug)]
pub struct NoMatchingVersionFilter {
    version: Version,
}

impl NoMatchingVersionFilter {
    /// Get the [`Version`] that couldn't be converted to a [`VersionFilter`].
    pub fn version(&self) -> &Version {
        &self.version
    }
}

impl fmt::Display for NoMatchingVersionFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "no `VersionFilter` for `{:?}`", self.version)
    }
}

impl std::error::Error for NoMatchingVersionFilter {}

impl TryFrom<Version> for VersionFilter {
    type Error = NoMatchingVersionFilter;

    fn try_from(m: Version) -> Result<Self, Self::Error> {
        match m {
            Version::HTTP_09 => Ok(VersionFilter::HTTP_09),
            Version::HTTP_10 => Ok(VersionFilter::HTTP_10),
            Version::HTTP_11 => Ok(VersionFilter::HTTP_11),
            Version::HTTP_2 => Ok(VersionFilter::HTTP_2),
            Version::HTTP_3 => Ok(VersionFilter::HTTP_3),
            other => Err(Self::Error { version: other }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::Matcher;

    #[test]
    fn test_version_filter() {
        let filter = VersionFilter::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_version_filter_any() {
        let filter = VersionFilter::HTTP_11
            .or(VersionFilter::HTTP_10)
            .or(VersionFilter::HTTP_11);

        let req = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));

        let req = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));

        let req = Request::builder()
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_version_filter_fail() {
        let filter = VersionFilter::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }
}
