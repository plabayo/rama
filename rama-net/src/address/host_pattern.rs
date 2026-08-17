use core::{fmt, str::FromStr};
use std::borrow::Cow;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext};
use rama_utils::thirdparty::wildcard::Wildcard;

use super::{Domain, DomainPattern, Host, HostRef, domain::build_glob};

/// A compiled pattern for matching a [`Host`].
///
/// The representation is intentionally private. Construct patterns explicitly
/// with [`exact`][Self::exact], [`sub`][Self::sub], or
/// [`try_glob`][Self::try_glob], or parse conventional syntax through
/// [`try_new`][Self::try_new].
///
/// ```
/// use rama_net::address::{Domain, Host, HostPattern};
///
/// let pattern = HostPattern::sub(Domain::from_static("example.com"));
/// assert!(pattern.matches(Host::from_static("api.example.com").view()));
/// assert!(!pattern.matches(Host::LOCALHOST_IPV4.view()));
/// ```
#[derive(Clone)]
pub struct HostPattern(HostPatternKind);

#[derive(Clone)]
enum HostPatternKind {
    Exact(Host),
    Domain(DomainPattern),
    Glob(Wildcard<'static>),
}

impl HostPattern {
    /// Match exactly one host.
    ///
    /// This constructor performs no parsing.
    #[must_use]
    pub const fn exact(host: Host) -> Self {
        Self(HostPatternKind::Exact(host))
    }

    /// Match a domain and all of its descendants.
    ///
    /// This constructor performs no parsing.
    #[must_use]
    pub fn sub(domain: Domain) -> Self {
        DomainPattern::sub(domain).into()
    }

    /// Compile a flat case-insensitive host glob.
    ///
    /// `*` matches any sequence of bytes, including dots. Matching is ASCII
    /// case-insensitive against [`HostRef::to_str`], so a glob can match
    /// domain names and IP literals alike. A static string is borrowed by the
    /// compiled wildcard; an owned [`String`] transfers its allocation.
    pub fn try_glob(pattern: impl Into<Cow<'static, str>>) -> Result<Self, BoxError> {
        let pattern = pattern.into();
        if pattern.is_empty() {
            return Err(BoxError::from_static_str("host glob cannot be empty"));
        }
        if !pattern.contains('*') {
            return Err(BoxError::from_static_str(
                "host glob must contain at least one '*' wildcard",
            ));
        }
        Ok(Self(HostPatternKind::Glob(build_glob(pattern)?)))
    }

    /// Parse a host pattern.
    ///
    /// Plain hosts are exact, `.example.com` and `*.example.com` are domain
    /// subtree patterns, and other values containing `*` are flat host globs.
    pub fn try_new(pattern: impl TryIntoHostPattern) -> Result<Self, BoxError> {
        private::TryIntoHostPatternPriv::try_into_host_pattern(pattern)
    }

    /// Return whether this pattern matches `host`.
    #[must_use]
    pub fn matches(&self, host: HostRef<'_>) -> bool {
        match &self.0 {
            HostPatternKind::Exact(expected) => host == expected.view(),
            HostPatternKind::Domain(pattern) => match host {
                HostRef::Name(domain) => pattern.matches(domain),
                HostRef::Uninterpreted(_) => host
                    .try_as_domain()
                    .is_ok_and(|domain| pattern.matches(domain.view())),
                HostRef::Address(_) => false,
            },
            HostPatternKind::Glob(pattern) => pattern.is_match(host.to_str().as_bytes()),
        }
    }
}

impl fmt::Debug for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            HostPatternKind::Exact(host) => f.debug_tuple("Exact").field(host).finish(),
            HostPatternKind::Domain(pattern) => f.debug_tuple("Domain").field(pattern).finish(),
            HostPatternKind::Glob(_) => f.write_str("Glob(..)"),
        }
    }
}

impl FromStr for HostPattern {
    type Err = BoxError;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        let pattern = pattern.trim();
        if pattern.starts_with("*.") || pattern.starts_with('.') {
            return DomainPattern::try_new(pattern).map(Into::into);
        }
        if pattern.contains('*') {
            return Self::try_glob(pattern.to_owned());
        }
        Host::try_from(pattern)
            .map(Self::exact)
            .context("parse exact host pattern")
    }
}

impl TryFrom<String> for HostPattern {
    type Error = BoxError;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        pattern.parse()
    }
}

impl TryFrom<Box<str>> for HostPattern {
    type Error = BoxError;

    fn try_from(pattern: Box<str>) -> Result<Self, Self::Error> {
        pattern.parse()
    }
}

/// Preserve a domain pattern's exact, subtree, or glob semantics while
/// widening its candidate type to [`Host`].
impl From<DomainPattern> for HostPattern {
    fn from(pattern: DomainPattern) -> Self {
        Self(HostPatternKind::Domain(pattern))
    }
}

impl TryFrom<HostPattern> for DomainPattern {
    type Error = BoxError;

    fn try_from(pattern: HostPattern) -> Result<Self, Self::Error> {
        match pattern.0 {
            HostPatternKind::Exact(host) => host
                .try_into_domain()
                .map(Self::exact)
                .context("exact host pattern is not a domain"),
            HostPatternKind::Domain(pattern) => Ok(pattern),
            HostPatternKind::Glob(_) => Err(BoxError::from_static_str(
                "a flat host glob cannot be narrowed to a domain pattern",
            )),
        }
    }
}

#[expect(private_bounds)]
/// Convert owned or borrowed pattern syntax into a [`HostPattern`].
///
/// This trait is sealed. It is implemented for [`HostPattern`],
/// [`DomainPattern`], `&str`, [`String`], and `Box<str>`, but deliberately not
/// for [`Host`] or [`Domain`]: callers must choose exact or subtree semantics.
pub trait TryIntoHostPattern: private::TryIntoHostPatternPriv {}

impl TryIntoHostPattern for HostPattern {}
impl TryIntoHostPattern for DomainPattern {}
impl TryIntoHostPattern for &str {}
impl TryIntoHostPattern for String {}
impl TryIntoHostPattern for Box<str> {}

mod private {
    use super::*;

    pub(super) trait TryIntoHostPatternPriv {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError>;
    }

    impl TryIntoHostPatternPriv for HostPattern {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError> {
            Ok(self)
        }
    }

    impl TryIntoHostPatternPriv for DomainPattern {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError> {
            Ok(self.into())
        }
    }

    impl TryIntoHostPatternPriv for &str {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError> {
            self.parse()
        }
    }

    impl TryIntoHostPatternPriv for String {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError> {
            self.parse()
        }
    }

    impl TryIntoHostPatternPriv for Box<str> {
        fn try_into_host_pattern(self) -> Result<HostPattern, BoxError> {
            self.parse()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_constructors_do_not_parse_or_guess_semantics() {
        let exact = HostPattern::exact(Host::from(Domain::from_static("example.com")));
        assert!(exact.matches(Host::from(Domain::from_static("example.com")).view()));
        assert!(!exact.matches(Host::from(Domain::from_static("api.example.com")).view()));

        let sub = HostPattern::sub(Domain::from_static("example.com"));
        assert!(sub.matches(Host::from(Domain::from_static("api.example.com")).view()));
    }

    #[test]
    fn parser_supports_exact_subtree_and_flat_glob_patterns() {
        let exact = HostPattern::try_new("127.0.0.1").unwrap();
        let sub = HostPattern::try_new("*.example.com").unwrap();
        let glob = HostPattern::try_new("192.168.*").unwrap();

        assert!(exact.matches(Host::try_from("127.0.0.1").unwrap().view()));
        assert!(sub.matches(Host::try_from("deep.api.example.com").unwrap().view()));
        assert!(glob.matches(Host::try_from("192.168.10.20").unwrap().view()));
    }

    #[test]
    fn explicit_glob_matches_the_host_text() {
        let pattern = HostPattern::try_glob("api-*.example.com").unwrap();
        assert!(pattern.matches(Host::try_from("api-one.example.com").unwrap().view()));
    }

    #[test]
    fn domain_conversion_is_intentionally_asymmetric() {
        let domain = DomainPattern::sub(Domain::from_static("example.com"));
        let host = HostPattern::from(domain);
        let domain = DomainPattern::try_from(host).unwrap();
        assert!(domain.matches(Domain::from_static("api.example.com").view()));

        let ip = HostPattern::exact(Host::try_from("127.0.0.1").unwrap());
        DomainPattern::try_from(ip).unwrap_err();

        let glob = HostPattern::try_glob("api-*.example.com").unwrap();
        DomainPattern::try_from(glob).unwrap_err();
    }

    #[test]
    fn try_into_trait_preserves_existing_pattern_semantics() {
        let domain = DomainPattern::sub(Domain::from_static("example.com"));
        let host = HostPattern::try_new(domain).unwrap();
        let domain = DomainPattern::try_from(host).unwrap();
        assert!(domain.matches(Domain::from_static("api.example.com").view()));
    }
}
