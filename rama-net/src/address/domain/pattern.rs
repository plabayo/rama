use core::{fmt, str::FromStr};

use crate::std::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    string::String,
};

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext};
use rama_utils::thirdparty::wildcard::{Wildcard, WildcardBuilder};

use super::{Domain, DomainLabels, DomainRef};

/// A compiled pattern for matching validated domain names.
///
/// The representation is intentionally private. Construct patterns explicitly
/// with [`exact`][Self::exact], [`sub`][Self::sub], or
/// [`try_glob`][Self::try_glob], or parse conventional pattern syntax through
/// [`try_new`][Self::try_new].
///
/// ```
/// use rama_net::address::{Domain, DomainPattern};
///
/// let pattern = DomainPattern::sub(Domain::from_static("example.com"));
/// assert!(pattern.matches(Domain::from_static("api.example.com").view()));
/// assert!(!pattern.matches(Domain::from_static("example.net").view()));
/// ```
#[derive(Clone)]
pub struct DomainPattern(DomainPatternKind);

#[derive(Clone)]
enum DomainPatternKind {
    Exact(Domain),
    Sub(Domain),
    Glob(Wildcard<'static>),
}

impl DomainPattern {
    /// Match exactly one domain.
    ///
    /// This constructor performs no parsing. A wildcard-valued [`Domain`] is
    /// treated literally; use [`Self::sub`] for subtree semantics.
    #[must_use]
    pub const fn exact(domain: Domain) -> Self {
        Self(DomainPatternKind::Exact(domain))
    }

    /// Match a domain and all of its descendants.
    ///
    /// This constructor performs no parsing. If `domain` is already in Rama's
    /// `*.example.com` wildcard form or its presentation has a leading dot,
    /// the stored subtree apex is normalized to `example.com`.
    #[must_use]
    pub fn sub(domain: Domain) -> Self {
        let apex = domain
            .as_wildcard_parent()
            .or_else(|| domain.strip_leading_dot())
            .unwrap_or(domain);
        Self(DomainPatternKind::Sub(apex))
    }

    /// Compile a case-insensitive domain glob.
    ///
    /// `*` matches any sequence of bytes, including dots. Exact and subtree
    /// matching should use [`Self::exact`] and [`Self::sub`] instead. Domain
    /// globs are restricted to ASCII because wildcard-aware IDNA conversion is
    /// ambiguous; exact and subtree patterns retain the normal [`Domain`] IDNA
    /// behavior. A static string is borrowed by the compiled wildcard; an
    /// owned [`String`] transfers its allocation.
    pub fn try_glob(pattern: impl Into<Cow<'static, str>>) -> Result<Self, BoxError> {
        let pattern = pattern.into();
        validate_domain_glob(&pattern)?;
        Ok(Self(DomainPatternKind::Glob(build_glob(pattern)?)))
    }

    /// Parse a domain pattern.
    ///
    /// Plain domains are exact, `.example.com` and `*.example.com` are subtree
    /// patterns, and other values containing `*` are globs.
    pub fn try_new(pattern: impl TryIntoDomainPattern) -> Result<Self, BoxError> {
        private::TryIntoDomainPatternPriv::try_into_domain_pattern(pattern)
    }

    /// Return whether this pattern matches `domain`.
    #[must_use]
    pub fn matches(&self, domain: DomainRef<'_>) -> bool {
        match &self.0 {
            DomainPatternKind::Exact(expected) => domain == expected.view(),
            DomainPatternKind::Sub(apex) => domain.is_subdomain_of(apex),
            DomainPatternKind::Glob(pattern) => pattern.is_match(domain.as_str().as_bytes()),
        }
    }
}

impl fmt::Debug for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            DomainPatternKind::Exact(domain) => f.debug_tuple("Exact").field(domain).finish(),
            DomainPatternKind::Sub(domain) => f.debug_tuple("Sub").field(domain).finish(),
            DomainPatternKind::Glob(_) => f.write_str("Glob(..)"),
        }
    }
}

impl FromStr for DomainPattern {
    type Err = BoxError;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        let pattern = pattern.trim();
        match Domain::try_from(pattern) {
            Ok(domain) => {
                // DomainPattern gives Rama wildcard domains and conventional
                // leading-dot proxy patterns subtree semantics.
                let kind = match domain
                    .as_wildcard_parent()
                    .or_else(|| domain.strip_leading_dot())
                {
                    Some(apex) => DomainPatternKind::Sub(apex),
                    None => DomainPatternKind::Exact(domain),
                };
                Ok(Self(kind))
            }
            Err(_) if pattern.contains('*') => Self::try_glob(pattern.to_owned()),
            Err(error) => Err(error).context("parse exact domain pattern"),
        }
    }
}

impl TryFrom<String> for DomainPattern {
    type Error = BoxError;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        pattern.parse()
    }
}

impl TryFrom<Box<str>> for DomainPattern {
    type Error = BoxError;

    fn try_from(pattern: Box<str>) -> Result<Self, Self::Error> {
        pattern.parse()
    }
}

fn validate_domain_glob(pattern: &str) -> Result<(), BoxError> {
    if pattern.is_empty() {
        return Err(BoxError::from_static_str("domain glob cannot be empty"));
    }
    if !pattern.is_ascii() {
        return Err(BoxError::from_static_str(
            "domain glob must be ASCII; use an exact or subtree pattern for IDNA names",
        ));
    }
    if !pattern.contains('*') {
        return Err(BoxError::from_static_str(
            "domain glob must contain at least one '*' wildcard",
        ));
    }
    let probe = pattern.replace('*', "a");
    Domain::try_from(probe)
        .map(drop)
        .context("validate domain glob shape")
}

pub(crate) fn build_glob(pattern: Cow<'static, str>) -> Result<Wildcard<'static>, BoxError> {
    let builder = match pattern {
        Cow::Borrowed(pattern) => WildcardBuilder::new(pattern.as_bytes()),
        Cow::Owned(pattern) => WildcardBuilder::from_owned(pattern.into_bytes()),
    };
    builder
        .without_one_metasymbol()
        .without_escape()
        .case_insensitive(true)
        .build()
        .context("compile wildcard pattern")
}

#[expect(private_bounds)]
/// Convert owned or borrowed pattern syntax into a [`DomainPattern`].
///
/// This trait is sealed. It is implemented for [`DomainPattern`], `&str`,
/// [`String`], and `Box<str>`, but deliberately not for [`Domain`]: callers
/// must choose [`DomainPattern::exact`] or [`DomainPattern::sub`].
pub trait TryIntoDomainPattern: private::TryIntoDomainPatternPriv {}

impl TryIntoDomainPattern for DomainPattern {}
impl TryIntoDomainPattern for &str {}
impl TryIntoDomainPattern for String {}
impl TryIntoDomainPattern for Box<str> {}

mod private {
    use super::*;

    pub(super) trait TryIntoDomainPatternPriv {
        fn try_into_domain_pattern(self) -> Result<DomainPattern, BoxError>;
    }

    impl TryIntoDomainPatternPriv for DomainPattern {
        fn try_into_domain_pattern(self) -> Result<DomainPattern, BoxError> {
            Ok(self)
        }
    }

    impl TryIntoDomainPatternPriv for &str {
        fn try_into_domain_pattern(self) -> Result<DomainPattern, BoxError> {
            self.parse()
        }
    }

    impl TryIntoDomainPatternPriv for String {
        fn try_into_domain_pattern(self) -> Result<DomainPattern, BoxError> {
            self.parse()
        }
    }

    impl TryIntoDomainPatternPriv for Box<str> {
        fn try_into_domain_pattern(self) -> Result<DomainPattern, BoxError> {
            self.parse()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_constructors_do_not_parse_or_guess_semantics() {
        let domain = Domain::from_static("example.com");
        assert!(DomainPattern::exact(domain.clone()).matches(domain.view()));
        assert!(
            !DomainPattern::exact(domain.clone())
                .matches(Domain::from_static("api.example.com").view())
        );
        assert!(DomainPattern::sub(domain).matches(Domain::from_static("api.example.com").view()));
    }

    #[test]
    fn parser_distinguishes_exact_subtree_and_glob() {
        let exact = DomainPattern::try_new("example.com").unwrap();
        let wildcard_sub = DomainPattern::try_new("*.example.com").unwrap();
        let leading_dot_sub = DomainPattern::try_new(".example.com").unwrap();
        let glob = DomainPattern::try_new("api-*.example.com").unwrap();
        let wildcard_prefix_glob = DomainPattern::try_new("*.corp*").unwrap();
        let all = DomainPattern::try_new("*").unwrap();

        assert!(exact.matches(Domain::from_static("example.com").view()));
        assert!(!exact.matches(Domain::from_static("api.example.com").view()));
        assert!(wildcard_sub.matches(Domain::from_static("example.com").view()));
        assert!(wildcard_sub.matches(Domain::from_static("deep.api.example.com").view()));
        assert!(leading_dot_sub.matches(Domain::from_static("example.com").view()));
        assert!(leading_dot_sub.matches(Domain::from_static("deep.api.example.com").view()));
        assert!(glob.matches(Domain::from_static("api-one.example.com").view()));
        assert!(!glob.matches(Domain::from_static("www.example.com").view()));
        assert!(wildcard_prefix_glob.matches(Domain::from_static("api.corporate").view()));
        assert!(!wildcard_prefix_glob.matches(Domain::from_static("corp.example").view()));
        assert!(all.matches(Domain::from_static("example.com").view()));
        assert!(all.matches(Domain::from_static("internal").view()));
    }

    #[test]
    fn glob_star_is_not_bounded_by_domain_labels() {
        let pattern = DomainPattern::try_glob("api-*.example.com").unwrap();

        assert!(pattern.matches(Domain::from_static("api-one.example.com").view()));
        assert!(pattern.matches(Domain::from_static("api-one.internal.example.com").view()));
        assert!(!pattern.matches(Domain::from_static("www.example.com").view()));
    }

    #[test]
    fn invalid_non_glob_reports_an_exact_domain_error() {
        let error = DomainPattern::try_new("not a valid domain").unwrap_err();
        assert!(error.to_string().contains("parse exact domain pattern"));
    }

    #[test]
    fn subtree_inputs_store_the_same_normalized_apex() {
        for input in [
            "example.com",
            "*.example.com",
            ".example.com",
            ".*.example.com",
        ] {
            let apex = match DomainPattern::sub(Domain::from_static(input)).0 {
                DomainPatternKind::Sub(apex) => Some(apex),
                DomainPatternKind::Exact(_) | DomainPatternKind::Glob(_) => None,
            }
            .unwrap();
            assert_eq!(apex.as_str(), "example.com", "{input}");
        }
    }

    #[test]
    fn try_into_trait_does_not_reparse_an_existing_pattern() {
        let pattern = DomainPattern::sub(Domain::from_static("example.com"));
        let pattern = DomainPattern::try_new(pattern).unwrap();
        assert!(pattern.matches(Domain::from_static("api.example.com").view()));
    }
}
