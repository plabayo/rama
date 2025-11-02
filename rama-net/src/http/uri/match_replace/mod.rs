//! Uri match and replace rules.

use std::{borrow::Cow, sync::Arc};

use rama_core::error::OpaqueError;
use rama_http_types::Uri;
use rama_utils::thirdparty::wildcard::Wildcard;
use smallvec::SmallVec;

mod fmt;

mod rule;
pub use rule::UriMatchReplaceRule;

mod rule_set;
pub use rule_set::UriMatchReplaceRuleset;

mod scheme;
pub use scheme::UriMatchReplaceScheme;

mod domain;
pub use domain::UriMatchReplaceDomain;

mod slice;
mod tuple;

mod fallthrough;
pub use fallthrough::UriMatchReplaceFallthrough;

/// A trait for types that can match and optionally replace (rewrite)
/// [`Uri`](rama_http_types::Uri) values.
///
/// # Blanket implementations
///
/// This trait is implemented for common iterable types:
///
/// - `[R; N]` for any array of [`UriMatchReplace`]s of usize `N`;
/// - `&[R]` for any slice of [`UriMatchReplace`]s;
/// - `Vec<R>` for any [`Vec`]] of [`UriMatchReplace`]s;
///
/// It is also implemeneted for tuples size 1 to 12,
/// allowing you to combine multiple [`UriMatchReplace`] types.
///
/// In case you wish a fallthrough behaviour for any supported
/// slice type or tuple you can also wrap it with [`UriMatchReplaceFallthrough`]
/// which will ensure that Uri's go through all rules,
/// preserving the last found match (if any).
///
/// For [`UriMatchReplaceRule`] it is best to use [`UriMatchReplaceRuleset`]
/// in case you wish to use multiple rules, as it is more optimal
/// than the blanket slice implementation.
///
/// For match-replace rules specifically for a scheme or domain-like
/// condition it is better to use [`UriMatchReplaceScheme`] and
/// [`UriMatchReplaceDomain`] respectively over [`UriMatchReplaceRule`]
/// as it also is more optimal and in some ways more powerful as well.
///
/// # Edge cases
///
/// - A rule that matches but produces an invalid URI will be skipped.
/// - When multiple rules could match, **only the first** one in iteration order
///   is applied.
/// - Query parameters are part of the match only when the rule’s pattern or
///   formatter includes `?` (escaped with `\\`) or ends on `*`
///
/// # Contract
///
/// A [`UriMatchReplace`] is expected to preserve the input [`Uri`] as-is
/// when returning [`UriMatchError::NoMatch`]. This error variant
/// is also to be returned for errors unless the original [`Uri`]
/// is no longer present in which case a [`UriMatchError::Unexpected`]
/// error can be returned.
///
/// # Examples
///
/// Apply a single rule:
///
/// ```rust
/// # use std::str::FromStr;
/// # use std::borrow::Cow;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule};
/// let rule = UriMatchReplaceRule::try_new("http://*", "https://$1").unwrap();
///
/// let uri = Uri::from_static("http://example.com/x");
/// let out = rule.match_replace_uri(Cow::Owned(uri)).unwrap();
/// assert_eq!(out.to_string(), "https://example.com/x");
/// ```
///
/// Apply several rules in order, multiple rules even if applicable:
///
/// ```rust
/// # use std::str::FromStr;
/// # use std::borrow::Cow;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule, UriMatchReplaceScheme, UriMatchReplaceFallthrough};
/// let rules = UriMatchReplaceFallthrough((
///     UriMatchReplaceScheme::http_to_https(),
///     UriMatchReplaceRule::try_new("https://*/docs/*", "https://$1/knowledge/$2").unwrap(),
/// ));
///
/// let uri = Uri::from_static("http://example.com/foo/docs/bar");
/// let out = rules.match_replace_uri(Cow::Owned(uri)).unwrap();
/// assert_eq!(out.to_string(), "https://example.com/foo/knowledge/bar");
/// ```
pub trait UriMatchReplace {
    /// Tries to match `uri` against the rule's pattern and, on success,
    /// returns the same Uri or a _new_ **reformatted** `Uri`.
    ///
    /// When the input does not match, or the resulting bytes do not parse as a
    /// valid `Uri`, `None` is returned.
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>>;
}

#[derive(Debug)]
/// Error (including [`NoMatch`]) returned by a [`UriMatchReplace::match_replace_uri`] call.
///
/// [`NoMatch`]: UriMatchError::NoMatch
pub enum UriMatchError<'a> {
    /// No error occurred, but no match was found either.
    ///
    /// The uri should be returned as-is, as it is useful
    /// in case of some kind of set or other chaining position
    /// to give the next matcher a shot at it.
    NoMatch(Cow<'a, Uri>),
    /// An unexpected error occurred and the input
    /// [`Uri`] has been lost in progress.
    Unexpected(OpaqueError),
}

impl std::fmt::Display for UriMatchError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UriMatchError::NoMatch(cow) => write!(f, "uri match error: no match: uri = {cow}"),
            UriMatchError::Unexpected(err) => write!(f, "uri match error: unexpected: {err}"),
        }
    }
}

impl std::error::Error for UriMatchError<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UriMatchError::NoMatch(_) => None,
            UriMatchError::Unexpected(err) => err.source(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// A [`UriMatchReplace`] which never matches.
pub struct UriMatchReplaceNever;

impl UriMatchReplaceNever {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// placeholder
impl UriMatchReplace for UriMatchReplaceNever {
    #[inline]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        Err(UriMatchError::NoMatch(uri))
    }
}

impl<R: UriMatchReplace> UriMatchReplace for &R {
    #[inline(always)]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        (*self).match_replace_uri(uri)
    }
}

impl<R: UriMatchReplace> UriMatchReplace for Arc<R> {
    #[inline(always)]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        (**self).match_replace_uri(uri)
    }
}

impl UriMatchReplace for Arc<dyn UriMatchReplace> {
    #[inline(always)]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        (**self).match_replace_uri(uri)
    }
}

impl UriMatchReplace for Box<dyn UriMatchReplace> {
    #[inline(always)]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        (**self).match_replace_uri(uri)
    }
}

impl<R: UriMatchReplace> UriMatchReplace for Option<R> {
    #[inline]
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        match self {
            Some(r) => r.match_replace_uri(uri),
            None => Err(UriMatchError::NoMatch(uri)),
        }
    }
}

macro_rules! impl_uri_match_replace_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> UriMatchReplace for rama_core::combinators::$id<$($param),+>
        where
            $($param: UriMatchReplace),+,
        {
            fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>,
            ) -> Result<Cow<'a, Uri>, UriMatchError<'a>>  {
                match self {
                    $(
                        rama_core::combinators::$id::$param(r) => r.match_replace_uri(uri),
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_uri_match_replace_either);

/// Private trait used by this module to easily create patterns from
/// owned or static byte-like objects.
#[allow(private_bounds)]
pub trait TryIntoPattern: private_ptn::TryIntoPatternPriv {}

impl TryIntoPattern for &'static str {}
impl TryIntoPattern for String {}
impl TryIntoPattern for &'static [u8] {}
impl TryIntoPattern for Vec<u8> {}

#[derive(Debug)]
/// result of [`TryIntoPattern`].
struct Pattern {
    wildcard: Wildcard<'static>,
    include_query: bool,
}

/// Private trait used by this module to easily create Uri formatters
/// from owned or static byte-like objects.
#[allow(private_bounds)]
pub trait TryIntoUriFmt: private_fmt::TryIntoUriFmtPriv {}

impl TryIntoUriFmt for &'static str {}
impl TryIntoUriFmt for String {}
impl TryIntoUriFmt for &'static [u8] {}
impl TryIntoUriFmt for Vec<u8> {}

mod private_ptn {
    use super::*;
    use rama_core::error::{ErrorContext as _, OpaqueError};
    use rama_utils::{str::submatch_ignore_ascii_case, thirdparty::wildcard::WildcardBuilder};

    pub(super) trait TryIntoPatternPriv {
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError>;
    }

    impl TryIntoPatternPriv for &'static str {
        #[inline(always)]
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError> {
            self.as_bytes().try_into_wildcard()
        }
    }

    impl TryIntoPatternPriv for &'static [u8] {
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError> {
            let wildcard = WildcardBuilder::new(self)
                .case_insensitive(true)
                .build()
                .context("build pattern from static slice")?;
            let include_query = submatch_ignore_ascii_case(self, b"\\?");
            Ok(Pattern {
                wildcard,
                include_query,
            })
        }
    }

    impl TryIntoPatternPriv for String {
        #[inline]
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError> {
            self.into_bytes().try_into_wildcard()
        }
    }

    impl TryIntoPatternPriv for Vec<u8> {
        #[inline]
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError> {
            let wildcard = WildcardBuilder::from_owned(self)
                .case_insensitive(true)
                .build()
                .context("build pattern from heap slice")?;
            let include_query = submatch_ignore_ascii_case(wildcard.pattern(), b"\\?");
            Ok(Pattern {
                wildcard,
                include_query,
            })
        }
    }
}

mod private_fmt {
    use super::*;
    use rama_core::error::OpaqueError;

    pub(super) trait TryIntoUriFmtPriv {
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError>;
    }

    impl TryIntoUriFmtPriv for &'static str {
        #[inline(always)]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            self.as_bytes().try_into_fmt()
        }
    }

    impl TryIntoUriFmtPriv for &'static [u8] {
        #[inline(always)]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            fmt::UriFormatter::try_new(self.into())
        }
    }

    impl TryIntoUriFmtPriv for String {
        #[inline(always)]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            self.into_bytes().try_into_fmt()
        }
    }

    impl TryIntoUriFmtPriv for Vec<u8> {
        #[inline(always)]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            fmt::UriFormatter::try_new(self.into())
        }
    }
}

type SmallUriStr = SmallVec<[u8; 128]>;
