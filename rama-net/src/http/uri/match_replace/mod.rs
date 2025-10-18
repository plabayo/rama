//! Uri match and replace rules.

use std::{borrow::Cow, sync::Arc};

use rama_http_types::Uri;
use rama_utils::thirdparty::wildcard::Wildcard;
use smallvec::SmallVec;

mod fmt;

mod rule;
pub use rule::UriMatchReplaceRule;

mod rule_set;

/// A trait for types that can match and optionally replace (rewrite)
/// [`Uri`](rama_http_types::Uri) values.
///
/// # Blanket implementations
///
/// This trait is implemented for several “set-like” container types of
/// [`UriMatchReplaceRule`]:
///
/// - `[UriMatchReplaceRule; N]` (fixed-size array)
/// - `&[UriMatchReplaceRule]` (slice reference)
/// - `Vec<UriMatchReplaceRule>`
/// - `Arc<[UriMatchReplaceRule]>`
///
/// In these cases, the rules are tested **in iteration order**, and the first
/// successful match determines the result.
/// If no rule matches, `None` is returned.
///
/// # Edge cases
///
/// - A rule that matches but produces an invalid URI will be skipped.
/// - When multiple rules could match, **only the first** one in iteration order
///   is applied.
/// - Query parameters are part of the match only when the rule’s pattern or
///   formatter includes `?` (escaped with `\\`) or ends on `*`
///
/// # Examples
///
/// Apply a single rule:
///
/// ```rust
/// # use std::str::FromStr;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule};
/// let rule = UriMatchReplaceRule::try_new("http://*", "https://$1").unwrap();
///
/// let uri: Uri = "http://example.com/x".parse().unwrap();
/// let out = rule.match_replace_uri(&uri).unwrap();
/// assert_eq!(out.to_string(), "https://example.com/x");
/// ```
///
/// Apply several rules in order:
///
/// ```rust
/// # use std::str::FromStr;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule};
/// let rules = [
///     UriMatchReplaceRule::try_new("https://*/docs/*", "https://$1/knowledge/$2").unwrap(),
///     UriMatchReplaceRule::http_to_https(),
/// ];
///
/// let uri: Uri = "http://example.com/abc".parse().unwrap();
/// let out = rules.match_replace_uri(&uri).unwrap();
/// assert_eq!(out.to_string(), "https://example.com/abc");
/// ```
///
/// If no rule matches:
///
/// ```rust
/// # use std::str::FromStr;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule};
/// let rules = [UriMatchReplaceRule::try_new("ftp://*", "https://$1").unwrap()];
/// let uri: Uri = "https://example.com".parse().unwrap();
/// assert!(rules.match_replace_uri(&uri).is_none());
/// ```
pub trait UriMatchReplace {
    /// Tries to match `uri` against the rule's pattern and, on success,
    /// returns the same Uri or a _new_ **reformatted** `Uri`.
    ///
    /// When the input does not match, or the resulting bytes do not parse as a
    /// valid `Uri`, `None` is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// # use rama_http_types::Uri;
    /// # use rama_net::http::uri::{UriMatchReplace, UriMatchReplaceRule};
    /// let rule = UriMatchReplaceRule::try_new(
    ///     "https://*/docs/*",
    ///     "https://$1/knowledge/$2"
    /// ).unwrap();
    ///
    /// let ok: Uri = "https://host/docs/rust".parse().unwrap();
    /// let out = rule.match_replace_uri(&ok).unwrap();
    /// assert_eq!(out.to_string(), "https://host/knowledge/rust");
    ///
    /// let miss: Uri = "https://host/other/x".parse().unwrap();
    /// assert!(rule.match_replace_uri(&miss).is_none());
    /// ```
    fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>>;
}

impl<R: UriMatchReplace> UriMatchReplace for &R {
    fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>> {
        (*self).match_replace_uri(uri)
    }
}

impl<R: UriMatchReplace> UriMatchReplace for Arc<R> {
    fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>> {
        (**self).match_replace_uri(uri)
    }
}

impl<R: UriMatchReplace> UriMatchReplace for Option<R> {
    #[inline]
    fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>> {
        self.as_ref().and_then(|r| r.match_replace_uri(uri))
    }
}

macro_rules! impl_uri_match_replace_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> UriMatchReplace for rama_core::combinators::$id<$($param),+>
        where
            $($param: UriMatchReplace),+,
        {
            fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>> {
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
        #[inline]
        fn try_into_wildcard(self) -> Result<Pattern, OpaqueError> {
            self.as_bytes().try_into_wildcard()
        }
    }

    impl TryIntoPatternPriv for &'static [u8] {
        #[inline]
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
        #[inline]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            self.as_bytes().try_into_fmt()
        }
    }

    impl TryIntoUriFmtPriv for &'static [u8] {
        #[inline]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            fmt::UriFormatter::try_new(self.into())
        }
    }

    impl TryIntoUriFmtPriv for String {
        #[inline]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            self.into_bytes().try_into_fmt()
        }
    }

    impl TryIntoUriFmtPriv for Vec<u8> {
        #[inline]
        fn try_into_fmt(self) -> Result<fmt::UriFormatter, OpaqueError> {
            fmt::UriFormatter::try_new(self.into())
        }
    }
}

type SmallUriStr = SmallVec<[u8; 128]>;
