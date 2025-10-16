//! Uri match and replace rules.

use rama_utils::thirdparty::wildcard::Wildcard;

mod fmt;

mod rule;
pub use rule::UriMatchReplaceRule;

mod rule_set;
pub use rule_set::UriMatchReplaceRuleset;

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
