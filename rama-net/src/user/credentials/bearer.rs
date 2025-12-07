use rama_core::error::{ErrorContext as _, OpaqueError};
use rama_utils::str::{NonEmptyStr, arcstr::ArcStr};
use std::{fmt, str::FromStr};

use crate::user::authority::StaticAuthorizer;

#[derive(Clone, PartialEq, Eq)]
/// Bearer credentials.
pub struct Bearer(NonEmptyStr);

/// Create a [`Bearer`] value at const-compile time.
///
/// Panics in case it is an invalid token
#[macro_export]
#[doc(hidden)]
macro_rules! __bearer {
    ($text:expr $(,)?) => {{
        const __BEARER_TEXT: &str = $text;
        if __BEARER_TEXT.is_empty() {
            panic!("empty str cannot be used as Bearer");
        }

        let mut i = 0;
        let bytes = __BEARER_TEXT.as_bytes();
        while i < bytes.len() {
            if bytes[i] < 32 || bytes[i] >= 127 {
                panic!("string contains non visible ASCII characters");
            }
            i += 1;
        }

        // SAFETY: the above algorithm guarantees bearer is valid
        unsafe {
            $crate::user::credentials::Bearer::new_unchecked(
                $crate::__private::utils::str::non_empty_str!(__BEARER_TEXT),
            )
        }
    }};
}

#[doc(inline)]
pub use crate::__bearer as bearer;

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bearer").field(&"***").finish()
    }
}

impl Bearer {
    #[doc(hidden)]
    #[must_use]
    /// Create a new [`Bearer`] token without validating if token is valid.
    ///
    /// # Safety
    ///
    /// Callee guarantees the given NonEmptyStr is a valid Bearer token.
    /// This can be useful in case you create the bearer token from
    /// a pre-validated non-empty str (e.g. in a macro at compile time).
    pub const unsafe fn new_unchecked(s: NonEmptyStr) -> Self {
        Self(s)
    }

    /// Try to create a [`Bearer`] from a [`NonEmptyStr`].
    ///
    /// Returns an error in case the token contains non-visible ASCII chars.
    pub fn try_new(s: NonEmptyStr) -> Result<Self, OpaqueError> {
        if s.as_bytes().iter().any(|b| *b < 32 || *b >= 127) {
            return Err(OpaqueError::from_display(
                "string contains non visible ASCII characters",
            ));
        }

        Ok(Self(s))
    }

    /// View the token part as a `&str`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.0
    }

    /// Turn itself into a [`StaticAuthorizer`], so it can be used to authorize.
    ///
    /// Just a shortcut, QoL.
    #[must_use]
    pub fn into_authorizer(self) -> StaticAuthorizer<Self> {
        StaticAuthorizer::new(self)
    }
}

impl TryFrom<&str> for Bearer {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(
            value
                .try_into()
                .context("turn str slice into non-empty str")?,
        )
    }
}

impl TryFrom<String> for Bearer {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value.try_into().context("turn string into non-empty str")?)
    }
}

impl TryFrom<ArcStr> for Bearer {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: ArcStr) -> Result<Self, Self::Error> {
        Self::try_new(
            value
                .try_into()
                .context("turn arc str into non-empty str")?,
        )
    }
}

impl TryFrom<NonEmptyStr> for Bearer {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: NonEmptyStr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl FromStr for Bearer {
    type Err = OpaqueError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl fmt::Display for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
