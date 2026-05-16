use rama_core::error::{BoxError, ErrorContext as _, ErrorExt, extra::OpaqueError};
use rama_utils::str::{NonEmptyStr, arcstr::ArcStr};
use std::{fmt, str::FromStr};

use rama_utils::bytes::ct::ct_eq_bytes;

use crate::user::authority::StaticAuthorizer;

#[derive(Clone, Eq)]
/// Bearer credentials.
pub struct Bearer(NonEmptyStr);

impl PartialEq for Bearer {
    /// Constant-time comparison over the token bytes.
    //
    // Why: bearer tokens are bearer secrets — anyone who can present the
    // string is authenticated. A short-circuiting `==` (the derive) lets an
    // attacker probe the token byte by byte via authentication latency.
    //
    // Regression: `tests::regression_bearer_constant_time_eq`.
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.0.as_bytes(), other.0.as_bytes())
    }
}

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
            if bytes[i] <= 32 || bytes[i] >= 127 || bytes[i] == b',' {
                panic!(
                    "Bearer token contains a forbidden byte (visible ASCII excl. SP and ',' required)"
                );
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
    /// Returns an error in case the token contains a forbidden byte. The
    /// accepted alphabet is the visible ASCII range `0x21..=0x7E` minus the
    /// comma. RFC 6750 defines `b64token` as a much narrower set; we are
    /// graceful by default (custom non-JWT-shaped opaque tokens are common
    /// in the wild) but reject:
    ///
    /// * SP (`0x20`) — would be ambiguous with `Authorization: Bearer <token>`
    ///   header framing and lets a tampered value smuggle an extra scheme.
    /// * `,` — ambiguous with the `#token` list syntax used by other
    ///   authentication-related headers.
    /// * non-visible ASCII (`< 0x21` or `>= 0x7F`) — CR / LF / NUL / DEL are
    ///   never legitimate inside an Authorization header value.
    //
    // Regression: `tests::regression_bearer_rejects_sp_comma_ctl`.
    pub fn try_new(s: NonEmptyStr) -> Result<Self, BoxError> {
        if let Some(idx) = s
            .as_bytes()
            .iter()
            .position(|b| *b <= 32 || *b >= 127 || *b == b',')
        {
            return Err(
                OpaqueError::from_static_str("Bearer token contains forbidden byte")
                    .context_field("byte_index", idx)
                    .into_box_error(),
            );
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
    type Error = BoxError;

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
    type Error = BoxError;

    #[inline(always)]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value.try_into().context("turn string into non-empty str")?)
    }
}

impl TryFrom<ArcStr> for Bearer {
    type Error = BoxError;

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
    type Error = BoxError;

    #[inline(always)]
    fn try_from(value: NonEmptyStr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl FromStr for Bearer {
    type Err = BoxError;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_bearer_constant_time_eq() {
        let a = Bearer::try_from("abcdefghij").unwrap();
        let b = Bearer::try_from("abcdefghij").unwrap();
        let last_diff = Bearer::try_from("abcdefghiX").unwrap();
        let first_diff = Bearer::try_from("Xbcdefghij").unwrap();
        let diff_len = Bearer::try_from("abcdefghi").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, last_diff);
        assert_ne!(a, first_diff);
        assert_ne!(a, diff_len);
    }

    #[test]
    fn regression_bearer_rejects_sp_comma_ctl() {
        // Space — ambiguous with `scheme SP credentials`.
        Bearer::try_from("foo bar").unwrap_err();
        // Comma — ambiguous with `#token` list syntax.
        Bearer::try_from("foo,bar").unwrap_err();
        // Control bytes that have no place in an Authorization header.
        Bearer::try_from("foo\rbar").unwrap_err();
        Bearer::try_from("foo\nbar").unwrap_err();
        Bearer::try_from("foo\0bar").unwrap_err();
        Bearer::try_from("foo\x7fbar").unwrap_err();
        // Realistic JWT-shaped tokens still pass.
        Bearer::try_from("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig").unwrap();
        // Other RFC 6750 b64token characters still pass.
        Bearer::try_from("abc-._~+/==").unwrap();
    }
}
