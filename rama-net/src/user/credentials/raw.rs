use rama_core::error::{BoxError, ErrorContext as _, ErrorExt, extra::OpaqueError};
use rama_utils::bytes::ct::ct_eq_bytes;
use rama_utils::str::{NonEmptyStr, arcstr::ArcStr};
use std::{fmt, str::FromStr};

use crate::user::authority::StaticAuthorizer;

/// Raw, scheme-less credentials.
///
/// Unlike [`Bearer`](crate::user::Bearer) — which corresponds to the
/// `Authorization: Bearer <token>` form — this type represents a bare
/// `Authorization: <token>` header. Some real-world APIs and home-grown
/// proxies authenticate with an opaque token directly in the
/// `Authorization` header (or in a request extension) without any
/// scheme prefix. Use [`RawToken`] when you need that.
///
/// The accepted alphabet is intentionally close to what an HTTP
/// `HeaderValue` itself allows: visible ASCII (`0x21..=0x7E`) plus space
/// (`0x20`) and HTAB (`0x09`). CR / LF / NUL / DEL are rejected — they
/// would be invalid header bytes in any case, but we make the check
/// explicit so misuse from other surfaces (request extensions, config
/// files) fails fast.
///
/// Equality is constant-time so this type can be used safely with
/// [`StaticAuthorizer`].
#[derive(Clone, Eq)]
pub struct RawToken(NonEmptyStr);

/// Create a [`RawToken`] at const-compile time.
///
/// # Panics
///
/// Panics if the token literal is empty or contains a forbidden byte.
#[macro_export]
#[doc(hidden)]
macro_rules! __raw_token {
    ($text:expr $(,)?) => {{
        const __RAW_TOKEN_TEXT: &str = $text;
        if __RAW_TOKEN_TEXT.is_empty() {
            panic!("empty str cannot be used as RawToken");
        }

        let mut i = 0;
        let bytes = __RAW_TOKEN_TEXT.as_bytes();
        while i < bytes.len() {
            let b = bytes[i];
            // Visible ASCII + SP + HTAB. Reject CR/LF/NUL/DEL and all
            // other CTLs — never legitimate in a header value.
            if !(b == b'\t' || (b' ' <= b && b <= b'~')) {
                panic!("RawToken contains a forbidden byte (visible ASCII + SP/HTAB required)");
            }
            i += 1;
        }

        // SAFETY: the loop above validated the byte alphabet.
        unsafe {
            $crate::user::credentials::RawToken::new_unchecked(
                $crate::__private::utils::str::non_empty_str!(__RAW_TOKEN_TEXT),
            )
        }
    }};
}

#[doc(inline)]
pub use crate::__raw_token as raw_token;

impl fmt::Debug for RawToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawToken").field(&"***").finish()
    }
}

impl PartialEq for RawToken {
    /// Constant-time comparison over the token bytes.
    //
    // Why: a raw token is a bearer secret. A short-circuiting `==`
    // lets an attacker probe the token byte by byte via authentication
    // latency. Regression: `tests::regression_raw_token_constant_time_eq`.
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl RawToken {
    #[doc(hidden)]
    #[must_use]
    /// Create a new [`RawToken`] without validating the byte alphabet.
    ///
    /// # Safety
    ///
    /// Callee guarantees the given [`NonEmptyStr`] is a valid raw-token
    /// byte sequence (visible ASCII plus SP / HTAB). This is intended
    /// for the `raw_token!` macro to wrap a compile-time validated
    /// literal.
    pub const unsafe fn new_unchecked(s: NonEmptyStr) -> Self {
        Self(s)
    }

    /// Try to create a [`RawToken`] from a [`NonEmptyStr`].
    ///
    /// Returns an error if the token contains a forbidden byte. See the
    /// type-level doc for the accepted alphabet.
    //
    // Regression: `tests::regression_raw_token_rejects_crlf_nul`.
    pub fn try_new(s: NonEmptyStr) -> Result<Self, BoxError> {
        if let Some(idx) = s
            .as_bytes()
            .iter()
            .position(|b| !(*b == b'\t' || (b' '..=b'~').contains(b)))
        {
            return Err(
                OpaqueError::from_static_str("RawToken contains forbidden byte")
                    .context_field("byte_index", idx)
                    .into_box_error(),
            );
        }

        Ok(Self(s))
    }

    /// View the token as a `&str`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.0
    }

    /// Turn itself into a [`StaticAuthorizer`], so it can be used to
    /// authorize.
    #[must_use]
    pub fn into_authorizer(self) -> StaticAuthorizer<Self> {
        StaticAuthorizer::new(self)
    }
}

impl TryFrom<&str> for RawToken {
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

impl TryFrom<String> for RawToken {
    type Error = BoxError;

    #[inline(always)]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value.try_into().context("turn string into non-empty str")?)
    }
}

impl TryFrom<ArcStr> for RawToken {
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

impl TryFrom<NonEmptyStr> for RawToken {
    type Error = BoxError;

    #[inline(always)]
    fn try_from(value: NonEmptyStr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl FromStr for RawToken {
    type Err = BoxError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl fmt::Display for RawToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_raw_token_constant_time_eq() {
        let a = RawToken::try_from("abcdefghij").unwrap();
        let b = RawToken::try_from("abcdefghij").unwrap();
        let last_diff = RawToken::try_from("abcdefghiX").unwrap();
        let first_diff = RawToken::try_from("Xbcdefghij").unwrap();
        let diff_len = RawToken::try_from("abcdefghi").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, last_diff);
        assert_ne!(a, first_diff);
        assert_ne!(a, diff_len);
    }

    #[test]
    fn regression_raw_token_rejects_crlf_nul() {
        // CR / LF / NUL / DEL are never legitimate inside an HTTP
        // header value and would enable CRLF injection if reflected
        // back into one.
        RawToken::try_from("foo\rbar").unwrap_err();
        RawToken::try_from("foo\nbar").unwrap_err();
        RawToken::try_from("foo\0bar").unwrap_err();
        RawToken::try_from("foo\x7fbar").unwrap_err();
        // Looser than Bearer: SP, comma, `:`, `=` are accepted.
        RawToken::try_from("foo bar").unwrap();
        RawToken::try_from("foo,bar").unwrap();
        RawToken::try_from("key=value:scope").unwrap();
        // HTAB allowed (valid HeaderValue byte).
        RawToken::try_from("foo\tbar").unwrap();
        // Realistic shapes still pass.
        RawToken::try_from("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig").unwrap();
    }
}
