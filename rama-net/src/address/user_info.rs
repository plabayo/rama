//! [`UserInfo`] — the RFC 3986 §3.2.1 userinfo component.
//!
//! `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`.
//!
//! Conventionally `user[:password]` but the grammar allows any
//! pchar-without-`@` byte sequence (and pct-encoded `@`). Stored as
//! raw [`Bytes`] for byte fidelity — convert to typed forms via
//! [`UserInfo::split_user_password`] for the conventional split, or
//! [`UserInfo::to_basic`] for HTTP Basic-Auth interop.

use rama_core::bytes::Bytes;

use crate::user::Basic;
use rama_core::error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError};

/// Raw RFC 3986 userinfo bytes. Cheap to clone (refcount on the
/// underlying [`Bytes`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserInfo {
    bytes: Bytes,
}

impl UserInfo {
    /// Construct from a compile-time string. Zero-allocation.
    #[must_use]
    pub const fn from_static_str(s: &'static str) -> Self {
        Self {
            bytes: Bytes::from_static(s.as_bytes()),
        }
    }

    /// Construct from already-validated bytes (parser invariant: UTF-8,
    /// no `@` or control characters). Skips validation — only callable
    /// from inside the crate.
    #[must_use]
    pub(crate) fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Self { bytes }
    }

    /// Raw on-the-wire bytes (possibly pct-encoded — not decoded here).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `&str` view of the raw bytes. Parser-validated UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Safety: parser only emits UTF-8 (graceful) or ASCII (strict).
        // `from_static_str` is the other constructor and inputs `&str`.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Borrowed view.
    #[must_use]
    pub fn as_ref(&self) -> UserInfoRef<'_> {
        UserInfoRef::new(&self.bytes)
    }

    /// Split on the first `:`. Returns `(user_bytes, password_bytes)`
    /// where the password is `None` if no `:` is present.
    ///
    /// **Bytes are raw — not percent-decoded.** Use
    /// [`crate::uri::util::percent_encoding`] to decode if needed.
    #[must_use]
    pub fn split_user_password(&self) -> (&[u8], Option<&[u8]>) {
        match self.bytes.iter().position(|&b| b == b':') {
            Some(i) => (&self.bytes[..i], Some(&self.bytes[i + 1..])),
            None => (&self.bytes, None),
        }
    }

    /// Convenience: convert this userinfo into a [`Basic`] HTTP
    /// Basic-Auth credential. Fails if the user portion is empty
    /// (`Basic` requires a non-empty username) or if either part is
    /// not valid UTF-8.
    pub fn to_basic(&self) -> Result<Basic, BoxError> {
        Basic::try_from(self.as_str()).context("convert UserInfo to Basic")
    }
}

impl std::fmt::Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UserInfo {
    type Err = BoxError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for UserInfo {
    type Error = BoxError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // Sanity: reject control bytes — `@` and other smuggling-class
        // characters are caught at parse time when used inside a URI.
        // Here we only guard against the obviously-wrong inputs.
        if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7F) {
            return Err(
                OpaqueError::from_static_str("userinfo contains control character")
                    .into_box_error(),
            );
        }
        Ok(Self {
            bytes: Bytes::copy_from_slice(s.as_bytes()),
        })
    }
}

impl TryFrom<String> for UserInfo {
    type Error = BoxError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7F) {
            return Err(
                OpaqueError::from_static_str("userinfo contains control character")
                    .into_box_error(),
            );
        }
        Ok(Self {
            bytes: Bytes::from(s),
        })
    }
}

impl From<Basic> for UserInfo {
    fn from(basic: Basic) -> Self {
        // Format as the canonical `user:password` or `user` string.
        let serialized = match basic.password() {
            Some(p) => format!("{}:{}", basic.username(), p),
            None => basic.username().to_owned(),
        };
        Self {
            bytes: Bytes::from(serialized),
        }
    }
}

/// Borrowed view of a [`UserInfo`]. Carries no ownership of the
/// underlying bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInfoRef<'a> {
    bytes: &'a [u8],
}

impl<'a> UserInfoRef<'a> {
    /// `pub(crate)` constructor — only the parser / accessors should
    /// produce one.
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Raw on-the-wire bytes (possibly pct-encoded).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// `&str` view (parser-validated UTF-8).
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: parser invariant.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Split on the first `:`. Mirrors [`UserInfo::split_user_password`].
    #[must_use]
    pub fn split_user_password(&self) -> (&'a [u8], Option<&'a [u8]>) {
        match self.bytes.iter().position(|&b| b == b':') {
            Some(i) => (&self.bytes[..i], Some(&self.bytes[i + 1..])),
            None => (self.bytes, None),
        }
    }

    /// Construct an owned [`UserInfo`] by copying the bytes.
    #[must_use]
    pub fn to_owned(&self) -> UserInfo {
        UserInfo {
            bytes: Bytes::copy_from_slice(self.bytes),
        }
    }

    /// Convenience: convert to a [`Basic`] HTTP credential.
    /// See [`UserInfo::to_basic`] for the same semantics.
    pub fn to_basic(&self) -> Result<Basic, BoxError> {
        Basic::try_from(self.as_str()).context("convert UserInfoRef to Basic")
    }
}

impl<'a> From<&'a UserInfo> for UserInfoRef<'a> {
    fn from(u: &'a UserInfo) -> Self {
        Self::new(&u.bytes)
    }
}

impl std::fmt::Display for UserInfoRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_static_str() {
        let u = UserInfo::from_static_str("alice");
        assert_eq!(u.as_bytes(), b"alice");
        assert_eq!(u.as_str(), "alice");
    }

    #[test]
    fn split_user_password_user_only() {
        let u = UserInfo::from_static_str("alice");
        assert_eq!(u.split_user_password(), (&b"alice"[..], None));
    }

    #[test]
    fn split_user_password_both() {
        let u = UserInfo::from_static_str("alice:secret");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b"secret"[..]));
    }

    #[test]
    fn split_user_password_empty_user() {
        let u = UserInfo::from_static_str(":secret");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"");
        assert_eq!(pass, Some(&b"secret"[..]));
    }

    #[test]
    fn split_user_password_empty_password() {
        let u = UserInfo::from_static_str("alice:");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b""[..]));
    }

    #[test]
    fn split_user_password_multiple_colons() {
        // RFC 3986 userinfo allows multiple `:`. First `:` is the split.
        let u = UserInfo::from_static_str("alice:p:w");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b"p:w"[..]));
    }

    #[test]
    fn to_basic_user_only() {
        let u = UserInfo::from_static_str("alice");
        let b = u.to_basic().unwrap();
        assert_eq!(b.username(), "alice");
        assert!(b.password().is_none());
    }

    #[test]
    fn to_basic_user_password() {
        let u = UserInfo::from_static_str("alice:secret");
        let b = u.to_basic().unwrap();
        assert_eq!(b.username(), "alice");
        assert_eq!(b.password(), Some("secret"));
    }

    #[test]
    fn to_basic_rejects_empty_user() {
        // `Basic` requires non-empty username.
        let u = UserInfo::from_static_str(":secret");
        u.to_basic().unwrap_err();
    }

    #[test]
    fn try_from_str_rejects_control_chars() {
        UserInfo::try_from("alice\r").unwrap_err();
        UserInfo::try_from("alice\n").unwrap_err();
        UserInfo::try_from("alice\0").unwrap_err();
        UserInfo::try_from("alice\x7F").unwrap_err();
    }

    #[test]
    fn try_from_str_accepts_valid() {
        UserInfo::try_from("alice").unwrap();
        UserInfo::try_from("alice:secret").unwrap();
        UserInfo::try_from("us!er$tag").unwrap();
        UserInfo::try_from("user%40info").unwrap(); // pct-encoded `@`
    }

    #[test]
    fn from_basic_serializes_canonical() {
        use crate::user::credentials::basic;
        let b = basic!("alice", "secret");
        let u = UserInfo::from(b);
        assert_eq!(u.as_str(), "alice:secret");
    }

    #[test]
    fn from_basic_user_only() {
        use rama_utils::str::non_empty_str;
        let b = Basic::new_insecure(non_empty_str!("alice"));
        let u = UserInfo::from(b);
        assert_eq!(u.as_str(), "alice");
    }

    #[test]
    fn ref_split_user_password() {
        let u = UserInfo::from_static_str("alice:secret");
        let r = u.as_ref();
        assert_eq!(
            r.split_user_password(),
            (&b"alice"[..], Some(&b"secret"[..]))
        );
    }

    #[test]
    fn ref_to_owned_roundtrip() {
        let u = UserInfo::from_static_str("alice:secret");
        let r = u.as_ref();
        let owned = r.to_owned();
        assert_eq!(owned, u);
    }
}
