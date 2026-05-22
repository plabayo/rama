//! [`UserInfo`] — the RFC 3986 §3.2.1 userinfo component.
//!
//! `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`.
//!
//! Conventionally `user[:password]` but the grammar allows any
//! pchar-without-`@` byte sequence (and pct-encoded `@`). The raw on-wire
//! bytes are preserved verbatim; convert to typed forms via
//! [`UserInfo::split_user_password`] for the conventional split or
//! [`UserInfo::to_basic`] for HTTP Basic-Auth interop.

use rama_core::bytes::Bytes;

use crate::user::Basic;
use rama_core::error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError};

/// Raw RFC 3986 userinfo bytes. Cheap to clone.
///
/// # Logging safety
///
/// The [`Debug`](std::fmt::Debug) impl redacts the password portion (anything
/// after the first `:`) as `"***"`, matching [`Basic`]'s logging behaviour.
/// This is the safe default for tracing spans and log lines, where a raw
/// `Debug`-print of a [`Uri`](crate::uri::Uri) would otherwise leak
/// credentials into observability sinks. The user portion is rendered raw;
/// pct-encoded bytes are not decoded for the Debug view.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UserInfo {
    bytes: Bytes,
}

impl UserInfo {
    /// Construct from a compile-time string. Zero-allocation.
    ///
    /// **Panics at compile time** if `s` contains a byte outside the
    /// RFC 3986 §3.2.1 userinfo grammar (`unreserved / pct-encoded /
    /// sub-delims / ":"`). This matches the URI parser's strict-mode
    /// validation: byte sets stay single-sourced, and typed construction
    /// can never produce a `UserInfo` that the parser would reject.
    #[must_use]
    pub const fn from_static_str(s: &'static str) -> Self {
        validate_userinfo_static(s.as_bytes());
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

    /// Validate `s` against the RFC 3986 §3.2.1 userinfo grammar —
    /// same byte set the URI parser uses in strict mode. Rejects:
    ///
    /// - Control bytes anywhere.
    /// - Raw `@` (must be percent-encoded as `%40`).
    /// - Raw space, brackets, gen-delims, and other non-userinfo bytes.
    /// - Malformed pct-escapes (`%X` truncated, `%XY` non-hex).
    /// - Pct-decoded control bytes (smuggling vector).
    ///
    /// Without this guard, `Uri::set_authority(authority_with_loose_userinfo)`
    /// could embed bytes the parser would otherwise reject — producing
    /// URIs that round-trip into malformed wire form.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        validate_userinfo_runtime(s.as_bytes())?;
        Ok(Self {
            bytes: Bytes::copy_from_slice(s.as_bytes()),
        })
    }
}

impl TryFrom<String> for UserInfo {
    type Error = BoxError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate_userinfo_runtime(s.as_bytes())?;
        Ok(Self {
            bytes: Bytes::from(s),
        })
    }
}

/// Runtime userinfo-grammar validator, shared by `TryFrom<&str>` and
/// `TryFrom<String>`. Delegates the byte-set check to
/// [`crate::byte_sets::is_userinfo_byte`] so the grammar is single-sourced.
///
/// Rules (RFC 3986 §3.2.1):
/// - Each byte must be `unreserved / pct-encoded / sub-delims / ":"`.
/// - `%XX` must be a well-formed hex pair.
/// - Pct-decoded byte must not be a control character (smuggling
///   defense — mirrors the URI parser's reg-name handling).
fn validate_userinfo_runtime(bytes: &[u8]) -> Result<(), BoxError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == 0x7F {
            return Err(
                OpaqueError::from_static_str("userinfo contains control character")
                    .into_box_error(),
            );
        }
        if b == b'%' {
            let h1 = bytes.get(i + 1).copied();
            let h2 = bytes.get(i + 2).copied();
            match (h1, h2) {
                (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                    if let Some(decoded) = rama_utils::hex::decode_pair(a, b)
                        && (decoded < 0x20 || decoded == 0x7F)
                    {
                        return Err(OpaqueError::from_static_str(
                            "userinfo pct-escape decodes to a control character",
                        )
                        .into_box_error());
                    }
                    i += 3;
                    continue;
                }
                _ => {
                    return Err(OpaqueError::from_static_str(
                        "userinfo contains malformed percent-escape",
                    )
                    .into_box_error());
                }
            }
        }
        if !crate::byte_sets::is_userinfo_byte(b) {
            return Err(
                OpaqueError::from_static_str("userinfo contains disallowed character")
                    .into_box_error(),
            );
        }
        i += 1;
    }
    Ok(())
}

/// `const` mirror of [`validate_userinfo_runtime`] for
/// [`UserInfo::from_static_str`]. Same rules; panics at compile time
/// on violation. Can't share the `?`-based runtime variant because `?`
/// isn't const-stable yet.
const fn validate_userinfo_static(bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(
            b >= 0x20 && b != 0x7F,
            "UserInfo::from_static_str: control character in input"
        );
        if b == b'%' {
            assert!(
                i + 2 < bytes.len(),
                "UserInfo::from_static_str: truncated percent-escape"
            );
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            assert!(
                h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit(),
                "UserInfo::from_static_str: malformed percent-escape"
            );
            // Shared hex helper — `decode_pair` is const-stable. Both
            // h1 and h2 just passed `is_ascii_hexdigit` so the `Some`
            // arm always fires; `unreachable_unchecked` lets the
            // compiler drop the dead `None` branch.
            let Some(decoded) = rama_utils::hex::decode_pair(h1, h2) else {
                // SAFETY: both hex digits are ASCII hex per the
                // assertion above; decode_pair always succeeds.
                unsafe { std::hint::unreachable_unchecked() }
            };
            assert!(
                decoded >= 0x20 && decoded != 0x7F,
                "UserInfo::from_static_str: pct-escape decodes to a control character"
            );
            i += 3;
            continue;
        }
        assert!(
            crate::byte_sets::is_userinfo_byte(b),
            "UserInfo::from_static_str: disallowed character"
        );
        i += 1;
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
///
/// `Debug` follows [`UserInfo`]'s redacting policy (password portion
/// rendered as `"***"`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

// ---- Redacting Debug ------------------------------------------------------
//
// Userinfo carries credentials by convention (`user:password`). A raw
// `Debug` print would leak the password into any tracing span, panic
// message, or `assert!`/`dbg!` line that touches a `Uri`. Mirror what
// [`Basic`]'s Debug impl does: username verbatim, password as `"***"`.
//
// Shared `fmt_redacted` helper drives both the owned and borrowed views;
// the borrowed view's impl is the canonical site and the owned one
// delegates through `UserInfoRef::from(self)`.

fn fmt_redacted(bytes: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // SAFETY: parser/static-validator invariant: UserInfo bytes are valid
    // UTF-8 (graceful preserves UTF-8; strict is ASCII-only; the
    // const validator at `from_static_str` rejects non-UTF-8 byte
    // sequences via its byte-class check, which is ASCII).
    let s = unsafe { std::str::from_utf8_unchecked(bytes) };
    let (user, password) = match bytes.iter().position(|&b| b == b':') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut dbg = f.debug_struct("UserInfo");
    dbg.field("user", &user);
    // Render the password field as the literal `"***"` regardless of
    // whether it's empty — its mere presence is the credential signal
    // we want to surface in logs.
    if password.is_some() {
        dbg.field("password", &"***");
    }
    dbg.finish()
}

impl std::fmt::Debug for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_redacted(&self.bytes, f)
    }
}

impl std::fmt::Debug for UserInfoRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_redacted(self.bytes, f)
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

    // -- Debug redaction (audit H3) -------------------------------------

    #[test]
    fn debug_redacts_password() {
        let u = UserInfo::from_static_str("alice:secret");
        let s = format!("{u:?}");
        assert!(!s.contains("secret"), "debug leaked password: {s}");
        assert!(s.contains("alice"), "debug missing user: {s}");
        assert!(s.contains("***"), "debug missing redaction marker: {s}");
    }

    #[test]
    fn debug_omits_password_field_when_absent() {
        // No `:` → no credential → no `password` field at all.
        let u = UserInfo::from_static_str("alice");
        let s = format!("{u:?}");
        assert!(s.contains("alice"));
        assert!(
            !s.contains("***"),
            "debug shouldn't show *** for plain user"
        );
        assert!(!s.contains("password"), "debug shouldn't mention password");
    }

    #[test]
    fn debug_redacts_empty_password() {
        // Empty password is still a credential signal.
        let u = UserInfo::from_static_str("alice:");
        let s = format!("{u:?}");
        assert!(s.contains("alice"));
        assert!(s.contains("***"), "debug must redact even empty password");
    }

    #[test]
    fn debug_redacts_multiple_colon_password() {
        // RFC 3986 allows extra `:` in the password portion. Redaction
        // covers everything after the first `:`.
        let u = UserInfo::from_static_str("alice:secret:more");
        let s = format!("{u:?}");
        assert!(!s.contains("secret"), "debug leaked password: {s}");
        assert!(!s.contains("more"), "debug leaked password tail: {s}");
    }

    #[test]
    fn ref_debug_matches_owned_redaction() {
        // The borrowed view uses the same redacting helper as the owned
        // type so logging through either path is safe.
        let u = UserInfo::from_static_str("alice:secret");
        let r: UserInfoRef<'_> = (&u).into();
        let owned_dbg = format!("{u:?}");
        let ref_dbg = format!("{r:?}");
        assert_eq!(owned_dbg, ref_dbg);
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

    /// Regression: previously `try_from` only rejected control bytes,
    /// so `UserInfo::try_from("a b@c")` succeeded and
    /// `Uri::set_authority(...)` then rendered `//a b@c@host/` — a
    /// malformed wire URI the parser would never accept. Tightened
    /// validation now matches the URI parser's strict-mode userinfo
    /// byte set.
    #[test]
    fn try_from_str_rejects_raw_at_sign() {
        // Raw `@` is the userinfo terminator and MUST be pct-encoded
        // (`%40`) per RFC 3986 §3.2.1.
        UserInfo::try_from("alice@example.com").unwrap_err();
        UserInfo::try_from("a@b@c").unwrap_err();
    }

    #[test]
    fn try_from_str_rejects_raw_space() {
        UserInfo::try_from("a b").unwrap_err();
        UserInfo::try_from("alice secret").unwrap_err();
    }

    #[test]
    fn try_from_str_rejects_gen_delims() {
        // gen-delims (other than `:` and `@`, which have specific roles)
        // aren't valid in userinfo.
        UserInfo::try_from("user/path").unwrap_err();
        UserInfo::try_from("user?query").unwrap_err();
        UserInfo::try_from("user#frag").unwrap_err();
        UserInfo::try_from("user[bracket").unwrap_err();
    }

    #[test]
    fn try_from_str_rejects_malformed_pct() {
        UserInfo::try_from("user%4").unwrap_err(); // truncated
        UserInfo::try_from("user%4Z").unwrap_err(); // non-hex
        UserInfo::try_from("user%").unwrap_err(); // bare %
    }

    #[test]
    fn try_from_str_rejects_pct_decoded_control_byte() {
        // Smuggling defense: `%00` (NUL), `%0D` (CR), `%0A` (LF), etc.
        // Even though the wire bytes are printable, the decoded byte
        // would be a control character — same protection the URI
        // parser applies to reg-name pct-escapes.
        UserInfo::try_from("user%00").unwrap_err();
        UserInfo::try_from("user%0D").unwrap_err();
        UserInfo::try_from("user%0A").unwrap_err();
        UserInfo::try_from("user%09").unwrap_err();
        UserInfo::try_from("user%7F").unwrap_err();
    }

    #[test]
    fn from_static_str_panics_on_invalid_input() {
        // `from_static_str` is a const fn that validates at compile
        // time. Use `catch_unwind` to verify the runtime panic message
        // for cases that would-be compile errors in actual usage.
        let bad_inputs = [
            "alice@host", // raw @
            "alice bob",  // raw space
            "user%4",     // truncated pct
            "user%00",    // pct-decoded NUL
        ];
        for input in bad_inputs {
            let result = std::panic::catch_unwind(|| {
                UserInfo::from_static_str(unsafe {
                    // Safety: the leaked `&'static str` is only used
                    // inside `catch_unwind`; we never escape it.
                    std::mem::transmute::<&str, &'static str>(input)
                })
            });
            assert!(result.is_err(), "expected panic for {input:?}");
        }
    }

    #[test]
    fn from_static_str_accepts_valid_inputs() {
        let _u = UserInfo::from_static_str("alice");
        let _u = UserInfo::from_static_str("alice:secret");
        let _u = UserInfo::from_static_str("user%40info"); // pct-encoded @
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
