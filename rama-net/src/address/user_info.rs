//! [`UserInfo`] — the RFC 3986 §3.2.1 userinfo component.
//!
//! `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`.
//!
//! Conventionally `user[:password]` but the grammar allows any
//! pchar-without-`@` byte sequence (and pct-encoded `@`). The raw on-wire
//! bytes are preserved verbatim; read the percent-decoded logical view
//! via [`UserInfo::as_decoded_str`] / [`UserInfo::username_decoded`] /
//! [`UserInfo::password_decoded`], split on the raw `:` via
//! [`UserInfo::split_user_password`], or cross into HTTP Basic-Auth (which
//! decodes + validates) via [`UserInfo::to_basic`]. The reverse —
//! [`From<Basic>`](UserInfo) — percent-encodes back into wire form.

use crate::std::{borrow::Cow, string::String};

use crate::user::Basic;

use rama_core::bytes::Bytes;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext};
use rama_utils::str::NonEmptyStr;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode, utf8_percent_encode};

/// Bytes percent-encoded inside a userinfo **password** component when
/// serializing a [`Basic`] back to wire form. Pass-through mirrors the
/// allow-set in [`crate::byte_sets`] (`unreserved / sub-delims / ":"`);
/// `%` is encoded so raw content round-trips (a literal `%` → `%25`).
const USERINFO_PASSWORD_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Same as [`USERINFO_PASSWORD_ENCODE_SET`] but also escapes `:`, so a `:`
/// inside a username can't be mistaken for the user/password separator on
/// the way back in.
const USERINFO_USERNAME_ENCODE_SET: &AsciiSet = &USERINFO_PASSWORD_ENCODE_SET.add(b':');

/// Reject a percent-decoded userinfo component that contains a control
/// byte. Decoding is what makes this necessary: the graceful authority
/// parser screens only *raw* control bytes, so a userinfo like `a%0Db`
/// reaches [`UserInfoRef::to_basic`]; decoding it into a credential that
/// round-trips into an `Authorization` header would be CRLF injection.
fn reject_decoded_control(s: &str) -> Result<(), BoxError> {
    if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7F) {
        return Err(BoxError::from_static_str(
            "decoded userinfo component contains a control character",
        ));
    }
    Ok(())
}

/// Raw RFC 3986 userinfo bytes. Cheap to clone.
///
/// # Logging safety
///
/// The [`Debug`](core::fmt::Debug) impl redacts the password portion (anything
/// after the first `:`) as `"***"`, matching [`Basic`]'s logging behaviour.
/// This is the safe default for tracing spans and log lines, where a raw
/// `Debug`-print of a [`Uri`](crate::uri::Uri) would otherwise leak
/// credentials into observability sinks. The user portion is rendered raw;
/// pct-encoded bytes are not decoded for the Debug view.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    ///
    /// Naming: `from_static` matches the `Uri::from_static` /
    /// `Domain::from_static` precedent across the rest of the crate.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
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
        unsafe { core::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Borrowed view. Named `view` (not `as_ref`) so it doesn't shadow
    /// the std `AsRef` trait — see the type-level docs.
    #[must_use]
    #[inline]
    pub fn view(&self) -> UserInfoRef<'_> {
        UserInfoRef::new(&self.bytes)
    }

    /// Split on the first `:`. Returns `(user_bytes, password_bytes)`
    /// where the password is `None` if no `:` is present.
    ///
    /// **Bytes are raw — not percent-decoded.** Use
    /// [`crate::uri::util::percent_encoding`] to decode if needed.
    #[must_use]
    pub fn split_user_password(&self) -> (&[u8], Option<&[u8]>) {
        self.view().split_user_password()
    }

    /// Percent-decoded view of the full userinfo. `Cow::Borrowed` when no
    /// `%XX` escapes are present; UTF-8 errors fall back to U+FFFD.
    ///
    /// **Lossy for re-splitting**: a `%3A` in the user part decodes to a
    /// literal `:`. Use [`UserInfo::username_decoded`] /
    /// [`UserInfo::password_decoded`] to decode the components separately.
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'_, str> {
        self.view().as_decoded_str()
    }

    /// Percent-decoded user component (everything before the first raw `:`).
    #[must_use]
    pub fn username_decoded(&self) -> Cow<'_, str> {
        self.view().username_decoded()
    }

    /// Percent-decoded password component (everything after the first raw
    /// `:`), or `None` if no `:` is present.
    #[must_use]
    pub fn password_decoded(&self) -> Option<Cow<'_, str>> {
        self.view().password_decoded()
    }

    /// Convenience: convert this userinfo into a [`Basic`] HTTP
    /// Basic-Auth credential. The components are **percent-decoded** first
    /// (so `user%40host` becomes `user@host`), then validated. See
    /// [`UserInfoRef::to_basic`] for the failure modes.
    pub fn to_basic(&self) -> Result<Basic, BoxError> {
        self.view().to_basic()
    }
}

impl core::fmt::Display for UserInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for UserInfo {
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

/// First-violation tag returned by the shared const validator below.
/// Lets the runtime and `from_static_str` entry points decode the same
/// algorithm into their preferred error mode (boxed error vs panic).
#[derive(Clone, Copy)]
enum UserInfoFault {
    /// Raw control byte (`< 0x20` or `0x7F`).
    ControlByte,
    /// `%` followed by fewer than two bytes.
    PctTruncated,
    /// `%XY` where `X` or `Y` is not a hex digit.
    PctMalformed,
    /// `%XX` that decodes to a control byte (smuggling vector).
    PctDecodesToControl,
    /// Byte outside the RFC 3986 §3.2.1 userinfo byte set.
    DisallowedByte,
}

/// `const` userinfo-grammar walker — single source of truth for both
/// [`validate_userinfo_runtime`] (returns [`BoxError`]) and
/// [`validate_userinfo_static`] (panics). Adding a rejection rule here
/// can't drift between the two entry points.
///
/// Rules (RFC 3986 §3.2.1):
/// - Each byte must be `unreserved / pct-encoded / sub-delims / ":"`.
/// - `%XX` must be a well-formed hex pair.
/// - Pct-decoded byte must not be a control character (smuggling
///   defense — mirrors the URI parser's reg-name handling).
const fn validate_userinfo_bytes(bytes: &[u8]) -> Result<(), UserInfoFault> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == 0x7F {
            return Err(UserInfoFault::ControlByte);
        }
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(UserInfoFault::PctTruncated);
            }
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                return Err(UserInfoFault::PctMalformed);
            }
            if crate::byte_sets::pct_decoded_control_byte(h1, h2).is_some() {
                return Err(UserInfoFault::PctDecodesToControl);
            }
            i += 3;
            continue;
        }
        if !crate::byte_sets::is_userinfo_byte(b) {
            return Err(UserInfoFault::DisallowedByte);
        }
        i += 1;
    }
    Ok(())
}

/// Runtime userinfo-grammar validator. Used by `TryFrom<&str>` /
/// `TryFrom<String>`; maps the const walker's fault tag into a boxed
/// error suitable for the `?`-ladder.
fn validate_userinfo_runtime(bytes: &[u8]) -> Result<(), BoxError> {
    match validate_userinfo_bytes(bytes) {
        Ok(()) => Ok(()),
        Err(fault) => {
            let msg = match fault {
                UserInfoFault::ControlByte => "userinfo contains control character",
                UserInfoFault::PctTruncated | UserInfoFault::PctMalformed => {
                    "userinfo contains malformed percent-escape"
                }
                UserInfoFault::PctDecodesToControl => {
                    "userinfo pct-escape decodes to a control character"
                }
                UserInfoFault::DisallowedByte => "userinfo contains disallowed character",
            };
            Err(BoxError::from_static_str(msg))
        }
    }
}

/// `const` validator for [`UserInfo::from_static`]. Maps the
/// const walker's fault tag into a `panic!` at compile time so static
/// inputs that violate the grammar fail the build.
#[expect(
    clippy::panic,
    reason = "static-str invariant: compile-time panic when the static input violates the userinfo grammar"
)]
const fn validate_userinfo_static(bytes: &[u8]) {
    match validate_userinfo_bytes(bytes) {
        Ok(()) => {}
        Err(UserInfoFault::ControlByte) => {
            panic!("UserInfo::from_static: control character in input")
        }
        Err(UserInfoFault::PctTruncated) => {
            panic!("UserInfo::from_static: truncated percent-escape")
        }
        Err(UserInfoFault::PctMalformed) => {
            panic!("UserInfo::from_static: malformed percent-escape")
        }
        Err(UserInfoFault::PctDecodesToControl) => {
            panic!("UserInfo::from_static: pct-escape decodes to a control character")
        }
        Err(UserInfoFault::DisallowedByte) => {
            panic!("UserInfo::from_static: disallowed character")
        }
    }
}

/// Construct a [`UserInfo`] from a [`Basic`] credential by
/// **percent-encoding** each component into the RFC 3986 §3.2.1 userinfo
/// wire form. The username escapes `:` (so the first literal `:` is
/// unambiguously the user/password separator); the password keeps `:`
/// literal. `@`, space, and every other non-userinfo byte become `%XX`,
/// so the result re-parses cleanly through [`UserInfo::try_from`] and
/// decodes back to the original credential via [`UserInfo::to_basic`].
///
/// # Round-trip invariant
///
/// Encoding always yields grammar-valid userinfo. The `Basic` →
/// `UserInfo` → [`UserInfo::try_from`] round-trip holds for exactly the
/// `Basic` values whose components are free of control bytes
/// (`0x00`–`0x1F` / `0x7F`): any control byte encodes to a `%XX` escape
/// that strict parsing then refuses as a pct-decoded-control smuggling
/// vector. [`Basic::try_from`] pre-rejects `\r` / `\n` / NUL, but the
/// typed constructors (`Basic::new`, the `with_`/`set_` setters,
/// `clone_with_*`) do not validate, so any control byte can reach this
/// obscure residual regardless of which entry point built the `Basic`.
impl From<Basic> for UserInfo {
    fn from(basic: Basic) -> Self {
        let mut s = String::new();
        s.extend(utf8_percent_encode(
            basic.username(),
            USERINFO_USERNAME_ENCODE_SET,
        ));
        if let Some(password) = basic.password() {
            s.push(':');
            s.extend(utf8_percent_encode(password, USERINFO_PASSWORD_ENCODE_SET));
        }
        Self {
            bytes: Bytes::from(s),
        }
    }
}

impl TryFrom<&UserInfo> for Basic {
    type Error = BoxError;

    /// Parse a [`UserInfo`] into HTTP Basic-Auth credentials. Same
    /// semantics as [`UserInfo::to_basic`] — kept as a [`TryFrom`]
    /// impl for the standard `Basic::try_from(&userinfo)?` idiom.
    fn try_from(value: &UserInfo) -> Result<Self, Self::Error> {
        value.to_basic()
    }
}

impl TryFrom<UserInfo> for Basic {
    type Error = BoxError;

    /// Owned-input form of [`TryFrom<&UserInfo>`](Self#impl-TryFrom<%26UserInfo>-for-Basic).
    /// Routes through the borrowed impl since [`Basic::try_from`]
    /// doesn't need to own the bytes.
    fn try_from(value: UserInfo) -> Result<Self, Self::Error> {
        Self::try_from(&value)
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
        unsafe { core::str::from_utf8_unchecked(self.bytes) }
    }

    /// Split on the first `:`. Mirrors [`UserInfo::split_user_password`].
    #[must_use]
    pub fn split_user_password(&self) -> (&'a [u8], Option<&'a [u8]>) {
        match self.bytes.iter().position(|&b| b == b':') {
            Some(i) => (&self.bytes[..i], Some(&self.bytes[i + 1..])),
            None => (self.bytes, None),
        }
    }

    /// Construct an owned [`UserInfo`] by copying the bytes. Named
    /// `into_owned` (matching [`crate::std::borrow::Cow::into_owned`]) so it doesn't
    /// shadow the std `ToOwned` trait method.
    #[must_use]
    pub fn into_owned(self) -> UserInfo {
        UserInfo {
            bytes: Bytes::copy_from_slice(self.bytes),
        }
    }

    /// Percent-decoded view of the full userinfo. See
    /// [`UserInfo::as_decoded_str`] (incl. the re-splitting caveat).
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'a, str> {
        percent_decode(self.bytes).decode_utf8_lossy()
    }

    /// Percent-decoded user component (before the first raw `:`).
    #[must_use]
    pub fn username_decoded(&self) -> Cow<'a, str> {
        let (user, _) = self.split_user_password();
        percent_decode(user).decode_utf8_lossy()
    }

    /// Percent-decoded password component (after the first raw `:`), or
    /// `None` if no `:` is present.
    #[must_use]
    pub fn password_decoded(&self) -> Option<Cow<'a, str>> {
        let (_, password) = self.split_user_password();
        password.map(|p| percent_decode(p).decode_utf8_lossy())
    }

    /// Convert to a [`Basic`] HTTP credential. The components are
    /// **percent-decoded** then validated.
    ///
    /// Fails if the decoded user is empty (`Basic` requires a non-empty
    /// username) or if a decoded component contains a control byte. The
    /// latter is load-bearing: the graceful authority parser screens only
    /// *raw* control bytes, so a userinfo like `a%0Db` can reach here, and
    /// decoding it into a credential that round-trips into an
    /// `Authorization` header would be CRLF injection.
    pub fn to_basic(&self) -> Result<Basic, BoxError> {
        let user = self.username_decoded();
        reject_decoded_control(&user)?;
        let username =
            NonEmptyStr::try_from(user.as_ref()).context("create username from userinfo")?;
        let password = match self.password_decoded() {
            Some(p) => {
                reject_decoded_control(&p)?;
                // An empty present password (`user:`) collapses to "no
                // password", matching `Basic::try_from`'s own semantics.
                (!p.is_empty())
                    .then(|| NonEmptyStr::try_from(p.as_ref()))
                    .transpose()
                    .context("create password from userinfo")?
            }
            None => None,
        };
        Ok(match password {
            Some(password) => Basic::new(username, password),
            None => Basic::new_insecure(username),
        })
    }
}

impl<'a> From<&'a UserInfo> for UserInfoRef<'a> {
    fn from(u: &'a UserInfo) -> Self {
        Self::new(&u.bytes)
    }
}

impl core::fmt::Display for UserInfoRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

fn fmt_redacted(bytes: &[u8], f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    // SAFETY: parser/static-validator invariant: UserInfo bytes are valid
    // UTF-8 (graceful preserves UTF-8; strict is ASCII-only; the
    // const validator at `from_static_str` rejects non-UTF-8 byte
    // sequences via its byte-class check, which is ASCII).
    let s = unsafe { core::str::from_utf8_unchecked(bytes) };
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

impl core::fmt::Debug for UserInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_redacted(&self.bytes, f)
    }
}

impl core::fmt::Debug for UserInfoRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_redacted(self.bytes, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_static_str() {
        let u = UserInfo::from_static("alice");
        assert_eq!(u.as_bytes(), b"alice");
        assert_eq!(u.as_str(), "alice");
    }

    #[test]
    fn split_user_password_user_only() {
        let u = UserInfo::from_static("alice");
        assert_eq!(u.split_user_password(), (&b"alice"[..], None));
    }

    #[test]
    fn split_user_password_both() {
        let u = UserInfo::from_static("alice:secret");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b"secret"[..]));
    }

    #[test]
    fn split_user_password_empty_user() {
        let u = UserInfo::from_static(":secret");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"");
        assert_eq!(pass, Some(&b"secret"[..]));
    }

    #[test]
    fn split_user_password_empty_password() {
        let u = UserInfo::from_static("alice:");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b""[..]));
    }

    #[test]
    fn split_user_password_multiple_colons() {
        // RFC 3986 userinfo allows multiple `:`. First `:` is the split.
        let u = UserInfo::from_static("alice:p:w");
        let (user, pass) = u.split_user_password();
        assert_eq!(user, b"alice");
        assert_eq!(pass, Some(&b"p:w"[..]));
    }

    #[test]
    fn to_basic_user_only() {
        let u = UserInfo::from_static("alice");
        let b = u.to_basic().unwrap();
        assert_eq!(b.username(), "alice");
        assert!(b.password().is_none());
    }

    #[test]
    fn to_basic_user_password() {
        let u = UserInfo::from_static("alice:secret");
        let b = u.to_basic().unwrap();
        assert_eq!(b.username(), "alice");
        assert_eq!(b.password(), Some("secret"));
    }

    // -- Debug redaction -------------------------------------

    #[test]
    fn debug_redacts_password() {
        let u = UserInfo::from_static("alice:secret");
        let s = format!("{u:?}");
        assert!(!s.contains("secret"), "debug leaked password: {s}");
        assert!(s.contains("alice"), "debug missing user: {s}");
        assert!(s.contains("***"), "debug missing redaction marker: {s}");
    }

    #[test]
    fn debug_omits_password_field_when_absent() {
        // No `:` → no credential → no `password` field at all.
        let u = UserInfo::from_static("alice");
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
        let u = UserInfo::from_static("alice:");
        let s = format!("{u:?}");
        assert!(s.contains("alice"));
        assert!(s.contains("***"), "debug must redact even empty password");
    }

    #[test]
    fn debug_redacts_multiple_colon_password() {
        // RFC 3986 allows extra `:` in the password portion. Redaction
        // covers everything after the first `:`.
        let u = UserInfo::from_static("alice:secret:more");
        let s = format!("{u:?}");
        assert!(!s.contains("secret"), "debug leaked password: {s}");
        assert!(!s.contains("more"), "debug leaked password tail: {s}");
    }

    #[test]
    fn ref_debug_matches_owned_redaction() {
        // The borrowed view uses the same redacting helper as the owned
        // type so logging through either path is safe.
        let u = UserInfo::from_static("alice:secret");
        let r: UserInfoRef<'_> = (&u).into();
        let owned_dbg = format!("{u:?}");
        let ref_dbg = format!("{r:?}");
        assert_eq!(owned_dbg, ref_dbg);
    }

    #[test]
    fn to_basic_rejects_empty_user() {
        // `Basic` requires non-empty username.
        let u = UserInfo::from_static(":secret");
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
                UserInfo::from_static(unsafe {
                    // Safety: the leaked `&'static str` is only used
                    // inside `catch_unwind`; we never escape it.
                    core::mem::transmute::<&str, &'static str>(input)
                })
            });
            assert!(result.is_err(), "expected panic for {input:?}");
        }
    }

    #[test]
    fn from_static_str_accepts_valid_inputs() {
        let _u = UserInfo::from_static("alice");
        let _u = UserInfo::from_static("alice:secret");
        let _u = UserInfo::from_static("user%40info"); // pct-encoded @
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
        let u = UserInfo::from_static("alice:secret");
        let r = u.view();
        assert_eq!(
            r.split_user_password(),
            (&b"alice"[..], Some(&b"secret"[..]))
        );
    }

    #[test]
    fn ref_into_owned_roundtrip() {
        let u = UserInfo::from_static("alice:secret");
        let r = u.view();
        let owned = r.into_owned();
        assert_eq!(owned, u);
    }

    // ---- TryFrom<UserInfo> for Basic ------------------------

    #[test]
    fn try_from_userinfo_for_basic_user_password() {
        let u = UserInfo::from_static("alice:secret");
        let b = Basic::try_from(&u).unwrap();
        assert_eq!(b.username(), "alice");
        assert_eq!(b.password(), Some("secret"));

        // Owned-input form delegates to the borrowed impl.
        let b2 = Basic::try_from(u).unwrap();
        assert_eq!(b2.username(), "alice");
    }

    #[test]
    fn try_from_userinfo_for_basic_propagates_error() {
        // Empty username — `Basic::try_from(&str)` rejects.
        let u = UserInfo::from_static(":secret");
        Basic::try_from(&u).unwrap_err();
    }

    // ---- decoded accessors + encode/decode round-trip -------

    #[test]
    fn decoded_accessors() {
        let ui = UserInfo::from_static("us%20er:p%40ss");
        assert_eq!(&*ui.as_decoded_str(), "us er:p@ss");
        assert_eq!(&*ui.username_decoded(), "us er");
        assert_eq!(ui.password_decoded().as_deref(), Some("p@ss"));

        // the borrowed view agrees with the owned type
        let r = ui.view();
        assert_eq!(&*r.as_decoded_str(), "us er:p@ss");
        assert_eq!(&*r.username_decoded(), "us er");
        assert_eq!(r.password_decoded().as_deref(), Some("p@ss"));

        // no password component
        let ui = UserInfo::from_static("alice");
        assert_eq!(&*ui.username_decoded(), "alice");
        assert!(ui.password_decoded().is_none());
    }

    #[test]
    fn to_basic_percent_decodes_components() {
        let ui = UserInfo::from_static("user%40host:p%40ss");
        let b = ui.to_basic().unwrap();
        assert_eq!(b.username(), "user@host");
        assert_eq!(b.password(), Some("p@ss"));
    }

    #[test]
    fn to_basic_username_with_encoded_colon() {
        // `%3A` decodes to ':' inside the username, but the user/password
        // split happens on the *raw* ':' separator, so the password is
        // still parsed correctly.
        let ui = UserInfo::from_static("a%3Ab:pw");
        let b = ui.to_basic().unwrap();
        assert_eq!(b.username(), "a:b");
        assert_eq!(b.password(), Some("pw"));
    }

    #[test]
    fn to_basic_rejects_pct_decoded_control() {
        // The graceful authority parser screens only RAW control bytes, so
        // a userinfo whose pct-escape *decodes* to CR/LF/NUL can exist.
        // Decoding it into an `Authorization`-bound credential would be
        // CRLF injection, so `to_basic` must reject it. (`from_static`
        // would reject at compile time, so build via the unchecked ctor.)
        for raw in [b"a%0Db".as_slice(), b"a%0Ab", b"a%00b", b"user:p%0Dw"] {
            let ui = UserInfo::from_bytes_unchecked(Bytes::copy_from_slice(raw));
            ui.to_basic().unwrap_err();
        }
    }

    // ---- `From<Basic>` now percent-encodes -------

    #[test]
    fn from_basic_percent_encodes_and_roundtrips() {
        // `@` in both components: `Basic::try_from` accepts it (only
        // CR/LF/NUL are rejected), and the encoder now emits valid wire
        // form that strict `UserInfo::try_from` accepts — the old
        // divergence is gone — and decodes back to the original credential.
        let basic = Basic::try_from("user@host:p@ss").unwrap();
        let ui: UserInfo = basic.clone().into();
        assert_eq!(ui.as_str(), "user%40host:p%40ss");
        UserInfo::try_from(ui.as_str()).expect("encoded userinfo must re-parse");
        let back = ui.to_basic().unwrap();
        assert_eq!(back, basic);
        assert_eq!(back.username(), "user@host");
        assert_eq!(back.password(), Some("p@ss"));
    }

    #[test]
    fn from_basic_escapes_colon_in_username() {
        // A `:` inside the username must be escaped so it isn't read as
        // the user/password separator on the way back in.
        let basic = Basic::new(
            NonEmptyStr::try_from("a:b").unwrap(),
            NonEmptyStr::try_from("pw").unwrap(),
        );
        let ui: UserInfo = basic.into();
        assert_eq!(ui.as_str(), "a%3Ab:pw");
        let back = ui.to_basic().unwrap();
        assert_eq!(back.username(), "a:b");
        assert_eq!(back.password(), Some("pw"));
    }

    #[test]
    fn from_basic_control_byte_is_the_residual_divergence() {
        // Documented residual: `Basic::try_from` allows a tab (only
        // CR/LF/NUL are rejected), so it encodes to `%09`, which strict
        // `UserInfo::try_from` still refuses as a pct-decoded control byte.
        let basic = Basic::try_from("a\tb:pw").unwrap();
        let ui: UserInfo = basic.into();
        assert_eq!(ui.as_str(), "a%09b:pw");
        UserInfo::try_from(ui.as_str()).unwrap_err();
    }

    #[test]
    fn userinfo_encode_set_matches_validator_allow_set() {
        // `AsciiSet::contains` is crate-private, so probe each set by
        // encoding a one-byte string and checking whether it changed.
        let escapes = |set: &'static AsciiSet, b: u8| {
            let buf = [b];
            let s = core::str::from_utf8(&buf).unwrap();
            utf8_percent_encode(s, set).to_string().as_str() != s
        };
        for b in 0u8..=127 {
            // `%` is the one intentional difference: the validator allows
            // it as the pct-escape lead, but the encoder escapes a raw `%`.
            if b == b'%' {
                continue;
            }
            // The password set keeps ':' literal, so a byte is escaped by
            // it iff it's outside the userinfo allow-set.
            let pw_escaped = escapes(USERINFO_PASSWORD_ENCODE_SET, b);
            assert_eq!(
                crate::byte_sets::is_userinfo_byte(b),
                !pw_escaped,
                "password set disagrees on byte {b:#04x}",
            );
            // The username set differs only by also escaping ':'.
            assert_eq!(
                escapes(USERINFO_USERNAME_ENCODE_SET, b),
                pw_escaped || b == b':',
                "username set disagrees on byte {b:#04x}",
            );
        }
    }
}
