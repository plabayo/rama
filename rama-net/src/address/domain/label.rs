//! [`Label`] — a single DNS label in presentation format.
//!
//! `Label` is a `?Sized`, `#[repr(transparent)]` view over `str`. It enforces
//! the per-label invariants of [`Domain`](super::Domain) (length, charset,
//! hyphen placement, wildcard form) and provides case-insensitive ASCII
//! equality, hashing, and ordering, so that `Domain` can delegate those impls
//! to its label sequence.
//!
//! This module is presentation-format only — there is no DNS wire format,
//! octets generic, or DNSSEC layer. The design mirrors the structural pieces
//! of `NLnetLabs/domain`'s `Label` type, scoped to what rama-net needs.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A single DNS label in presentation format.
///
/// `Label` is a borrowed, unsized view: you'll always work with `&Label`,
/// produced either by [`Label::from_str`] (validated) or by internal helpers
/// that already maintain the invariant.
///
/// # Invariants
///
/// A `&Label`'s contents always satisfy:
///
/// - non-empty, at most [`Label::MAX_LEN`] (`63`) bytes
/// - either the single-byte wildcard form `"*"`, **or** a sequence of ASCII
///   alphanumerics, `_`, and `-`, with no leading or trailing `-`
///
/// # Equality / ordering
///
/// `Label`'s `PartialEq`, `Eq`, `Hash`, `Ord`, and `PartialOrd` impls are
/// **ASCII-case-insensitive**. `"Foo"`, `"foo"`, and `"FOO"` compare equal and
/// hash to the same value.
#[repr(transparent)]
pub struct Label(str);

impl Label {
    /// Maximum byte length of a single label (RFC 1035).
    pub const MAX_LEN: usize = 63;

    /// Parses a single label.
    ///
    /// # Errors
    ///
    /// Returns a [`LabelError`] if `s` violates any [invariant](Self).
    #[expect(
        clippy::should_implement_trait,
        reason = "Label is !Sized; FromStr requires Sized + returns Self by value"
    )]
    pub fn from_str(s: &str) -> Result<&Self, LabelError> {
        validate_label_bytes(s.as_bytes())?;
        // Safety: `validate_label_bytes` guarantees the invariant.
        Ok(unsafe { Self::from_str_unchecked(s) })
    }

    /// Constructs a `&Label` without validation.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `s` upholds every [invariant](Self).
    /// In practice this is used when iterating over a `Domain`'s buffer, which
    /// was already fully validated at construction.
    pub(crate) unsafe fn from_str_unchecked(s: &str) -> &Self {
        // Safety: `Label` is `#[repr(transparent)]` over `str`, so the layout
        // of `&str` and `&Label` is identical.
        unsafe { &*(s as *const str as *const Self) }
    }

    /// Returns the label as its underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the label length in bytes.
    ///
    /// A label is non-empty by [invariant](Self), so length is always `>= 1`;
    /// there is intentionally no `is_empty` method.
    #[expect(
        clippy::len_without_is_empty,
        reason = "Label is non-empty by invariant; is_empty would be trivially false"
    )]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this is the wildcard label `"*"`.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0.as_bytes() == b"*"
    }
}

impl AsRef<str> for Label {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({:?})", &self.0)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Label {}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Length-prefix so concatenated labels don't collide with longer ones.
        state.write_usize(self.0.len());
        for b in self.0.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut a = self.0.bytes();
        let mut b = other.0.bytes();
        loop {
            match (a.next(), b.next()) {
                (Some(x), Some(y)) => match x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()) {
                    Ordering::Equal => {}
                    non_eq => return non_eq,
                },
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (None, None) => return Ordering::Equal,
            }
        }
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Error returned by [`Label::from_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelError(LabelErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum LabelErrorKind {
    Empty,
    TooLong { len: usize },
    LeadingHyphen,
    TrailingHyphen,
    InvalidChar { byte: u8, at: usize },
}

impl LabelError {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self(LabelErrorKind::Empty)
    }
    #[inline]
    pub(crate) fn too_long(len: usize) -> Self {
        Self(LabelErrorKind::TooLong { len })
    }
    #[inline]
    pub(crate) fn leading_hyphen() -> Self {
        Self(LabelErrorKind::LeadingHyphen)
    }
    #[inline]
    pub(crate) fn trailing_hyphen() -> Self {
        Self(LabelErrorKind::TrailingHyphen)
    }
    #[inline]
    pub(crate) fn invalid_char(byte: u8, at: usize) -> Self {
        Self(LabelErrorKind::InvalidChar { byte, at })
    }
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            LabelErrorKind::Empty => f.write_str("empty domain label"),
            LabelErrorKind::TooLong { len } => write!(
                f,
                "domain label is {len} bytes long, max is {}",
                Label::MAX_LEN
            ),
            LabelErrorKind::LeadingHyphen => f.write_str("domain label may not start with '-'"),
            LabelErrorKind::TrailingHyphen => f.write_str("domain label may not end with '-'"),
            LabelErrorKind::InvalidChar { byte, at } => {
                write!(f, "invalid byte 0x{byte:02x} in domain label at index {at}")
            }
        }
    }
}

impl std::error::Error for LabelError {}

/// Shared validation: also used by [`Domain`](super::Domain)'s internal parser
/// so error reporting agrees byte-for-byte between the two surfaces.
pub(crate) fn validate_label_bytes(bytes: &[u8]) -> Result<(), LabelError> {
    if bytes.is_empty() {
        return Err(LabelError::empty());
    }
    if bytes.len() > Label::MAX_LEN {
        return Err(LabelError::too_long(bytes.len()));
    }

    // Wildcard label is the single byte `*`.
    if bytes == b"*" {
        return Ok(());
    }

    if bytes[0] == b'-' {
        return Err(LabelError::leading_hyphen());
    }
    if bytes[bytes.len() - 1] == b'-' {
        return Err(LabelError::trailing_hyphen());
    }

    for (at, &c) in bytes.iter().enumerate() {
        let ok = c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
        if !ok {
            return Err(LabelError::invalid_char(c, at));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::{HashMap, HashMapExt as _};

    #[test]
    fn valid_labels() {
        for s in [
            "a",
            "A",
            "aA1",
            "example",
            "_acme-challenge",
            "_acme_challenge_",
            "a-b-c",
            "rr5---sn-q4fl6n6s",
            "127",
            "*",
        ] {
            Label::from_str(s).unwrap_or_else(|e| panic!("expected ok for {s:?}: {e}"));
        }
    }

    #[test]
    fn invalid_labels() {
        let cases: &[(&str, &str)] = &[
            ("", "empty"),
            ("-foo", "leading hyphen"),
            ("foo-", "trailing hyphen"),
            ("-", "leading hyphen"),
            ("foo.bar", "dot not allowed inside label"),
            ("foo*bar", "embedded wildcard"),
            ("*foo", "wildcard with extra"),
            ("foo*", "wildcard with extra"),
            ("こんにちは", "non-ascii"),
            ("foo bar", "space"),
        ];
        for (s, why) in cases {
            assert!(
                Label::from_str(s).is_err(),
                "expected error for {s:?} ({why})"
            );
        }

        // too long
        let too_long = "a".repeat(Label::MAX_LEN + 1);
        let err = Label::from_str(&too_long).unwrap_err();
        assert!(format!("{err}").contains("max is 63"));
    }

    #[test]
    fn ascii_case_insensitive_eq_hash_ord() {
        let a = Label::from_str("Example").unwrap();
        let b = Label::from_str("eXaMpLe").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cmp(b), Ordering::Equal);

        let mut m: HashMap<&Label, ()> = HashMap::new();
        m.insert(Label::from_str("Foo").unwrap(), ());
        assert!(m.contains_key(Label::from_str("FOO").unwrap()));
        assert!(m.contains_key(Label::from_str("foo").unwrap()));
        assert!(!m.contains_key(Label::from_str("foo2").unwrap()));
    }

    #[test]
    fn ordering_lex_case_folded() {
        let a = Label::from_str("Apple").unwrap();
        let b = Label::from_str("banana").unwrap();
        assert!(a < b);
        assert!(b > a);

        // length-tiebreak: prefix is less than longer name
        let pre = Label::from_str("foo").unwrap();
        let longer = Label::from_str("foobar").unwrap();
        assert!(pre < longer);
    }

    #[test]
    fn wildcard_helper() {
        assert!(Label::from_str("*").unwrap().is_wildcard());
        assert!(!Label::from_str("foo").unwrap().is_wildcard());
    }

    #[test]
    fn unchecked_constructor_layout() {
        // Compile-time-ish: confirm round trip through unchecked goes via repr(transparent).
        let s = "valid";
        let l = unsafe { Label::from_str_unchecked(s) };
        assert_eq!(l.as_str(), s);
        assert_eq!(l.len(), s.len());
    }
}
