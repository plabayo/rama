//! [`DomainBuilder`] — incrementally construct a [`Domain`] from labels,
//! enforcing per-label and total-length invariants at push time.
//!
//! Modeled on `NLnetLabs/domain`'s `NameBuilder`, scoped to rama-net's
//! presentation-format reality (no octets generic, `String`-backed).

use std::fmt;

use super::label::validate_label_bytes;
use super::{Domain, DomainLabels, Label, LabelError, MAX_NAME_LEN};

/// Builder for a [`Domain`].
///
/// Labels are pushed in DNS-natural order: leftmost (most specific) first,
/// rightmost (TLD) last. The builder maintains the [`Domain`] invariant
/// after every successful push, so [`DomainBuilder::finish`] is infallible.
///
/// # Example
///
/// ```
/// use rama_net::address::domain::DomainBuilder;
///
/// let mut b = DomainBuilder::new();
/// b.push_label("www").unwrap();
/// b.push_label("example").unwrap();
/// b.push_label("com").unwrap();
/// let d = b.finish();
/// assert_eq!(d.as_str(), "www.example.com");
/// ```
#[derive(Debug, Clone, Default)]
pub struct DomainBuilder {
    buf: String,
}

impl DomainBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: String::new() }
    }

    /// Creates an empty builder pre-allocating `cap` bytes.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: String::with_capacity(cap),
        }
    }

    /// Returns the number of labels currently in the builder.
    #[must_use]
    pub fn label_count(&self) -> usize {
        if self.buf.is_empty() {
            0
        } else {
            self.buf.bytes().filter(|b| *b == b'.').count() + 1
        }
    }

    /// Returns `true` if no labels have been pushed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the current length in bytes (including separating dots).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Push a single label.
    ///
    /// `label` must satisfy [`Label`]'s invariants. The total name length
    /// after the push (including the joining dot) must not exceed
    /// `Domain::MAX_NAME_LEN` (253).
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] if the label or resulting name length is invalid.
    pub fn push_label(&mut self, label: &str) -> Result<&mut Self, PushError> {
        validate_label_bytes(label.as_bytes()).map_err(PushError::from_label)?;
        self.push_validated_label(label)
    }

    /// Push an already-validated [`Label`] reference.
    ///
    /// Still enforces the total name length cap.
    ///
    /// # Errors
    ///
    /// Returns a too-long [`PushError`] if the resulting name length would
    /// exceed `Domain::MAX_NAME_LEN`.
    pub fn push(&mut self, label: &Label) -> Result<&mut Self, PushError> {
        self.push_validated_label(label.as_str())
    }

    fn push_validated_label(&mut self, label: &str) -> Result<&mut Self, PushError> {
        // Wildcard `*` is only valid as the leftmost label. The label-level
        // validator accepts `"*"` standalone, so the positional rule lives
        // here in the builder.
        if label == "*" && !self.buf.is_empty() {
            return Err(PushError::misplaced_wildcard());
        }

        // Each push adds `label.len()` plus a separating dot (except for the
        // very first label).
        let added = if self.buf.is_empty() {
            label.len()
        } else {
            label.len() + 1
        };
        let new_len = self.buf.len() + added;
        if new_len > MAX_NAME_LEN {
            return Err(PushError::too_long(new_len));
        }
        if !self.buf.is_empty() {
            self.buf.push('.');
        }
        self.buf.push_str(label);
        Ok(self)
    }

    /// Push every label from `it` in iteration order.
    ///
    /// # Errors
    ///
    /// Returns the first [`PushError`] encountered. On error, the builder
    /// retains the labels that pushed successfully — the caller may still
    /// inspect or discard it.
    pub fn push_labels<'a, I: IntoIterator<Item = &'a Label>>(
        &mut self,
        it: I,
    ) -> Result<&mut Self, PushError> {
        for l in it {
            self.push(l)?;
        }
        Ok(self)
    }

    /// Append every label from another label-aware value (e.g. a [`Domain`]
    /// or [`Host`](super::super::Host)).
    ///
    /// # Errors
    ///
    /// Returns the first [`PushError`] encountered.
    pub fn append<D: DomainLabels + ?Sized>(&mut self, other: &D) -> Result<&mut Self, PushError> {
        self.push_labels(other.labels())
    }

    /// Parse `dotted` as a sequence of labels separated by `.`, ignoring
    /// empty segments (i.e. leading and trailing FQDN dots are accepted).
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] on the first invalid label or length overflow.
    pub fn push_label_segments(&mut self, dotted: &str) -> Result<&mut Self, PushError> {
        for part in dotted.split('.') {
            if part.is_empty() {
                continue;
            }
            self.push_label(part)?;
        }
        Ok(self)
    }

    /// Consume the builder and produce a [`Domain`].
    ///
    /// # Panics
    ///
    /// Panics if no labels have been pushed. Use [`Self::try_finish`] for a
    /// non-panicking variant.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "API contract: caller must have pushed at least one label"
    )]
    pub fn finish(self) -> Domain {
        if self.buf.is_empty() {
            panic!("DomainBuilder::finish called with no labels pushed");
        }
        if self.buf == "*" {
            panic!("DomainBuilder::finish: bare '*' is not a valid domain");
        }
        // Safety: builder maintained the Domain invariant at every push.
        unsafe { Domain::from_maybe_borrowed_unchecked(self.buf) }
    }

    /// Consume the builder and produce a [`Domain`], or return [`PushError`]
    /// if the builder is empty.
    ///
    /// # Errors
    ///
    /// Returns an empty [`PushError`] if no labels have been pushed.
    pub fn try_finish(self) -> Result<Domain, PushError> {
        if self.buf.is_empty() {
            return Err(PushError::empty());
        }
        if self.buf == "*" {
            return Err(PushError::misplaced_wildcard());
        }
        // Safety: as above.
        Ok(unsafe { Domain::from_maybe_borrowed_unchecked(self.buf) })
    }
}

/// Error returned by [`DomainBuilder`] when a push would violate the
/// [`Domain`] invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushError(PushErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum PushErrorKind {
    Empty,
    Label(LabelError),
    TooLong { len: usize },
    MisplacedWildcard,
}

impl PushError {
    #[inline]
    fn empty() -> Self {
        Self(PushErrorKind::Empty)
    }
    #[inline]
    fn from_label(e: LabelError) -> Self {
        Self(PushErrorKind::Label(e))
    }
    #[inline]
    fn too_long(len: usize) -> Self {
        Self(PushErrorKind::TooLong { len })
    }
    #[inline]
    fn misplaced_wildcard() -> Self {
        Self(PushErrorKind::MisplacedWildcard)
    }

    /// Returns the underlying [`LabelError`] if this is a label-validation
    /// failure.
    #[must_use]
    pub fn as_label_error(&self) -> Option<&LabelError> {
        match &self.0 {
            PushErrorKind::Label(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            PushErrorKind::Empty => f.write_str("no labels pushed to domain builder"),
            PushErrorKind::Label(e) => write!(f, "invalid label: {e}"),
            PushErrorKind::TooLong { len } => write!(
                f,
                "domain name would be {len} bytes long, max is {MAX_NAME_LEN}"
            ),
            PushErrorKind::MisplacedWildcard => f.write_str(
                "wildcard label '*' is only valid as the leftmost label and never alone",
            ),
        }
    }
}

impl std::error::Error for PushError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            PushErrorKind::Label(e) => Some(e),
            _ => None,
        }
    }
}

impl From<LabelError> for PushError {
    fn from(e: LabelError) -> Self {
        Self::from_label(e)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Domain;
    use super::*;

    #[test]
    fn build_single_label() {
        let mut b = DomainBuilder::new();
        b.push_label("com").unwrap();
        assert_eq!(b.label_count(), 1);
        let d = b.finish();
        assert_eq!(d.as_str(), "com");
    }

    #[test]
    fn build_multi_label() {
        let mut b = DomainBuilder::new();
        b.push_label("www").unwrap();
        b.push_label("example").unwrap();
        b.push_label("com").unwrap();
        assert_eq!(b.label_count(), 3);
        let d = b.finish();
        assert_eq!(d.as_str(), "www.example.com");
    }

    #[test]
    fn build_wildcard() {
        let mut b = DomainBuilder::new();
        b.push_label("*").unwrap();
        b.push_label("example").unwrap();
        b.push_label("com").unwrap();
        let d = b.finish();
        assert_eq!(d.as_str(), "*.example.com");
        assert!(d.is_wildcard());
    }

    #[test]
    fn append_domain() {
        let parent = Domain::from_static("example.com");
        let mut b = DomainBuilder::new();
        b.push_label("www").unwrap();
        b.append(&parent).unwrap();
        assert_eq!(b.finish().as_str(), "www.example.com");
    }

    #[test]
    fn push_label_segments_handles_dots() {
        let mut b = DomainBuilder::new();
        b.push_label_segments("a.b.c").unwrap();
        assert_eq!(b.finish().as_str(), "a.b.c");

        // leading/trailing/duplicate dots are squashed (split + filter empty)
        let mut b = DomainBuilder::new();
        b.push_label_segments(".a.b.").unwrap();
        assert_eq!(b.finish().as_str(), "a.b");
    }

    #[test]
    fn rejects_invalid_label() {
        let mut b = DomainBuilder::new();
        let err = b.push_label("-bad").unwrap_err();
        assert!(err.as_label_error().is_some());
        assert!(b.is_empty(), "builder is unchanged after failed push");
    }

    #[test]
    fn rejects_total_length_overflow() {
        // 63 + 1 + 63 + 1 + 63 + 1 + 63 = 255 > 253. Three 63-byte labels fit
        // (191), a fourth doesn't.
        let label63 = "a".repeat(63);
        let mut b = DomainBuilder::new();
        b.push_label(&label63).unwrap();
        b.push_label(&label63).unwrap();
        b.push_label(&label63).unwrap();
        let err = b.push_label(&label63).unwrap_err();
        assert!(format!("{err}").contains("max is 253"));
    }

    #[test]
    fn try_finish_empty() {
        let b = DomainBuilder::new();
        let err = b.try_finish().unwrap_err();
        assert!(format!("{err}").contains("no labels"));
    }

    #[test]
    #[should_panic(expected = "no labels")]
    fn finish_panics_when_empty() {
        let b = DomainBuilder::new();
        // Discard via drop, not `let _ = ...`, since `finish` is `#[must_use]`.
        drop(b.finish());
    }

    #[test]
    fn push_already_validated_label() {
        let l = Label::from_str("example").unwrap();
        let mut b = DomainBuilder::new();
        b.push(l).unwrap();
        b.push_label("com").unwrap();
        assert_eq!(b.finish().as_str(), "example.com");
    }

    #[test]
    fn rejects_wildcard_at_non_leftmost_position() {
        // Pushed after a regular label.
        let mut b = DomainBuilder::new();
        b.push_label("example").unwrap();
        let err = b.push_label("*").unwrap_err();
        assert!(
            format!("{err}").contains("wildcard"),
            "expected wildcard mention, got: {err}"
        );

        // Pushed via push_label_segments.
        let mut b = DomainBuilder::new();
        let err = b.push_label_segments("x.*.com").unwrap_err();
        assert!(format!("{err}").contains("wildcard"), "got: {err}");

        // Pushed via append (Domain whose first label is `*`).
        let parent = Domain::from_static("*.example.com");
        let mut b = DomainBuilder::new();
        b.push_label("foo").unwrap();
        let err = b.append(&parent).unwrap_err();
        assert!(format!("{err}").contains("wildcard"), "got: {err}");
    }

    #[test]
    fn accepts_wildcard_as_leftmost_label() {
        let mut b = DomainBuilder::new();
        b.push_label("*").unwrap();
        b.push_label("example").unwrap();
        b.push_label("com").unwrap();
        let d = b.finish();
        assert_eq!(d.as_str(), "*.example.com");
        // And the output reparses (no broken invariant).
        Domain::try_from(d.as_str().to_owned()).expect("builder output reparses");
    }

    #[test]
    fn rejects_bare_wildcard_on_finish() {
        let mut b = DomainBuilder::new();
        b.push_label("*").unwrap();
        // Only one label, and it's `*` — not a valid domain on its own.
        let err = b.try_finish().unwrap_err();
        assert!(format!("{err}").contains("wildcard"), "got: {err}");
    }

    #[test]
    #[should_panic(expected = "bare '*'")]
    fn finish_panics_on_bare_wildcard() {
        let mut b = DomainBuilder::new();
        b.push_label("*").unwrap();
        drop(b.finish());
    }

    #[test]
    fn build_matches_validating_parser() {
        // The buffer the builder produces is parseable as a Domain — i.e. the
        // builder's invariant matches the parser's.
        let mut b = DomainBuilder::new();
        b.push_label("a").unwrap();
        b.push_label("_acme-challenge").unwrap();
        b.push_label("example").unwrap();
        b.push_label("com").unwrap();
        let s = b.clone().finish().as_str().to_owned();
        Domain::try_from(s).expect("builder output must reparse");
    }
}
