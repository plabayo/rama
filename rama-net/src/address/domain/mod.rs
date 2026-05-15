use rama_utils::str::smol_str::SmolStr;
use std::{cmp::Ordering, fmt};

use super::Host;

mod label;
#[doc(inline)]
pub use label::{Label, LabelError};

mod labels;
#[doc(inline)]
pub use labels::{DomainLabelIter, DomainLabels, SuffixIter};

mod builder;
#[doc(inline)]
pub use builder::{DomainBuilder, PushError};

// (DomainParseError is defined in this module — see below.)

/// Maximum byte length of a fully-qualified domain name (RFC 1035).
pub const MAX_NAME_LEN: usize = 253;

/// A domain.
///
/// # Remarks
///
/// The validation of domains created by this type is very shallow.
/// Proper validation is offloaded to other services such as DNS resolvers.
#[derive(Debug, Clone)]
pub struct Domain(SmolStr);

impl Domain {
    /// Creates a domain at compile time.
    ///
    /// This function requires the static string to be a valid domain
    ///
    /// # Panics
    ///
    /// This function panics at **compile time** when the static string is not a valid domain.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "static-str invariant: panic at compile time when the static is invalid"
    )]
    pub const fn from_static(s: &'static str) -> Self {
        if !is_valid_name(s.as_bytes()) {
            panic!("static str is an invalid domain");
        }
        Self(SmolStr::new_static(s))
    }

    /// Safety: callee ensures that the given string is a valid domain,
    /// this can be useful in cases where we store a string but which
    /// came from a Domain originally.
    pub(crate) unsafe fn from_maybe_borrowed_unchecked(s: impl Into<SmolStr>) -> Self {
        Self(s.into())
    }

    /// Creates the example [`Domain].
    #[must_use]
    #[inline(always)]
    pub const fn example() -> Self {
        Self::from_static("example.com")
    }

    /// Create an new apex [`Domain`] (TLD) meant for loopback purposes.
    ///
    /// As proposed in
    /// <https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf>.
    ///
    /// In specific this means that it will match on any domain with the TLD `.internal`.
    #[must_use]
    #[inline(always)]
    pub const fn tld_private() -> Self {
        Self::from_static("internal")
    }

    /// Creates the localhost [`Domain`].
    #[must_use]
    #[inline(always)]
    pub const fn tld_localhost() -> Self {
        Self::from_static("localhost")
    }

    /// Consumes the domain as a host.
    #[must_use]
    pub const fn into_host(self) -> Host {
        Host::Name(self)
    }

    /// Returns `true` if this domain is a Fully Qualified Domain Name.
    #[must_use]
    pub fn is_fqdn(&self) -> bool {
        self.0.ends_with('.')
    }

    /// Returns `true` if this domain is a wildcard domain (i.e. its leftmost
    /// label is `"*"`).
    ///
    /// Label-based — agrees with [`Self::as_wildcard_parent`] for inputs like
    /// `".*.example.com"` where a leading FQDN dot precedes the wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.labels().next().is_some_and(Label::is_wildcard)
    }

    /// Returns `true` if this domain is Top-Level [`Domain`] (TLD).
    ///
    /// Note that we consider a country-level TLD (ccTLD) such as `org.uk`
    /// also a TLD. That is we consider any `ccTLD` also `TLD`. While
    /// not technically correct, in practice it is at least for the purposes
    /// that we are aware of a non-meaningful distinction to make.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(Domain::from_static("com").is_tld());
    /// assert!(Domain::from_static(".com").is_tld());
    /// assert!(Domain::from_static("co.uk").is_tld());
    ///
    /// assert!(!Domain::from_static("example.com").is_tld());
    /// assert!(!Domain::from_static("example.co.uk").is_tld());
    /// ```
    #[must_use]
    pub fn is_tld(&self) -> bool {
        self.suffix()
            .map(|s| cmp_domain(&self.0, s).is_eq())
            .unwrap_or_default()
    }

    /// Returns `true` if this domain is Second-Level [`Domain`] (SLD).
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(!Domain::from_static("com").is_sld());
    /// assert!(!Domain::from_static(".com").is_sld());
    /// assert!(!Domain::from_static("co.uk").is_sld());
    /// assert!(!Domain::from_static(".co.uk").is_sld());
    ///
    /// assert!(Domain::from_static(".example.com").is_sld());
    /// assert!(Domain::from_static(".example.co.uk").is_sld());
    ///
    /// assert!(!Domain::from_static("foo.example.com").is_sld());
    /// assert!(!Domain::from_static("foo.example.co.uk").is_sld());
    /// ```
    #[must_use]
    pub fn is_sld(&self) -> bool {
        self.suffix()
            .and_then(|s| self.0.strip_suffix(s))
            .map(|s| {
                let s = s.trim_matches('.');
                !(s.is_empty() || s.contains('.'))
            })
            .unwrap_or_default()
    }

    /// Returns the parent of this wildcard domain, or `None` if `self` is not
    /// a wildcard.
    ///
    /// Equivalent to [`DomainLabels::parent`] when [`Self::is_wildcard`].
    /// Use [`Self::is_wildcard`] alone if you only need the predicate; it
    /// doesn't allocate.
    #[must_use]
    pub fn as_wildcard_parent(&self) -> Option<Self> {
        let mut it = self.labels();
        let first = it.next()?;
        if !first.is_wildcard() {
            return None;
        }
        // Use the trait's `parent`-style rebuild via the builder so the result
        // is a properly-validated Domain (no string slicing).
        let mut b = DomainBuilder::new();
        b.push_labels(it).ok()?;
        b.finish().ok()
    }

    /// Try to create a subdomain from the current [`Domain`] with the given
    /// subdomain prefixed to it.
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] if any segment of `sub` is not a valid label or
    /// the combined name would exceed [`MAX_NAME_LEN`].
    pub fn try_as_sub(&self, sub: impl AsDomainRef) -> Result<Self, PushError> {
        let mut b = DomainBuilder::new();
        b.push_label_segments(sub.domain_as_str())?;
        b.append(self)?;
        b.finish()
    }

    /// Promote this [`Domain`] to a wildcard.
    ///
    /// E.g. turn `example.com` in `*.example.com`.
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] if the resulting name would exceed
    /// [`MAX_NAME_LEN`].
    pub fn try_as_wildcard(&self) -> Result<Self, PushError> {
        let mut b = DomainBuilder::new();
        b.push_label("*")?;
        b.append(self)?;
        b.finish()
    }

    /// Try to strip the subdomain (prefix) from the current domain.
    ///
    /// `prefix` is matched label-by-label, case-insensitively. Returns
    /// `Some(remainder)` if every label of `prefix` matches the corresponding
    /// leftmost label of `self` and at least one label remains; otherwise
    /// `None`.
    ///
    /// # Behavior note
    ///
    /// Prior to the move to label-based matching, this performed a raw
    /// case-sensitive string `strip_prefix`. The current implementation is
    /// label-aware and case-insensitive, which is consistent with the rest
    /// of the type (Eq/Hash/Ord are also case-insensitive).
    pub fn strip_sub(&self, prefix: impl AsDomainRef) -> Option<Self> {
        let prefix_str = prefix.domain_as_str();
        let mut self_labels = self.labels();
        // Walk the prefix label-by-label.
        for prefix_seg in dotted_segments(prefix_str) {
            let self_label = self_labels.next()?;
            if !self_label.as_str().eq_ignore_ascii_case(prefix_seg) {
                return None;
            }
        }
        // Build from the remaining labels directly — no intermediate Vec.
        let mut b = DomainBuilder::new();
        b.push_labels(&mut self_labels).ok()?;
        // At least one label must remain (otherwise the whole domain was
        // stripped and no valid sub-domain is left).
        if b.is_empty() {
            return None;
        }
        b.finish().ok()
    }

    /// Returns `true` if `self` is a sub-domain of (or equal to) `other`.
    ///
    /// Pure delegation to [`DomainLabels::is_subdomain_of`]; kept as an
    /// inherent method for source-compat.
    #[must_use]
    pub fn is_sub_of(&self, other: &Self) -> bool {
        <Self as DomainLabels>::is_subdomain_of(self, other)
    }

    /// Returns `true` if `self` is a parent of (or equal to) `other`.
    #[must_use]
    pub fn is_parent_of(&self, other: &Self) -> bool {
        other.is_sub_of(self)
    }

    /// Compare the registrable domain
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(Domain::from_static("www.example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("example.com")));
    ///
    /// assert!(Domain::from_static("example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("www.example.com")));
    ///
    /// assert!(Domain::from_static("a.example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("b.example.com")));
    ///
    /// assert!(Domain::from_static("example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("example.com")));
    /// ```
    #[must_use]
    pub fn have_same_registrable_domain(&self, other: &Self) -> bool {
        let this_rd = psl::domain_str(self.as_str());
        let other_rd = psl::domain_str(other.as_str());
        this_rd == other_rd
    }

    /// Get the public suffix of the domain
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert_eq!(Some("com"), Domain::from_static("www.example.com").suffix());
    /// assert_eq!(Some("co.uk"), Domain::from_static("site.co.uk").suffix());
    /// ```
    #[must_use]
    pub fn suffix(&self) -> Option<&str> {
        psl::suffix_str(self.as_str())
    }

    /// Gets the length of domain
    #[expect(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Gets the domain name as reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Returns the domain name inner value.
    ///
    /// Should not be exposed in the public rama API.
    pub(crate) fn into_inner(self) -> SmolStr {
        self.0
    }
}

impl std::hash::Hash for Domain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Delegate to per-label hashing so the impl is consistent with
        // PartialEq/Ord (both derived from label iteration). Label::hash is
        // length-prefixed + ASCII-case-folded, so leading/trailing FQDN dots
        // (normalized away by `labels()`) and case differences vanish.
        for label in self.labels() {
            label.hash(state);
        }
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for Domain {
    type Err = DomainParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_domain_str(s)?;
        Ok(Self(SmolStr::new(s)))
    }
}

impl TryFrom<String> for Domain {
    type Error = DomainParseError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        validate_domain_str(&name)?;
        Ok(Self(SmolStr::new(name)))
    }
}

impl<'a> TryFrom<&'a str> for Domain {
    type Error = DomainParseError;

    fn try_from(name: &'a str) -> Result<Self, Self::Error> {
        validate_domain_str(name)?;
        Ok(Self(SmolStr::new(name)))
    }
}

impl<'a> TryFrom<&'a [u8]> for Domain {
    type Error = DomainParseError;

    fn try_from(name: &'a [u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(name).map_err(DomainParseError::non_utf8)?;
        validate_domain_str(s)?;
        Ok(Self(SmolStr::new(s)))
    }
}

impl TryFrom<Vec<u8>> for Domain {
    type Error = DomainParseError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(name).map_err(|e| DomainParseError::non_utf8(e.utf8_error()))?;
        validate_domain_str(&s)?;
        Ok(Self(SmolStr::new(s)))
    }
}

/// Error returned when parsing a string or byte sequence into a [`Domain`]
/// fails.
///
/// Public newtype around a private enum so the variant set can evolve without
/// breaking pattern-matching callers. Convert into a boxed error via
/// `BoxError::from(err)` for the common composition case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainParseError(DomainParseErrorKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainParseErrorKind {
    Empty,
    TooLong { len: usize },
    NonUtf8 { source: std::str::Utf8Error },
    Label { at: usize, error: LabelError },
    BadWildcard { at: usize },
}

impl DomainParseError {
    #[inline]
    fn empty() -> Self {
        Self(DomainParseErrorKind::Empty)
    }
    #[inline]
    fn too_long(len: usize) -> Self {
        Self(DomainParseErrorKind::TooLong { len })
    }
    #[inline]
    fn non_utf8(source: std::str::Utf8Error) -> Self {
        Self(DomainParseErrorKind::NonUtf8 { source })
    }
    #[inline]
    fn label(at: usize, error: LabelError) -> Self {
        Self(DomainParseErrorKind::Label { at, error })
    }
    #[inline]
    fn bad_wildcard(at: usize) -> Self {
        Self(DomainParseErrorKind::BadWildcard { at })
    }
}

impl fmt::Display for DomainParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            DomainParseErrorKind::Empty => f.write_str("empty domain"),
            DomainParseErrorKind::TooLong { len } => {
                write!(f, "domain is {len} bytes long, max is {MAX_NAME_LEN}")
            }
            DomainParseErrorKind::NonUtf8 { source } => {
                write!(f, "domain bytes are not valid UTF-8: {source}")
            }
            DomainParseErrorKind::Label { at, error } => {
                write!(f, "invalid label at index {at}: {error}")
            }
            DomainParseErrorKind::BadWildcard { at } => write!(
                f,
                "'*' wildcard label is only valid at index 0, found at index {at}"
            ),
        }
    }
}

impl std::error::Error for DomainParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            DomainParseErrorKind::Label { error, .. } => Some(error),
            DomainParseErrorKind::NonUtf8 { source } => Some(source),
            _ => None,
        }
    }
}

/// Validate a `&str` as a presentation-format domain.
///
/// Single source of truth for the runtime parse path (`FromStr` / `TryFrom`).
/// Mirrors the const `is_valid_name` used by `from_static`, but reports
/// position info via [`DomainParseError`].
///
/// # Accepted shapes
///
/// - bare: `"example.com"`, `"localhost"`
/// - FQDN: `"example.com."` (trailing dot)
/// - leading-dot: `".example.com"` (matches behaviour of the const path)
/// - wildcard: `"*.example.com"`
/// - leading-dot wildcard: `".*.example.com"` (the leading FQDN dot is
///   stripped before label-walking; equivalent to `"*.example.com"`)
///
/// The bare wildcard label `"*"` is rejected (it must prefix at least one
/// further label), and `"*"` is only valid as the leftmost label.
fn validate_domain_str(s: &str) -> Result<(), DomainParseError> {
    if s.is_empty() {
        return Err(DomainParseError::empty());
    }
    if s.len() > MAX_NAME_LEN {
        return Err(DomainParseError::too_long(s.len()));
    }

    // Normalize leading/trailing FQDN dots away for label walking. Each is
    // optional and at most one.
    let trimmed = s.strip_prefix('.').unwrap_or(s);
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(DomainParseError::empty());
    }

    let mut parts = trimmed.split('.');
    let mut idx = 0usize;
    let mut last_part: Option<&str> = None;
    for part in &mut parts {
        label::validate_label_bytes(part.as_bytes())
            .map_err(|e| DomainParseError::label(idx, e))?;
        // Wildcard label is only valid as the leftmost.
        if part == "*" && idx != 0 {
            return Err(DomainParseError::bad_wildcard(idx));
        }
        last_part = Some(part);
        idx += 1;
    }
    // A bare wildcard ("*" alone) is not a valid domain — it must prefix at
    // least one further label.
    if idx == 1 && last_part == Some("*") {
        return Err(DomainParseError::bad_wildcard(0));
    }
    Ok(())
}

/// Strip leading and trailing FQDN dots, then yield ASCII-lowercased bytes.
///
/// Single helper: split `s` into label-shaped `&str` segments, dropping
/// leading/trailing FQDN dots and any empty segments.
///
/// This is the str-side counterpart to [`DomainLabels::labels`] and is the
/// shared source of truth for every `Domain`↔`str` comparison/hash impl.
/// Unlike `labels()`, it makes no validity claims about each segment — the
/// caller doesn't have to know whether `s` is a real domain.
fn dotted_segments(s: &str) -> impl DoubleEndedIterator<Item = &str> + Clone {
    let s = s.strip_prefix('.').unwrap_or(s);
    let s = s.strip_suffix('.').unwrap_or(s);
    s.split('.').filter(|x| !x.is_empty())
}

/// Compare two label-shaped segment iterators ASCII-case-insensitively.
///
/// Lazily flattens both sides to `(segment_index, byte)` pairs where every
/// "segment break" comes first in `Ord` (so `"a"` < `"aa"`, mirroring stdlib
/// string ordering on the same underlying bytes). Single source of truth via
/// [`label::cmp_ignore_ascii_case`] for the inner per-segment compare.
fn cmp_segments<'a>(
    mut a: impl Iterator<Item = &'a str>,
    mut b: impl Iterator<Item = &'a str>,
) -> Ordering {
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (Some(x), Some(y)) => match label::cmp_ignore_ascii_case(x, y) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            },
        }
    }
}

/// Equal-by-segments, ASCII-case-insensitive.
fn eq_segments<'a>(
    mut a: impl Iterator<Item = &'a str>,
    mut b: impl Iterator<Item = &'a str>,
) -> bool {
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x.eq_ignore_ascii_case(y) => {}
            _ => return false,
        }
    }
}

fn cmp_domain(a: impl AsRef<str>, b: impl AsRef<str>) -> Ordering {
    cmp_segments(dotted_segments(a.as_ref()), dotted_segments(b.as_ref()))
}

impl PartialOrd<Self> for Domain {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Domain {
    fn cmp(&self, other: &Self) -> Ordering {
        // Same primitive as `cmp_domain(self, other)`. Both feed into
        // `cmp_segments`; the Domain side just exposes its labels via the
        // structural iterator rather than re-splitting the buffer.
        cmp_segments(
            self.labels().map(Label::as_str),
            other.labels().map(Label::as_str),
        )
    }
}

impl PartialOrd<str> for Domain {
    fn partial_cmp(&self, other: &str) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for str {
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<&str> for Domain {
    fn partial_cmp(&self, other: &&str) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for &str {
    #[inline(always)]
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<String> for Domain {
    #[inline(always)]
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for String {
    #[inline(always)]
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

fn partial_eq_domain(a: impl AsRef<str>, b: impl AsRef<str>) -> bool {
    eq_segments(dotted_segments(a.as_ref()), dotted_segments(b.as_ref()))
}

impl PartialEq<Self> for Domain {
    fn eq(&self, other: &Self) -> bool {
        eq_segments(
            self.labels().map(Label::as_str),
            other.labels().map(Label::as_str),
        )
    }
}

impl Eq for Domain {}

impl PartialEq<str> for Domain {
    fn eq(&self, other: &str) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<&str> for Domain {
    fn eq(&self, other: &&str) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<Domain> for str {
    fn eq(&self, other: &Domain) -> bool {
        other == self
    }
}

impl PartialEq<Domain> for &str {
    #[inline(always)]
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<String> for Domain {
    #[inline(always)]
    fn eq(&self, other: &String) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<Domain> for String {
    #[inline(always)]
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
    }
}

impl serde::Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Domain {
    /// The maximum length of a domain label.
    const MAX_LABEL_LEN: usize = Label::MAX_LEN;

    /// The maximum length of a domain name.
    const MAX_NAME_LEN: usize = MAX_NAME_LEN;
}

const fn is_valid_label(name: &[u8], start: usize, stop: usize) -> bool {
    if start >= stop
        || stop - start > Domain::MAX_LABEL_LEN
        || name[start] == b'-'
        || start == stop
        || name[stop - 1] == b'-'
    {
        false
    } else {
        let mut i = start;
        while i < stop {
            let c = name[i];
            if !c.is_ascii_alphanumeric() && c != b'_' && (c != b'-' || i == start) {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// Checks if the domain name is valid.
const fn is_valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > Domain::MAX_NAME_LEN {
        false
    } else {
        let mut non_empty_groups = 0;
        let mut i = 0;
        let mut offset = 0;

        // wildcard special case, only needed once
        if name[0] == b'*' {
            if name.len() <= 2 || name[1] != b'.' {
                return false;
            }
            offset = 2;
            i = 2;
            non_empty_groups = 1;
        }

        while i < name.len() {
            let c = name[i];
            if c == b'.' {
                if offset == i {
                    // empty
                    if i == 0 || i == name.len() - 1 {
                        i += 1;
                        offset = i + 1;
                        continue;
                    } else {
                        // double dot not allowed
                        return false;
                    }
                }
                if !is_valid_label(name, offset, i) {
                    return false;
                }
                offset = i + 1;
                non_empty_groups += 1;
            }
            i += 1;
        }
        if offset == i {
            non_empty_groups > 0
        } else {
            is_valid_label(name, offset, i)
        }
    }
}

#[expect(private_bounds)]
/// A trait which is used by the `rama-net` crate
/// for places where we wish to have access to
/// a reference to a Domain, directly or indirectly,
/// for non-move purposes.
///
/// For example to compare it, or use it in a derived form.
pub trait AsDomainRef: seal::AsDomainRefPrivate {
    fn as_wildcard_parent(&self) -> Option<Domain> {
        self.domain_as_str()
            .strip_prefix("*.")
            .and_then(|s| s.parse().ok())
    }

    /// Return an owned [`Domain`].
    ///
    /// For `&'static str` inputs this validates and panics on invalid input
    /// (matching [`Domain::from_static`]); for [`Domain`] it clones cheaply.
    fn to_domain(&self) -> Domain {
        // Safety: domain_as_str is contractually a validated domain string.
        unsafe { Domain::from_maybe_borrowed_unchecked(self.domain_as_str()) }
    }

    /// Return this value in wildcard form (`*.x`).
    ///
    /// If `self` is already a wildcard, an owned copy is returned as-is.
    /// Otherwise this is equivalent to `self.to_domain().try_as_wildcard()`
    /// — i.e. `x` becomes `*.x` (with the usual length cap).
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] if the resulting name would exceed
    /// [`MAX_NAME_LEN`].
    ///
    /// # Panics
    ///
    /// Inherited from [`Self::to_domain`]: for `&'static str` inputs this
    /// panics on invalid domain syntax (matching [`Domain::from_static`]).
    fn to_wildcard(&self) -> Result<Domain, PushError> {
        let d = self.to_domain();
        if d.is_wildcard() {
            Ok(d)
        } else {
            d.try_as_wildcard()
        }
    }

    /// If `self` is already in wildcard form, return it as an owned
    /// [`Domain`]; otherwise return `None`.
    ///
    /// Unlike [`Self::to_wildcard`], this does **not** transform bare inputs
    /// into the wildcard form — use it when you want to know "was this
    /// input already a wildcard?" without doing any conversion.
    fn as_wildcard(&self) -> Option<Domain> {
        let s = self.domain_as_str();
        let trimmed = s.strip_prefix('.').unwrap_or(s);
        trimmed.starts_with("*.").then(|| self.to_domain())
    }
}

impl AsDomainRef for &'static str {}
impl AsDomainRef for Domain {}
impl<T: seal::AsDomainRefPrivate> AsDomainRef for &T {}

/// A trait which can be use by crates where a Domain is expected,
/// it can however only be implemented by the rama-net rate.
pub trait IntoDomain: seal::IntoDomainImpl {}

impl IntoDomain for &'static str {}
impl IntoDomain for Domain {}

pub(super) mod seal {
    pub(in crate::address) trait AsDomainRefPrivate {
        fn domain_as_str(&self) -> &str;
    }

    impl AsDomainRefPrivate for &'static str {
        #[expect(
            clippy::panic,
            reason = "static-str invariant: matches Domain::from_static panicking style"
        )]
        fn domain_as_str(&self) -> &str {
            if !super::is_valid_name(self.as_bytes()) {
                panic!("static str is an invalid domain");
            }
            self
        }
    }

    impl AsDomainRefPrivate for super::Domain {
        fn domain_as_str(&self) -> &str {
            self.as_str()
        }
    }

    impl<T: AsDomainRefPrivate> AsDomainRefPrivate for &T {
        #[inline(always)]
        fn domain_as_str(&self) -> &str {
            (**self).domain_as_str()
        }
    }

    pub trait IntoDomainImpl {
        fn into_domain(self) -> super::Domain;
    }

    impl IntoDomainImpl for &'static str {
        #[inline(always)]
        fn into_domain(self) -> super::Domain {
            super::Domain::from_static(self)
        }
    }

    impl IntoDomainImpl for super::Domain {
        #[inline]
        fn into_domain(self) -> super::Domain {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::{HashMap, HashMapExt as _};

    #[test]
    fn test_specials() {
        assert_eq!(Domain::tld_localhost(), "localhost");
        assert_eq!(Domain::tld_private(), "internal");
        assert_eq!(Domain::example(), "example.com");
    }

    #[test]
    fn test_domain_parse_valid() {
        for str in [
            "example.com",
            "_acme-challenge.example.com",
            "_acme-challenge_.example.com",
            "_acme_challenge_.example.com",
            "www.example.com",
            "*.com", // technically invalid, but valid for us *shrug*
            "*.example.com",
            "a-b-c.com",
            "a-b-c.example.com",
            "a-b-c.example",
            "aA1",
            ".example.com",
            "example.com.",
            ".example.com.",
            "rr5---sn-q4fl6n6s.video.com", // multiple dashes
            "127.0.0.1",
        ] {
            let msg = format!("to parse: {str}");
            assert_eq!(Domain::try_from(str.to_owned()).expect(msg.as_str()), str);
            assert_eq!(
                Domain::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                str
            );
        }
    }

    #[test]
    fn test_domain_is_wildcard() {
        assert!(!Domain::from_static("localhost").is_wildcard());
        assert!(!Domain::from_static("example.com").is_wildcard());
        assert!(!Domain::from_static("foo.example.com").is_wildcard());

        assert!(Domain::from_static("*.com").is_wildcard());
        assert!(Domain::from_static("*.example.com").is_wildcard());
        assert!(Domain::from_static("*.foo.example.com").is_wildcard());
    }

    #[test]
    fn test_domain_as_wildcard_parent() {
        assert!(
            Domain::from_static("localhost")
                .as_wildcard_parent()
                .is_none()
        );
        assert!(
            Domain::from_static("example.com")
                .as_wildcard_parent()
                .is_none()
        );
        assert!(
            Domain::from_static("foo.example.com")
                .as_wildcard_parent()
                .is_none()
        );

        assert_eq!(
            Some(Domain::from_static("com")),
            Domain::from_static("*.com").as_wildcard_parent()
        );
        assert_eq!(
            Some(Domain::from_static("example.com")),
            Domain::from_static("*.example.com").as_wildcard_parent()
        );
        assert_eq!(
            Some(Domain::from_static("foo.example.com")),
            Domain::from_static("*.foo.example.com").as_wildcard_parent()
        );
    }

    #[test]
    fn test_domain_parse_invalid() {
        for str in [
            "",
            ".",
            "..",
            "-",
            "*",
            ".*",
            "*.",
            ".*.",
            ".-",
            "-.",
            ".-.",
            "-.-.",
            "-.-.-",
            ".-.-",
            "2001:db8:3333:4444:5555:6666:7777:8888",
            "-example.com",
            "foo.*.com",
            "*example.com",
            "*foo",
            "o*o",
            "fo*",
            "local!host",
            "thislabeliswaytoolongforbeingeversomethingwewishtocareabout-example.com",
            "example-thislabeliswaytoolongforbeingeversomethingwewishtocareabout.com",
            "こんにちは",
            "こんにちは.com",
            "😀",
            "example..com",
            "example dot com",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(Domain::try_from(str.to_owned()).is_err(), "input = '{str}'");
            assert!(
                Domain::try_from(str.as_bytes().to_vec()).is_err(),
                "input = '{str}'"
            );
        }
    }

    #[test]
    fn is_parent() {
        let test_cases = vec![
            ("www.example.com", "www.example.com"),
            ("www.example.com", "www.example.com."),
            ("www.example.com", ".www.example.com."),
            (".www.example.com", "www.example.com"),
            (".www.example.com", "www.example.com."),
            (".www.example.com.", "www.example.com."),
            ("www.example.com", "WwW.ExamplE.COM"),
            ("example.com", "www.example.com"),
            ("example.com", "m.example.com"),
            ("example.com", "www.EXAMPLE.com"),
            ("example.com", "M.example.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            let a = Domain::from_static(a);
            let b = Domain::from_static(b);
            assert!(a.is_parent_of(&b), "({a:?}).is_parent_of({b})");
        }
    }

    #[test]
    fn as_wildcard_sub() {
        let test_cases = vec![
            ("example.com", "*.example.com"),
            ("fp.ramaproxy.org", "*.fp.ramaproxy.org"),
            ("print.co.uk", "*.print.co.uk"),
        ];
        for (domain_raw, expected_output) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, expected_output));
            let subdomain = domain.try_as_wildcard().expect(&msg);
            assert_eq!(expected_output, subdomain);
            assert!(subdomain.is_wildcard());
            assert_eq!(Some(domain), subdomain.as_wildcard_parent())
        }
    }

    #[test]
    fn as_sub_success() {
        let test_cases = vec![
            ("example.com", "www", "www.example.com"),
            ("fp.ramaproxy.org", "h1", "h1.fp.ramaproxy.org"),
            (
                // long, but just within limit (251+2)
                "dadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
                "a",
                "a.dadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
            ),
        ];
        for (domain_raw, sub, expected_output) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, sub, expected_output));
            let subdomain = domain.try_as_sub(sub).expect(&msg);
            assert_eq!(expected_output, subdomain);
        }
    }

    #[test]
    fn as_sub_failure() {
        let test_cases = vec![
            // too long (254 > 253)
            (
                "adadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
                "a",
            ),
        ];
        for (domain_raw, sub) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, sub));
            _ = domain.try_as_sub(sub).expect_err(&msg);
        }
    }

    #[test]
    fn strip_sub() {
        let test_cases = vec![
            ("www.example.com", "www", Some("example.com")),
            ("example.com", "www", None),
            ("www.www.example.com", "www", Some("www.example.com")),
            // Multi-label prefix.
            ("a.b.example.com", "a.b", Some("example.com")),
            ("a.b.example.com", "a.x", None),
            // Stripping the entire domain returns None (no labels remain).
            ("example.com", "example.com", None),
            // Case-insensitive matching (behavior change in this PR; aligns
            // with Eq/Hash/Ord, which are also case-insensitive).
            ("WWW.example.com", "www", Some("example.com")),
            ("www.example.com", "WWW", Some("example.com")),
        ];
        for (sub_raw, prefix, expected_output) in test_cases.into_iter() {
            let sub = Domain::from_static(sub_raw);
            let result = sub.strip_sub(prefix);
            let expected_result = expected_output.map(Domain::from_static);
            assert_eq!(expected_result, result, "sub={sub_raw} prefix={prefix}");
        }
    }

    #[test]
    fn is_not_parent() {
        let test_cases = vec![
            ("www.example.com", "www.example.co"),
            ("www.example.com", "www.ejemplo.com"),
            ("www.example.com", "www3.example.com"),
            ("w.example.com", "www.example.com"),
            ("gel.com", "kegel.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            let a = Domain::from_static(a);
            let b = Domain::from_static(b);
            assert!(!a.is_parent_of(&b), "!({a:?}).is_parent_of({b})");
        }
    }

    #[test]
    fn is_equal() {
        let test_cases = vec![
            ("example.com", "example.com"),
            ("example.com", "EXAMPLE.com"),
            (".example.com", ".example.com"),
            (".example.com", "example.com"),
            ("example.com", ".example.com"),
            // FQDN trailing dot normalized away
            ("example.com", "example.com."),
            ("example.com.", "example.com"),
            (".example.com.", "example.com"),
            (".example.com", "example.com."),
        ];
        for (a, b) in test_cases.into_iter() {
            assert_eq!(Domain::from_static(a), b);
            assert_eq!(Domain::from_static(a), b.to_owned());
            assert_eq!(Domain::from_static(a), Domain::from_static(b));
            assert_eq!(a, Domain::from_static(b));
            assert_eq!(a.to_owned(), Domain::from_static(b));
        }
    }

    #[test]
    fn is_tld() {
        for (expected, input) in [
            (true, ".com"),
            (true, "com"),
            (true, "co.uk"),
            (true, ".co.uk"),
            (false, "example.com"),
            (false, "foo.uk"),
            (false, "foo.example.com"),
        ] {
            assert_eq!(
                expected,
                Domain::from_static(input).is_tld(),
                "input: {input}"
            )
        }
    }

    #[test]
    fn is_sld() {
        for (expected, input) in [
            (false, "com"),
            (false, "co.uk"),
            (true, "example.com"),
            (true, ".example.com"),
            (true, "foo.uk"),
            (true, ".foo.uk"),
            (false, "foo.example.com"),
        ] {
            assert_eq!(
                expected,
                Domain::from_static(input).is_sld(),
                "input: {input}"
            )
        }
    }

    #[test]
    fn is_not_equal() {
        let test_cases = vec![
            ("example.com", "localhost"),
            ("example.com", "example.co"),
            ("example.com", "examine.com"),
            ("example.com", "example.com.us"),
            ("example.com", "www.example.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            assert_ne!(Domain::from_static(a), b);
            assert_ne!(Domain::from_static(a), b.to_owned());
            assert_ne!(Domain::from_static(a), Domain::from_static(b));
            assert_ne!(a, Domain::from_static(b));
            assert_ne!(a.to_owned(), Domain::from_static(b));
        }
    }

    #[test]
    fn cmp() {
        let test_cases = vec![
            ("example.com", "example.com", Ordering::Equal),
            ("example.com", "EXAMPLE.com", Ordering::Equal),
            (".example.com", ".example.com", Ordering::Equal),
            (".example.com", "example.com", Ordering::Equal),
            ("example.com", ".example.com", Ordering::Equal),
            ("example.com", "localhost", Ordering::Less),
            // FQDN trailing dot normalized away
            ("example.com", "example.com.", Ordering::Equal),
            ("example.com.", "example.com", Ordering::Equal),
            ("example.com", "example.co", Ordering::Greater),
            ("example.com", "examine.com", Ordering::Greater),
            ("example.com", "example.com.us", Ordering::Less),
            ("example.com", "www.example.com", Ordering::Less),
        ];
        for (a, b, expected) in test_cases.into_iter() {
            assert_eq!(Some(expected), Domain::from_static(a).partial_cmp(&b));
            assert_eq!(
                Some(expected),
                Domain::from_static(a).partial_cmp(&b.to_owned())
            );
            assert_eq!(
                Some(expected),
                Domain::from_static(a).partial_cmp(&Domain::from_static(b))
            );
            assert_eq!(
                expected,
                Domain::from_static(a).cmp(&Domain::from_static(b))
            );
            assert_eq!(Some(expected), a.partial_cmp(&Domain::from_static(b)));
            assert_eq!(
                Some(expected),
                a.to_owned().partial_cmp(&Domain::from_static(b))
            );
        }
    }

    #[test]
    fn test_hash() {
        let mut m = HashMap::new();

        assert!(!m.contains_key(&Domain::from_static("example.com")));
        assert!(!m.contains_key(&Domain::from_static("EXAMPLE.COM")));
        assert!(!m.contains_key(&Domain::from_static(".example.com")));
        assert!(!m.contains_key(&Domain::from_static(".example.COM")));

        m.insert(Domain::from_static("eXaMpLe.COm"), ());

        assert!(m.contains_key(&Domain::from_static("example.com")));
        assert!(m.contains_key(&Domain::from_static("EXAMPLE.COM")));
        assert!(m.contains_key(&Domain::from_static(".example.com")));
        assert!(m.contains_key(&Domain::from_static(".example.COM")));
        // FQDN trailing dot normalized away — same key
        assert!(m.contains_key(&Domain::from_static("example.com.")));
        assert!(m.contains_key(&Domain::from_static(".example.com.")));

        assert!(!m.contains_key(&Domain::from_static("www.example.com")));
        assert!(!m.contains_key(&Domain::from_static("examine.com")));
        assert!(!m.contains_key(&Domain::from_static("example.co")));
        assert!(!m.contains_key(&Domain::from_static("example.commerce")));
    }

    #[test]
    fn parse_error_variant_empty() {
        let err = Domain::try_from(String::new()).unwrap_err();
        assert_eq!(format!("{err}"), "empty domain");
        // also for purely-dot input — trims to empty
        let err = Domain::try_from(".".to_owned()).unwrap_err();
        assert_eq!(format!("{err}"), "empty domain");
    }

    #[test]
    fn parse_error_variant_too_long() {
        let too_long = "a".repeat(MAX_NAME_LEN + 1);
        let err = Domain::try_from(too_long).unwrap_err();
        assert!(format!("{err}").contains("max is 253"), "got: {err}");
    }

    #[test]
    fn parse_error_variant_label_at_index() {
        // empty middle label → idx 1
        let err = Domain::try_from("a..b".to_owned()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("index 1"), "msg: {msg}");
        // a label-level Error is exposed via source()
        let src = std::error::Error::source(&err);
        assert!(src.is_some(), "label error should be source-chained");
    }

    #[test]
    fn parse_error_variant_bad_wildcard() {
        // wildcard not at index 0
        let err = Domain::try_from("foo.*.com".to_owned()).unwrap_err();
        assert!(
            format!("{err}").contains("wildcard"),
            "expected wildcard mention: {err}"
        );
        // bare wildcard
        let err = Domain::try_from("*".to_owned()).unwrap_err();
        assert!(
            format!("{err}").contains("wildcard"),
            "expected wildcard mention: {err}"
        );
    }

    #[test]
    fn parse_error_variant_non_utf8() {
        // 0xff is invalid UTF-8 as a starting byte
        let bytes: Vec<u8> = vec![0xff, b'x', b'.', b'c', b'o', b'm'];
        let err = <Domain as TryFrom<Vec<u8>>>::try_from(bytes.clone()).unwrap_err();
        assert!(format!("{err}").contains("UTF-8"), "got: {err}");
        let err = <Domain as TryFrom<&[u8]>>::try_from(bytes.as_slice()).unwrap_err();
        assert!(format!("{err}").contains("UTF-8"), "got: {err}");
    }

    #[test]
    fn parse_error_converts_to_box_error_via_questionmark() {
        fn use_questionmark(s: &str) -> Result<Domain, rama_core::error::BoxError> {
            let d: Domain = s.parse()?;
            Ok(d)
        }
        use_questionmark("example.com").unwrap();
        use_questionmark("").unwrap_err();
    }
}
