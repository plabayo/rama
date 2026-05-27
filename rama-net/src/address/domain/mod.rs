use rama_core::bytes::Bytes;
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
///
/// Storage is `Bytes` so that domain values can share allocations with the
/// buffers they were parsed from (e.g. URI byte buffers) at zero copy cost.
/// The validator only accepts ASCII bytes, so the contents are always valid
/// UTF-8.
#[derive(Debug, Clone)]
pub struct Domain(Bytes);

impl Domain {
    /// Maximum byte length of a fully-qualified domain name (RFC 1035).
    /// Inputs longer than this fail validation.
    pub const MAX_LEN: usize = MAX_NAME_LEN;

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
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// Safety: callee ensures that the given byte/string source is a valid
    /// domain. Useful when we have a buffer that we know came from a Domain
    /// originally (e.g. label-joining helpers, trie key reversal).
    pub(crate) unsafe fn from_maybe_borrowed_unchecked(s: impl Into<Bytes>) -> Self {
        let bytes = s.into();
        debug_assert!(
            is_valid_name(&bytes),
            "from_maybe_borrowed_unchecked called with invalid domain bytes"
        );
        Self(bytes)
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
        self.0.last() == Some(&b'.')
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
            .map(|s| cmp_domain(self.as_str(), s).is_eq())
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
            .and_then(|s| self.as_str().strip_suffix(s))
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
        // Safety: the validator only accepts ASCII bytes, so the contents
        // are always valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }

    /// Borrowed view.
    #[must_use]
    #[inline]
    pub fn view(&self) -> DomainRef<'_> {
        DomainRef::from(self)
    }

    /// Returns the Unicode (display) form of the domain. See
    /// [`DomainRef::as_unicode`] for borrow / allocation behavior.
    #[cfg(feature = "idna")]
    #[cfg_attr(docsrs, doc(cfg(feature = "idna")))]
    #[must_use]
    pub fn as_unicode(&self) -> std::borrow::Cow<'_, str> {
        DomainRef::from(self).as_unicode()
    }
}

/// Borrowed view into a domain-name byte slice.
///
/// The slice is contractually a validated [`Domain`] in presentation form
/// (ASCII A-label) — invariants are enforced wherever `DomainRef` is
/// constructed. Methods always treat the bytes as ASCII (and therefore
/// valid UTF-8).
///
/// Useful for any context where you want a borrowed domain view without
/// committing to an owned [`Domain`] allocation — e.g. iterating zero-copy
/// slices out of a parent buffer, or pattern-matching against a transient
/// header value.
///
/// `PartialEq` / `Eq` / `Hash` / `Ord` / `PartialOrd` are
/// **ASCII-case-insensitive** per RFC 3986 §6.2.2.1 (and §3.2.2 host) —
/// `DomainRef("EXAMPLE.com")` and `DomainRef("example.com")` compare and
/// hash identically. Mirrors the owned [`Domain`]'s semantics so the two
/// types stay interchangeable as collection keys.
#[derive(Debug, Clone, Copy)]
pub struct DomainRef<'a> {
    bytes: &'a [u8],
}

impl<'a> DomainRef<'a> {
    /// Returns the raw bytes (always ASCII).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the domain as a `&str`. ASCII bytes are valid UTF-8 by
    /// construction.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: `DomainRef` is only ever constructed from a validated
        // Domain buffer.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Returns an owned [`Domain`] by copying the underlying bytes.
    /// Named `into_owned` (matching [`std::borrow::Cow::into_owned`]) so it doesn't
    /// shadow the std `ToOwned` trait method.
    #[must_use]
    pub fn into_owned(self) -> Domain {
        let bytes = Bytes::copy_from_slice(self.bytes);
        // Safety: `DomainRef`'s contents are a validated `Domain` in
        // presentation form.
        unsafe { Domain::from_maybe_borrowed_unchecked(bytes) }
    }

    /// Returns the Unicode (display) form of the domain. See
    /// [`Domain::as_unicode`] for the contract.
    #[cfg(feature = "idna")]
    #[cfg_attr(docsrs, doc(cfg(feature = "idna")))]
    #[must_use]
    pub fn as_unicode(&self) -> std::borrow::Cow<'a, str> {
        let s = self.as_str();
        if memchr::memmem::find(s.as_bytes(), b"xn--").is_none() {
            return std::borrow::Cow::Borrowed(s);
        }
        let (unicode, _result) = idna::domain_to_unicode(s);
        std::borrow::Cow::Owned(unicode)
    }
}

impl<'a> From<&'a Domain> for DomainRef<'a> {
    fn from(d: &'a Domain) -> Self {
        Self { bytes: &d.0 }
    }
}

// ---- ASCII-case-insensitive Eq / Hash / Ord (parallels `Domain`) ----------
//
// Driven by the same `dotted_segments` + per-label case-fold helpers
// that `Domain` uses, so a borrowed view and its owned counterpart are
// fully interchangeable as collection keys / sort keys / equality
// witnesses. No allocation — the segment iterator borrows from the
// existing `&str` view.

impl PartialEq for DomainRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        eq_segments(
            dotted_segments(self.as_str()),
            dotted_segments(other.as_str()),
        )
    }
}

impl Eq for DomainRef<'_> {}

impl Ord for DomainRef<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_segments(
            dotted_segments(self.as_str()),
            dotted_segments(other.as_str()),
        )
    }
}

impl PartialOrd for DomainRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for DomainRef<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Match `Domain`'s per-label hash exactly so the two types
        // produce identical byte streams for identical content:
        // for each label `len_usize` + `byte_lower` per byte.
        for seg in dotted_segments(self.as_str()) {
            state.write_usize(seg.len());
            for b in seg.bytes() {
                state.write_u8(b.to_ascii_lowercase());
            }
        }
    }
}

impl fmt::Display for DomainRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ASCII presentation form — `as_unicode` handles IDN decoding.
        f.write_str(self.as_str())
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
        self.as_str()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Domain {
    type Err = DomainParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Domain {
    type Error = DomainParseError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        // Fast-path: already ASCII → reuse the input buffer.
        if name.is_ascii() {
            validate_domain_str(&name)?;
            return Ok(Self(Bytes::from(name.into_bytes())));
        }
        let ace = idn_to_ascii(&name)?;
        validate_domain_str(&ace)?;
        Ok(Self(Bytes::from(ace.into_bytes())))
    }
}

impl<'a> TryFrom<&'a str> for Domain {
    type Error = DomainParseError;

    fn try_from(name: &'a str) -> Result<Self, Self::Error> {
        if name.is_ascii() {
            validate_domain_str(name)?;
            return Ok(Self(Bytes::copy_from_slice(name.as_bytes())));
        }
        let ace = idn_to_ascii(name)?;
        validate_domain_str(&ace)?;
        Ok(Self(Bytes::from(ace.into_bytes())))
    }
}

impl<'a> TryFrom<&'a [u8]> for Domain {
    type Error = DomainParseError;

    fn try_from(name: &'a [u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(name).map_err(DomainParseError::non_utf8)?;
        Self::try_from(s)
    }
}

impl TryFrom<Vec<u8>> for Domain {
    type Error = DomainParseError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(&name).map_err(DomainParseError::non_utf8)?;
        if s.is_ascii() {
            validate_domain_str(s)?;
            return Ok(Self(Bytes::from(name)));
        }
        let ace = idn_to_ascii(s)?;
        validate_domain_str(&ace)?;
        Ok(Self(Bytes::from(ace.into_bytes())))
    }
}

/// Convert a non-ASCII domain string to its ASCII-Compatible Encoding
/// (ACE / Punycode) via UTS #46 non-transitional processing.
///
/// Caller MUST have already checked that `input` contains non-ASCII —
/// this isn't a fast-path optimisation, it's the explicit IDN entry
/// point. Returns an error if the `idna` feature is off, or if UTS #46
/// rejects the input.
fn idn_to_ascii(input: &str) -> Result<String, DomainParseError> {
    #[cfg(feature = "idna")]
    {
        idna::domain_to_ascii(input).map_err(|_e| DomainParseError::idna_processing())
    }
    #[cfg(not(feature = "idna"))]
    {
        let _ = input;
        Err(DomainParseError::idna_not_enabled())
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
    TooLong {
        len: usize,
    },
    NonUtf8 {
        source: std::str::Utf8Error,
    },
    Label {
        at: usize,
        error: LabelError,
    },
    BadWildcard {
        at: usize,
    },
    /// The input bytes form an IP-literal in URI authority syntax
    /// (bracketed `[...]`, e.g. an IPvFuture literal). IP-literals
    /// are a distinct grammatical category from domains — produced
    /// when converting from
    /// [`UninterpretedHost`](crate::address::UninterpretedHost) that
    /// preserved a bracketed host.
    BracketedIpLiteral,
    /// UTS #46 IDN processing rejected the input (e.g. disallowed
    /// codepoints, bidi violations). Only produced when the `idna`
    /// feature is on.
    #[cfg(feature = "idna")]
    IdnaProcessing,
    /// Non-ASCII bytes were supplied but the `idna` feature is off.
    #[cfg(not(feature = "idna"))]
    IdnaNotEnabled,
}

impl DomainParseError {
    #[inline]
    const fn empty() -> Self {
        Self(DomainParseErrorKind::Empty)
    }
    #[inline]
    const fn too_long(len: usize) -> Self {
        Self(DomainParseErrorKind::TooLong { len })
    }
    #[inline]
    fn non_utf8(source: std::str::Utf8Error) -> Self {
        Self(DomainParseErrorKind::NonUtf8 { source })
    }
    #[inline]
    const fn label(at: usize, error: LabelError) -> Self {
        Self(DomainParseErrorKind::Label { at, error })
    }
    #[inline]
    const fn bad_wildcard(at: usize) -> Self {
        Self(DomainParseErrorKind::BadWildcard { at })
    }
    #[inline]
    pub(crate) const fn bracketed_ip_literal() -> Self {
        Self(DomainParseErrorKind::BracketedIpLiteral)
    }
    #[cfg(feature = "idna")]
    #[inline]
    fn idna_processing() -> Self {
        Self(DomainParseErrorKind::IdnaProcessing)
    }
    #[cfg(not(feature = "idna"))]
    #[inline]
    fn idna_not_enabled() -> Self {
        Self(DomainParseErrorKind::IdnaNotEnabled)
    }

    /// `true` if the failure is the "input requires IDNA but the
    /// `idna` feature is off" case. Lets callers (e.g. the URI parser)
    /// surface a more specific top-level error. Always `false` when the
    /// `idna` feature is enabled.
    #[must_use]
    pub fn is_idna_not_enabled(&self) -> bool {
        #[cfg(not(feature = "idna"))]
        {
            matches!(self.0, DomainParseErrorKind::IdnaNotEnabled)
        }
        #[cfg(feature = "idna")]
        {
            false
        }
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
            DomainParseErrorKind::BracketedIpLiteral => {
                f.write_str("bracketed IP-literal is not a domain")
            }
            #[cfg(feature = "idna")]
            DomainParseErrorKind::IdnaProcessing => {
                f.write_str("IDN domain rejected by UTS #46 processing")
            }
            #[cfg(not(feature = "idna"))]
            DomainParseErrorKind::IdnaNotEnabled => {
                f.write_str("non-ASCII domain requires the `idna` feature")
            }
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

/// Validate a `&[u8]` as a presentation-format domain.
///
/// **Single source of truth** for every Domain validity decision. Both the
/// compile-time entry point ([`Domain::from_static`]) and the runtime parse
/// path ([`Domain::try_from`]) call through this; the bool-returning
/// [`is_valid_name`] and the str-taking [`validate_domain_str`] are thin
/// wrappers.
///
/// Keeping the algorithm in one place is the fix for a class of
/// fuzz-found bugs where two near-identical validators drifted (the URI
/// parser validated via `try_from` and then deref'd via
/// `from_maybe_borrowed_unchecked`, whose debug-assert called the
/// const validator — divergence panicked).
///
/// # Accepted shapes
///
/// - bare: `b"example.com"`, `b"localhost"`
/// - FQDN: `b"example.com."` (one trailing dot)
/// - leading-dot: `b".example.com"`
/// - wildcard (leftmost only): `b"*.example.com"`
/// - leading-dot wildcard: `b".*.example.com"` — the leading FQDN dot is
///   consumed before the wildcard check
///
/// The bare wildcard `b"*"` is rejected (it must prefix at least one
/// further label).
///
/// # Const-fn constraints
///
/// `?` and slice equality (`==`) are not stable in const fn yet, so the
/// body uses explicit `match` for label results and length-plus-first-byte
/// for the wildcard compare.
const fn validate_domain_bytes(name: &[u8]) -> Result<(), DomainParseError> {
    if name.is_empty() {
        return Err(DomainParseError::empty());
    }
    // RFC 1035 §2.3.4: the wire-format max is 255 octets and the
    // presentation-form max is 253 octets *exclusive* of the optional
    // trailing FQDN dot. Counting the dot would reject otherwise legal
    // FQDN-form input like `example.com.` of length 254.
    //
    // Regression: `tests::regression_domain_fqdn_trailing_dot_length`.
    let last = name[name.len() - 1];
    let effective_len = if last == b'.' {
        name.len() - 1
    } else {
        name.len()
    };
    if effective_len > MAX_NAME_LEN {
        return Err(DomainParseError::too_long(name.len()));
    }

    // Skip at most one leading FQDN dot and at most one trailing FQDN
    // dot. The label-walking loop below operates on the inner range
    // `[start, stop)`.
    let start = if name[0] == b'.' { 1 } else { 0 };
    let stop = if last == b'.' && name.len() > 1 {
        name.len() - 1
    } else {
        name.len()
    };
    if start >= stop {
        // Input was just "." or "..".
        return Err(DomainParseError::empty());
    }

    // Walk labels by indexing into `name[start..stop]`. `idx` counts
    // non-empty labels (0-based) and is what error reporting uses.
    let mut idx: usize = 0;
    let mut label_start = start;
    let mut leftmost_was_wildcard = false;
    let mut i = start;
    while i <= stop {
        if i == stop || name[i] == b'.' {
            // Label byte-range is name[label_start..i].
            if label_start == i {
                // Mid-name empty label (double-dot inside the trimmed
                // range). Leading and trailing FQDN dots were already
                // consumed by `start` / `stop`.
                return Err(DomainParseError::label(idx, LabelError::empty()));
            }
            // Validate the label bytes via the shared const validator.
            // `name.split_at(...)` is the const-stable way to subslice;
            // direct indexing `&name[start..end]` still needs the
            // `Index` trait to be const, which it isn't.
            let (_, after_start) = name.split_at(label_start);
            let (label, _) = after_start.split_at(i - label_start);
            // Manual match because `?` isn't stable in const fn yet.
            match label::validate_label_bytes(label) {
                Ok(()) => {}
                Err(e) => return Err(DomainParseError::label(idx, e)),
            }
            // Wildcard `*` is only valid as the leftmost label.
            if label.len() == 1 && label[0] == b'*' {
                if idx != 0 {
                    return Err(DomainParseError::bad_wildcard(idx));
                }
                leftmost_was_wildcard = true;
            }
            label_start = i + 1;
            idx += 1;
            if i == stop {
                break;
            }
        }
        i += 1;
    }

    // Bare wildcard (`*` or `.*` or `*.`) — no parent label.
    if leftmost_was_wildcard && idx == 1 {
        return Err(DomainParseError::bad_wildcard(0));
    }
    Ok(())
}

/// Bool-returning const wrapper used by [`Domain::from_static`] and
/// the debug-assert in [`Domain::from_maybe_borrowed_unchecked`].
const fn is_valid_name(name: &[u8]) -> bool {
    matches!(validate_domain_bytes(name), Ok(()))
}

/// Str-returning runtime wrapper used by every `TryFrom` impl. Just
/// dispatches to the byte validator — keeping both surfaces honest by
/// construction.
fn validate_domain_str(s: &str) -> Result<(), DomainParseError> {
    validate_domain_bytes(s.as_bytes())
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
        self.as_str().serialize(serializer)
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
        unsafe {
            Domain::from_maybe_borrowed_unchecked(Bytes::copy_from_slice(
                self.domain_as_str().as_bytes(),
            ))
        }
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
            // The following are invalid only when the `idna` feature is off
            // (under it they're UTS #46-processed into valid ACE forms).
            #[cfg(not(feature = "idna"))]
            "こんにちは",
            #[cfg(not(feature = "idna"))]
            "こんにちは.com",
            #[cfg(not(feature = "idna"))]
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
    fn domain_and_domainref_hash_identically() {
        // Owned and borrowed must hash equal so they're interchangeable
        // as collection keys.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as _, Hasher};

        for name in ["example.com", "EXAMPLE.com", "sub.example.com", "x.y"] {
            let owned = Domain::from_static(name);
            let borrowed = DomainRef::from(&owned);

            let mut ho = DefaultHasher::new();
            owned.hash(&mut ho);
            let mut hb = DefaultHasher::new();
            borrowed.hash(&mut hb);
            assert_eq!(ho.finish(), hb.finish(), "hash mismatch for {name:?}");
        }
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

    /// Regression: RFC 1035 §2.3.4 caps the presentation-form length at 253
    /// octets *exclusive* of the optional trailing FQDN dot. Previously the
    /// length check compared `s.len()` directly to 253, which rejected
    /// legitimate FQDN-form input like `a...a.` of length 254.
    #[test]
    fn regression_domain_fqdn_trailing_dot_length() {
        // Build a 253-octet presentation-form domain: four labels (63, 63,
        // 62, 62) joined by three dots → 63+63+62+62+3 = 253 octets.
        let l63 = "a".repeat(63);
        let l62 = "a".repeat(62);
        let prefix = format!("{l63}.{l63}.{l62}.{l62}");
        assert_eq!(prefix.len(), 253);
        // No trailing dot: still accepted.
        Domain::try_from(prefix.clone()).unwrap();
        // With trailing dot (FQDN form), total bytes = 254, still accepted.
        let fqdn = format!("{prefix}.");
        assert_eq!(fqdn.len(), 254);
        Domain::try_from(fqdn)
            .expect("FQDN with trailing dot should be accepted at 254 octets total");
        // But 254 effective octets (no trailing dot) is rejected.
        let too_long = format!("{prefix}c");
        assert_eq!(too_long.len(), 254);
        Domain::try_from(too_long).unwrap_err();
    }

    /// Regression: `is_valid_name` (the const validator behind
    /// `from_static` / `from_maybe_borrowed_unchecked`) used to disagree
    /// with `validate_domain_str` (the public-API validator behind
    /// `try_from`) on two leading-dot shapes — `.A` and `.*.k`. The URI
    /// parser validates via `try_from` and dereferences via
    /// `from_maybe_borrowed_unchecked`, so the divergence surfaced as a
    /// debug-assert panic in `from_maybe_borrowed_unchecked`. Both
    /// inputs were found by the `uri_parse` / `uri_resolve` fuzz targets.
    #[test]
    fn regression_domain_const_validator_matches_public_validator() {
        for input in [
            ".A",     // leading-dot single label
            ".*.k",   // leading-dot wildcard
            ".com",   // leading-dot TLD (was accidentally working pre-fix)
            ".com.",  // leading + trailing dot
            "*.x",    // bare wildcard
            "A",      // single label, no dots
            "com.uk", // ordinary multi-label
        ] {
            Domain::try_from(input)
                .unwrap_or_else(|e| panic!("try_from({input:?}) rejected unexpectedly: {e}"));
            // `from_static` exercises `is_valid_name` — must agree.
            // `let _ =` would discard the must-use value; bind to a
            // suppression name instead so clippy is happy.
            let _domain = Domain::from_static(input);
        }
        // Mirror the URI-parser paths that originally hit the panic.
        let uri: crate::uri::Uri = "k://.A/".parse().unwrap();
        assert_eq!(uri.host().unwrap().to_str(), ".A");
        let uri: crate::uri::Uri = "k://.*.k".parse().unwrap();
        assert_eq!(uri.host().unwrap().to_str(), ".*.k");
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
