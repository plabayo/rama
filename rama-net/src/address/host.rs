use super::domain::{DomainLabelIter, DomainLabels, Label};
use super::{Domain, UninterpretedHost, UninterpretedHostRef, parse_utils};
use crate::address::ip::{
    IPV4_BROADCAST, IPV4_LOCALHOST, IPV4_UNSPECIFIED, IPV6_LOCALHOST, IPV6_UNSPECIFIED,
};
use rama_core::error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "http")]
use rama_http_types::HeaderValue;

/// Either a [`Domain`], an [`IpAddr`], or [`UninterpretedHost`] bytes
/// preserved verbatim from a URI authority.
///
/// `Uninterpreted` covers the RFC 3986 host shapes that aren't a strict
/// DNS-label-shaped [`Domain`] or a recognized IP address — pct-encoded
/// `reg-name` (`exa%6Dple.com`), sub-delim hostnames (`tag,with,commas`),
/// IPvFuture literals (`[vN.X]`), and raw UTF-8 host bytes preserved
/// under graceful URI / IRI parsing. The variant exists so a proxy
/// receiving wire bytes can forward them faithfully; callers needing a
/// canonical typed form convert via the `TryFrom` impls on
/// [`UninterpretedHost`].
///
/// Equality, hashing, and ordering bridge across variant boundaries per
/// RFC 3986 §6.2.2.2: see [`HostRef`]'s type-level docs.
///
/// # Empty Uninterpreted host
///
/// RFC 3986 §3.2.2 `reg-name = *(...)` permits empty bytes, so URIs like
/// `file:///path` or `unix:///run/x` parse with `Host::Uninterpreted(b"")`.
/// This is URI-valid but **not network-valid** — protocol writers that
/// have no representation for "no host" (SOCKS5, TLS SNI, HTTP `Host:`)
/// will refuse it. Code dispatching a `Host` onto a network call must
/// either reject the empty case or substitute a sensible default.
///
/// # Alternate IPv4 forms (SSRF awareness)
///
/// Inputs that look like IP addresses but aren't accepted by Rust's
/// `Ipv4Addr::from_str` — octal (`0177.0.0.1`), hex (`0x7f.0.0.1`),
/// 3-part (`127.0.1`), and integer (`2130706433`) — parse as
/// [`Host::Name(Domain)`](Self::Name) rather than
/// [`Host::Address`](Self::Address), because each label is digit-only
/// and passes the DNS-label byte set. This is RFC 3986 compliant (the
/// strings *are* reg-names under §3.2.2) but **diverges from
/// browsers**, which normalise all four to `127.0.0.1`.
///
/// **SSRF caveat**: code that filters destination addresses on
/// `Host::Address` will see `0177.0.0.1` as a `Name` and bypass
/// IP-based allowlists / blocklists. Either:
///
/// - resolve through DNS (loopback returns naturally) before applying
///   the filter, OR
/// - reject any `Name` whose labels look digit-only at the policy
///   layer, OR
/// - call [`crate::uri::Uri::canonicalize`] first — it doesn't promote
///   these to `Address` (Rust's strict parser still rejects), so this
///   is informational rather than a fix.
///
/// # Why `#[non_exhaustive]`
///
/// Variant matching is a footgun on this type: a [`Domain`] can live
/// in `Name` *or* in `Uninterpreted` (pct-encoded bytes that decode
/// to a domain), and an [`IpAddr`] can live in `Address` *or* in
/// `Uninterpreted` (pct-encoded dotted-quad). External callers that
/// pattern-match on the variant tag will miss the bridged forms.
/// Use [`try_as_domain`](Self::try_as_domain) /
/// [`try_as_ip`](Self::try_as_ip) (and the `try_into_*` consuming
/// counterparts) which bridge across variants.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Host {
    /// A DNS-label-shaped name (ASCII, IDN normalised to ACE on
    /// construction via [`Domain::try_from`]).
    Name(Domain),

    /// A literal IPv4 or IPv6 address.
    Address(IpAddr),

    /// Host bytes preserved verbatim. See [`UninterpretedHost`].
    Uninterpreted(UninterpretedHost),
}

impl Host {
    /// Returns `true` if this is the [`Host::Name`] variant.
    /// View as a [`Domain`], bridging the `Uninterpreted` variant.
    /// `Cow::Borrowed` for `Name`; `Cow::Owned` for an `Uninterpreted`
    /// whose pct-decoded (and IDN-normalized) bytes parse as a domain.
    /// `Address` and IPvFuture-bracketed `Uninterpreted` fail.
    pub fn try_as_domain(&self) -> Result<std::borrow::Cow<'_, Domain>, BoxError> {
        match self {
            Self::Name(d) => Ok(std::borrow::Cow::Borrowed(d)),
            Self::Address(_) => Err(rama_core::error::extra::OpaqueError::from_static_str(
                "Host::Address is not a Domain",
            )
            .into_box_error()),
            Self::Uninterpreted(host) => Domain::try_from(host)
                .map(std::borrow::Cow::Owned)
                .map_err(Into::into),
        }
    }

    /// Consuming form of [`try_as_domain`](Self::try_as_domain).
    pub fn try_into_domain(self) -> Result<Domain, BoxError> {
        match self {
            Self::Name(d) => Ok(d),
            Self::Address(_) => Err(rama_core::error::extra::OpaqueError::from_static_str(
                "Host::Address is not a Domain",
            )
            .into_box_error()),
            Self::Uninterpreted(ref host) => Domain::try_from(host).map_err(Into::into),
        }
    }

    /// View as an [`IpAddr`], bridging the `Uninterpreted` variant.
    /// Returns the address from `Address` directly; `Uninterpreted`
    /// succeeds when its pct-decoded bytes parse as an IPv4 or IPv6
    /// address. `Name` and IPvFuture-bracketed `Uninterpreted` fail.
    pub fn try_as_ip(&self) -> Result<IpAddr, BoxError> {
        match self {
            Self::Address(ip) => Ok(*ip),
            Self::Name(_) => Err(rama_core::error::extra::OpaqueError::from_static_str(
                "Host::Name is not an IpAddr",
            )
            .into_box_error()),
            Self::Uninterpreted(host) => IpAddr::try_from(host).map_err(Into::into),
        }
    }

    /// Borrowed view. Same shape as `From<&Self> for HostRef` but
    /// surfaces the borrowed view as an inherent method so call sites
    /// don't need the trait in scope.
    #[must_use]
    #[inline]
    pub fn view(&self) -> HostRef<'_> {
        HostRef::from(self)
    }

    /// Returns this host as a string. See [`HostRef::to_str`] for the
    /// borrow / allocation behavior.
    #[must_use]
    pub fn to_str(&self) -> std::borrow::Cow<'_, str> {
        HostRef::from(self).to_str()
    }

    /// Returns the Unicode (display) form of this host. For named hosts,
    /// any `xn--` A-labels are inverse-encoded via UTS #46. IP addresses
    /// are rendered to their standard textual form.
    ///
    /// `Cow::Borrowed` when no conversion is needed; `Cow::Owned` for
    /// IP addresses and IDN A-labels that actually require decoding.
    #[cfg(feature = "idna")]
    #[cfg_attr(docsrs, doc(cfg(feature = "idna")))]
    #[must_use]
    pub fn as_unicode(&self) -> std::borrow::Cow<'_, str> {
        HostRef::from(self).as_unicode()
    }

    /// Returns `true` if this host designates the local machine via
    /// loopback. See [`HostRef::is_loopback`] for the full contract.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        HostRef::from(self).is_loopback()
    }
}

impl Host {
    /// Compile-time constructor for a [`Domain`]-shaped host. Panics
    /// at compile time when `s` isn't a valid domain.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        Self::Name(Domain::from_static(s))
    }

    /// Local loopback address (IPv4)
    pub const LOCALHOST_IPV4: Self = Self::Address(IPV4_LOCALHOST);

    /// Local loopback address (IPv6)
    pub const LOCALHOST_IPV6: Self = Self::Address(IPV6_LOCALHOST);

    /// Local loopback name
    pub const LOCALHOST_NAME: Self = Self::Name(Domain::from_static("localhost"));

    /// Default address, not routable
    pub const DEFAULT_IPV4: Self = Self::Address(IPV4_UNSPECIFIED);

    /// Default address, not routable (IPv6)
    pub const DEFAULT_IPV6: Self = Self::Address(IPV6_UNSPECIFIED);

    /// Broadcast address (IPv4)
    pub const BROADCAST_IPV4: Self = Self::Address(IPV4_BROADCAST);

    /// `example.com` domain name
    pub const EXAMPLE_NAME: Self = Self::Name(Domain::from_static("example.com"));
}

/// Borrowed view of a [`Host`].
///
/// Either a [`DomainRef`](super::domain::DomainRef) borrowing into the source
/// buffer or an [`IpAddr`] (which is `Copy` and so always carried by value).
///
/// Useful anywhere a borrowed host view makes sense — URI host components,
/// header-parse temporaries, DNS lookups against a non-owning buffer.
///
/// # Equality, hashing, ordering
///
/// RFC 3986 §6.2.2 syntactic equivalence applies across variants. A
/// non-bracketed [`HostRef::Uninterpreted`] whose bytes pct-decode
/// (and IDN-normalize) to a typed [`Domain`] compares, hashes, and
/// orders equal to the corresponding [`HostRef::Name`]; same for a
/// pct-encoded reg-name that decodes to an [`IpAddr`] vs
/// [`HostRef::Address`]. Bracketed `Uninterpreted` (IPvFuture) keeps
/// its own equality class — there's no typed counterpart to bridge to.
/// `#[non_exhaustive]` for the same reason as [`Host`] — bridging
/// `Uninterpreted` to typed variants is what callers usually want;
/// pattern-matching on the tag misses the bridged forms.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HostRef<'a> {
    /// A DNS-style name.
    Name(super::domain::DomainRef<'a>),
    /// A literal IPv4 or IPv6 address.
    Address(IpAddr),
    /// Borrowed view of an [`UninterpretedHost`] — reg-name bytes
    /// preserved verbatim or a bracketed IP-literal.
    Uninterpreted(UninterpretedHostRef<'a>),
}

impl<'a> HostRef<'a> {
    /// Returns this host as a string. Domain names and non-bracketed
    /// reg-names return `Cow::Borrowed` (no allocation); IP addresses
    /// and bracketed IP-literals are formatted into a fresh `String`.
    #[must_use]
    pub fn to_str(self) -> std::borrow::Cow<'a, str> {
        match self {
            Self::Name(d) => d.as_str().into(),
            Self::Address(ip) => ip.to_string().into(),
            Self::Uninterpreted(host) if host.is_bracketed() => host.to_string().into(),
            Self::Uninterpreted(host) => host.as_str().into(),
        }
    }

    /// Returns the Unicode (display) form of this host. See
    /// [`Host::as_unicode`] for the full contract.
    #[cfg(feature = "idna")]
    #[cfg_attr(docsrs, doc(cfg(feature = "idna")))]
    #[must_use]
    pub fn as_unicode(self) -> std::borrow::Cow<'a, str> {
        match self {
            Self::Name(d) => d.as_unicode(),
            Self::Address(ip) => ip.to_string().into(),
            Self::Uninterpreted(host) if host.is_bracketed() => host.to_string().into(),
            Self::Uninterpreted(host) => host.as_unicode(),
        }
    }

    /// Returns `true` if this host designates the local machine via
    /// loopback — either a loopback IP address (`127.0.0.0/8` or `::1`,
    /// per [`IpAddr::is_loopback`]) or the RFC 6761 §6.3 `localhost`
    /// name (`localhost` itself or any `*.localhost` subdomain,
    /// case-insensitively).
    ///
    /// The [`Uninterpreted`](Self::Uninterpreted) variant is bridged
    /// through its pct-decoded form: bytes that decode to a loopback IP
    /// or the `localhost` name also return `true`. Bracketed IPvFuture
    /// literals have no typed counterpart and are never loopback.
    ///
    /// This is **not** browser-style normalization: alternate IPv4
    /// spellings that parse as a [`Name`](Self::Name) (`0177.0.0.1`,
    /// `2130706433`, …) report as non-loopback — see the [`Host`] type
    /// docs (SSRF awareness). IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
    /// follows std and is likewise not loopback.
    #[must_use]
    pub fn is_loopback(self) -> bool {
        match self {
            Self::Address(ip) => ip.is_loopback(),
            Self::Name(domain) => domain.is_loopback(),
            // Bridge pct-encoded / alternate bytes through their decoded
            // form, decoded once: a loopback IP literal, else the
            // `localhost` name. `as_unicode` borrows when there's no `%`,
            // so the common path doesn't allocate. Bracketed IPvFuture
            // parses as neither and is not loopback.
            Self::Uninterpreted(host) => {
                let decoded = host.as_unicode();
                decoded
                    .parse::<IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or_else(|_| super::domain::is_loopback_name(&decoded))
            }
        }
    }

    /// Returns an owned [`Host`] containing a copy of the underlying bytes
    /// (or, for the IP variants, a copy of the address value). Named
    /// `into_owned` (matching [`std::borrow::Cow::into_owned`]) so it doesn't shadow
    /// the std `ToOwned` trait method.
    #[must_use]
    pub fn into_owned(self) -> Host {
        match self {
            Self::Name(d) => Host::Name(d.into_owned()),
            Self::Address(ip) => Host::Address(ip),
            Self::Uninterpreted(host) => Host::Uninterpreted(host.into_owned()),
        }
    }

    /// Bridging accessor. Returns an owned [`Domain`] — unlike the
    /// `Host::try_as_domain` `Cow`-returning variant, the borrowed view
    /// has no `Domain` to lend (it carries a
    /// [`DomainRef`](super::domain::DomainRef)), so this always
    /// materializes an owned value.
    pub fn try_as_domain(self) -> Result<Domain, BoxError> {
        match self {
            Self::Name(d) => Ok(d.into_owned()),
            Self::Address(_) => Err(rama_core::error::extra::OpaqueError::from_static_str(
                "HostRef::Address is not a Domain",
            )
            .into_box_error()),
            Self::Uninterpreted(host) => Domain::try_from(host).map_err(Into::into),
        }
    }

    /// Bridging accessor. See [`Host::try_as_ip`].
    pub fn try_as_ip(self) -> Result<IpAddr, BoxError> {
        match self {
            Self::Address(ip) => Ok(ip),
            Self::Name(_) => Err(rama_core::error::extra::OpaqueError::from_static_str(
                "HostRef::Name is not an IpAddr",
            )
            .into_box_error()),
            Self::Uninterpreted(host) => IpAddr::try_from(host).map_err(Into::into),
        }
    }
}

impl<'a> From<&'a Host> for HostRef<'a> {
    fn from(h: &'a Host) -> Self {
        match h {
            Host::Name(d) => Self::Name(d.into()),
            Host::Address(ip) => Self::Address(*ip),
            Host::Uninterpreted(host) => Self::Uninterpreted(host.into()),
        }
    }
}

impl PartialEq<str> for Host {
    /// ASCII-case-insensitive compare against a string, matching
    /// [`Domain`] / `Uri` / `Eq for Host` (RFC 3986 §6.2.2.1).
    fn eq(&self, other: &str) -> bool {
        match self {
            // `Domain == &str` is already case-insensitive (matches
            // `Domain::Eq` itself); delegate.
            Self::Name(domain) => domain == other,
            // Compare via address parsing rather than `ip.to_string()`, so
            // we avoid allocating a `String` on every comparison *and*
            // canonicalize the right-hand side (e.g. `"::1"` and
            // `"0:0:0:0:0:0:0:1"` are equal, `"127.0.0.001"` is not equal
            // to `127.0.0.1` because std rejects leading-zero octets).
            // `IpAddr::parse` accepts mixed case for IPv6 (`FE80::1` ==
            // `fe80::1`) and IPv4 is digits-only, so case-insensitivity
            // is satisfied for free.
            Self::Address(ip) => other.parse::<IpAddr>().is_ok_and(|parsed| parsed == *ip),
            Self::Uninterpreted(host) if host.is_bracketed() => {
                // Bracketed forms (e.g. `[v1.fe80::a]`) store bytes
                // without the surrounding brackets. Strip the brackets
                // from `other` and ASCII-case-fold the inside — no
                // allocation, no `to_string()`.
                let o = other.as_bytes();
                o.len() >= 2
                    && o[0] == b'['
                    && o[o.len() - 1] == b']'
                    && rama_utils::str::eq_ignore_ascii_case(&o[1..o.len() - 1], host.as_bytes())
            }
            Self::Uninterpreted(host) => {
                // Fast path — case-insensitive byte compare on the raw
                // wire form.
                let bytes = host.as_bytes();
                if rama_utils::str::eq_ignore_ascii_case(bytes, other.as_bytes()) {
                    return true;
                }
                // Semantic path — when pct-encoding is present, the
                // decoded form might match (case-insensitively). Only
                // allocate when there's actually `%` to decode.
                if bytes.contains(&b'%')
                    && let s = host.as_unicode()
                    && rama_utils::str::eq_ignore_ascii_case(
                        s.as_ref().as_bytes(),
                        other.as_bytes(),
                    )
                {
                    return true;
                }
                false
            }
        }
    }
}

impl PartialEq<Host> for str {
    fn eq(&self, other: &Host) -> bool {
        other == self
    }
}

impl PartialEq<&str> for Host {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<Host> for &str {
    #[inline(always)]
    fn eq(&self, other: &Host) -> bool {
        other == *self
    }
}

impl PartialEq<String> for Host {
    #[inline(always)]
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<Host> for String {
    fn eq(&self, other: &Host) -> bool {
        other == self.as_str()
    }
}

impl PartialEq<Ipv4Addr> for Host {
    fn eq(&self, other: &Ipv4Addr) -> bool {
        match self {
            Self::Name(_) => false,
            Self::Address(ip) => match ip {
                IpAddr::V4(ip) => ip == other,
                IpAddr::V6(ip) => ip.to_ipv4().map(|ip| ip == *other).unwrap_or_default(),
            },
            // Semantic equivalence: pct-decoded bytes might be a v4
            // dotted-quad or a v4-mapped v6. Decode once via the
            // `TryFrom<UninterpretedHostRef>` impl (which uses
            // `as_unicode` — borrowed when no `%` is present, so the
            // happy path doesn't allocate). Bracketed IPvFuture inputs
            // always return `Err` and so never match an IP.
            Self::Uninterpreted(host) => match IpAddr::try_from(host) {
                Ok(IpAddr::V4(ip)) => ip == *other,
                Ok(IpAddr::V6(ip)) => ip.to_ipv4().map(|ip| ip == *other).unwrap_or_default(),
                Err(_) => false,
            },
        }
    }
}

impl PartialEq<Host> for Ipv4Addr {
    fn eq(&self, other: &Host) -> bool {
        other == self
    }
}

impl PartialEq<Ipv6Addr> for Host {
    fn eq(&self, other: &Ipv6Addr) -> bool {
        match self {
            Self::Name(_) => false,
            Self::Address(ip) => match ip {
                IpAddr::V4(ip) => ip.to_ipv6_mapped() == *other,
                IpAddr::V6(ip) => ip == other,
            },
            // Same semantic strategy as the v4 case — see comment there.
            Self::Uninterpreted(host) => match IpAddr::try_from(host) {
                Ok(IpAddr::V4(ip)) => ip.to_ipv6_mapped() == *other,
                Ok(IpAddr::V6(ip)) => ip == *other,
                Err(_) => false,
            },
        }
    }
}

impl PartialEq<Host> for Ipv6Addr {
    fn eq(&self, other: &Host) -> bool {
        other == self
    }
}

impl PartialEq<IpAddr> for Host {
    fn eq(&self, other: &IpAddr) -> bool {
        match other {
            IpAddr::V4(ip) => self == ip,
            IpAddr::V6(ip) => self == ip,
        }
    }
}

impl PartialEq<Host> for IpAddr {
    fn eq(&self, other: &Host) -> bool {
        other == self
    }
}

/// Label iterator for [`Host`]: delegates to the underlying [`Domain`] for
/// [`Host::Name`], and is empty for [`Host::Address`].
#[derive(Clone)]
pub enum HostLabelIter<'a> {
    Domain(DomainLabelIter<'a>),
    Empty,
}

impl<'a> Iterator for HostLabelIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        match self {
            Self::Domain(it) => it.next(),
            Self::Empty => None,
        }
    }
}

impl DoubleEndedIterator for HostLabelIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Domain(it) => it.next_back(),
            Self::Empty => None,
        }
    }
}

impl DomainLabels for Host {
    type LabelIter<'a> = HostLabelIter<'a>;

    fn labels(&self) -> Self::LabelIter<'_> {
        match self {
            Self::Name(d) => HostLabelIter::Domain(d.labels()),
            // No label structure is exposed for non-Domain variants —
            // pct-encoded reg-name bytes aren't DNS labels by definition,
            // and IP literals don't have labels at all.
            Self::Address(_) | Self::Uninterpreted(_) => HostLabelIter::Empty,
        }
    }
}

impl From<Domain> for Host {
    fn from(domain: Domain) -> Self {
        Self::Name(domain)
    }
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        Self::Address(ip)
    }
}

impl From<Ipv4Addr> for Host {
    fn from(ip: Ipv4Addr) -> Self {
        Self::Address(IpAddr::V4(ip))
    }
}

impl From<Ipv6Addr> for Host {
    fn from(ip: Ipv6Addr) -> Self {
        Self::Address(IpAddr::V6(ip))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(domain) => domain.fmt(f),
            Self::Address(ip) => ip.fmt(f),
            // [`UninterpretedHost`]'s Display already handles the
            // bracketed-IP-literal vs reg-name distinction.
            Self::Uninterpreted(host) => host.fmt(f),
        }
    }
}

impl fmt::Display for HostRef<'_> {
    /// Renders the host in its canonical wire form — matching
    /// [`Host`]'s `Display` for the same value. Useful for one-liner
    /// log/format calls (`format!("{}", host_ref)`) without first
    /// promoting to an owned [`Host`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(d) => f.write_str(d.as_str()),
            Self::Address(ip) => ip.fmt(f),
            Self::Uninterpreted(host) => host.fmt(f),
        }
    }
}

// ---- Cross-variant Eq / Hash / Ord (RFC 3986 §6.2.2.2) -------------------
//
// Two `HostRef`s are equal iff their *canonical* host form is equal. A
// non-bracketed `Uninterpreted(u)` whose bytes pct-decode + IDN-normalise
// to a typed `Domain` IS that `Domain` per the spec — so we project
// `Uninterpreted` through `Domain::try_from` / `IpAddr::try_from` before
// comparing / hashing / ordering. Same-variant cases short-circuit
// through the underlying type's own impls (case-folded for `Domain`,
// logical-byte for `UninterpretedHost`, value for `IpAddr`).
//
// Cost: promotion attempts run only on cross-variant paths; same-variant
// is single-dispatch via the sub-type's existing fast impl.

/// Canonical projection of a `HostRef` for Eq / Hash / Ord purposes.
/// Owned because `Domain::try_from(UninterpretedHostRef)` may allocate
/// (pct-decoded + IDN-encoded bytes) — the projection only runs at the
/// Eq/Hash/Ord call site, not on every accessor.
enum HostCanonical<'a> {
    Domain(super::domain::Domain),
    DomainRef(super::domain::DomainRef<'a>),
    Address(IpAddr),
    /// Sub-delim reg-name / IPvFuture body — no typed canonical form.
    Opaque(UninterpretedHostRef<'a>),
}

impl<'a> HostCanonical<'a> {
    fn from_ref(host: HostRef<'a>) -> Self {
        match host {
            HostRef::Name(d) => Self::DomainRef(d),
            HostRef::Address(ip) => Self::Address(ip),
            HostRef::Uninterpreted(u) => {
                // Bracketed → IPvFuture body, no typed promotion possible.
                if u.is_bracketed() {
                    return Self::Opaque(u);
                }
                // Try IP first — cheaper than `Domain::try_from` (no
                // allocation for the common pct-free IPv4 case) and
                // avoids classifying `127.0.0.1` as a `Name`.
                if let Ok(ip) = IpAddr::try_from(u) {
                    return Self::Address(ip);
                }
                if let Ok(d) = Domain::try_from(u) {
                    return Self::Domain(d);
                }
                Self::Opaque(u)
            }
        }
    }

    /// Borrowed `DomainRef` view of the canonical form (used by Eq/Ord
    /// without re-allocating the owned `Domain` produced by `try_from`).
    fn as_view(&self) -> HostCanonicalView<'_> {
        match self {
            Self::Domain(d) => HostCanonicalView::Domain(d.into()),
            Self::DomainRef(d) => HostCanonicalView::Domain(*d),
            Self::Address(ip) => HostCanonicalView::Address(*ip),
            Self::Opaque(u) => HostCanonicalView::Opaque(*u),
        }
    }
}

/// Borrowed view of the canonical form. Variant tag identical to
/// `HostCanonical`'s; only used for comparing two projections.
#[derive(Clone, Copy)]
enum HostCanonicalView<'a> {
    Domain(super::domain::DomainRef<'a>),
    Address(IpAddr),
    Opaque(UninterpretedHostRef<'a>),
}

impl HostCanonicalView<'_> {
    /// Discriminant tag for total ordering — `Domain < Address <
    /// Opaque`. Matches the source `HostRef` variant order (Name → 0,
    /// Address → 1, Uninterpreted → 2) so the bridging doesn't shuffle
    /// the natural ordering.
    fn tag(&self) -> u8 {
        match self {
            Self::Domain(_) => 0,
            Self::Address(_) => 1,
            Self::Opaque(_) => 2,
        }
    }
}

impl PartialEq for HostRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        // Same-variant fast paths. `Uninterpreted` only skips canonical
        // projection when both sides are pct-free pure ASCII — otherwise
        // UTS #46 may fold distinct surface bytes (e.g. `ß` vs `ẞ`) to
        // the same Domain, which the byte-level compare wouldn't see.
        match (self, other) {
            (Self::Name(a), Self::Name(b)) => return a == b,
            (Self::Address(a), Self::Address(b)) => return a == b,
            (Self::Uninterpreted(a), Self::Uninterpreted(b))
                if uninterpreted_byte_compare_is_canonical(*a)
                    && uninterpreted_byte_compare_is_canonical(*b) =>
            {
                return a == b;
            }
            _ => {}
        }
        // Cross-variant or non-ASCII Uninterpreted: project through the
        // canonical form.
        let lhs = HostCanonical::from_ref(*self);
        let rhs = HostCanonical::from_ref(*other);
        match (lhs.as_view(), rhs.as_view()) {
            (HostCanonicalView::Domain(a), HostCanonicalView::Domain(b)) => a == b,
            (HostCanonicalView::Address(a), HostCanonicalView::Address(b)) => a == b,
            (HostCanonicalView::Opaque(a), HostCanonicalView::Opaque(b)) => a == b,
            _ => false,
        }
    }
}

/// `true` when an `UninterpretedHostRef`'s bytes cannot be UTS #46
/// normalized into a different surface form — i.e. byte-level case-fold
/// already matches the canonical projection. Requires: no `%` (pct-decode
/// could yield non-ASCII) and no byte ≥ 0x80 (raw non-ASCII normalizes).
#[inline]
fn uninterpreted_byte_compare_is_canonical(u: UninterpretedHostRef<'_>) -> bool {
    u.as_bytes().iter().all(|&b| b < 0x80 && b != b'%')
}

impl Eq for HostRef<'_> {}

impl Ord for HostRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let lhs = HostCanonical::from_ref(*self);
        let rhs = HostCanonical::from_ref(*other);
        let (la, ra) = (lhs.as_view(), rhs.as_view());
        match la.tag().cmp(&ra.tag()) {
            std::cmp::Ordering::Equal => match (la, ra) {
                (HostCanonicalView::Domain(a), HostCanonicalView::Domain(b)) => a.cmp(&b),
                (HostCanonicalView::Address(a), HostCanonicalView::Address(b)) => a.cmp(&b),
                (HostCanonicalView::Opaque(a), HostCanonicalView::Opaque(b)) => a.cmp(&b),
                // SAFETY: `HostCanonicalView::tag()` returns a unique
                // discriminant per variant; equal tags ⇒ same variant.
                // `unreachable_unchecked` keeps the codegen lean without
                // tripping `clippy::unreachable` for arbitrary inputs.
                _ => unsafe { std::hint::unreachable_unchecked() },
            },
            non_eq => non_eq,
        }
    }
}

impl PartialOrd for HostRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for HostRef<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let canonical = HostCanonical::from_ref(*self);
        let view = canonical.as_view();
        // Discriminant tag first so Domain / Address / Opaque can't
        // collide on equal-bytes (e.g. an Address hash and a Domain
        // hash that happen to produce the same state).
        state.write_u8(view.tag());
        match view {
            HostCanonicalView::Domain(d) => d.hash(state),
            HostCanonicalView::Address(ip) => ip.hash(state),
            HostCanonicalView::Opaque(u) => u.hash(state),
        }
    }
}

// ---- Owned `Host` delegates to `HostRef` for Eq / Hash / Ord ------------

impl PartialEq for Host {
    fn eq(&self, other: &Self) -> bool {
        HostRef::from(self) == HostRef::from(other)
    }
}

impl Eq for Host {}

impl Ord for Host {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        HostRef::from(self).cmp(&HostRef::from(other))
    }
}

impl PartialOrd for Host {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for Host {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        HostRef::from(self).hash(state);
    }
}

impl std::str::FromStr for Host {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Host {
    type Error = BoxError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        try_from_host_str(name.as_str())
    }
}

impl TryFrom<&str> for Host {
    type Error = BoxError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        try_from_host_str(name)
    }
}

/// Parse `s` as a [`Host`] — IPv4/IPv6/IPvFuture (bracketed or bare),
/// DNS-shaped domain, or otherwise a reg-name [`Uninterpreted`] host.
/// Symmetric with the URI parser's host byte set so any URI host
/// `Display`-round-trips through this entry point.
fn try_from_host_str(s: &str) -> Result<Host, BoxError> {
    if s.is_empty() {
        return Err(OpaqueError::from_static_str("empty host string").into_box_error());
    }
    // Bracketed IP-literal fast path — without it, the colon-in-IPv6
    // body confuses bare parses and `[v1.X]` IPvFuture has no shot.
    if s.starts_with('[') && s.ends_with(']') {
        let inside = &s[1..s.len() - 1];
        if inside.is_empty() {
            return Err(OpaqueError::from_static_str("empty bracketed IP-literal").into_box_error());
        }
        // IPvFuture: surface as `Uninterpreted(bracketed=true)`.
        if matches!(inside.as_bytes().first(), Some(b'v' | b'V')) {
            crate::uri::parser::authority::validate_ipvfuture(inside.as_bytes())
                .map_err(BoxError::from)
                .context("parse bracketed IPvFuture")?;
            return Ok(Host::Uninterpreted(
                UninterpretedHost::from_validated_bytes(
                    rama_core::bytes::Bytes::copy_from_slice(inside.as_bytes()),
                    true,
                ),
            ));
        }
        if super::parse_utils::ipv6_bracket_has_zone(inside.as_bytes()) {
            return Err(OpaqueError::from_static_str(
                "ipv6 zone identifiers (RFC 6874) are not supported",
            )
            .into_box_error());
        }
        let addr = inside
            .parse::<std::net::Ipv6Addr>()
            .context("parse bracketed ipv6 host")?;
        return Ok(Host::Address(IpAddr::V6(addr)));
    }
    if let Some(ip) = parse_utils::try_to_parse_str_to_ip(s) {
        return Ok(Host::Address(ip));
    }
    if let Ok(domain) = Domain::try_from(s.to_owned()) {
        return Ok(Host::Name(domain));
    }
    // Reg-name fallback (pct-encoded, sub-delim, raw UTF-8) — symmetric
    // with the URI parser's host shape.
    let host = UninterpretedHost::try_from_reg_name_str(s).context("parse host as reg-name")?;
    Ok(Host::Uninterpreted(host))
}

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
impl TryFrom<HeaderValue> for Host {
    type Error = BoxError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
impl TryFrom<&HeaderValue> for Host {
    type Error = BoxError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        header.to_str().context("convert header to str")?.try_into()
    }
}

impl TryFrom<Vec<u8>> for Host {
    type Error = BoxError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(name.as_slice())
    }
}

impl TryFrom<&[u8]> for Host {
    type Error = BoxError;

    fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
        // Text-first: a 4-byte text input like `b"[::]"` parses to the
        // IPv6 unspecified address; the binary-octet interpretation
        // (4 bytes → IPv4, 16 bytes → IPv6) is the fallback for byte
        // payloads that aren't valid UTF-8 host text.
        if let Ok(s) = std::str::from_utf8(name)
            && let Ok(host) = try_from_host_str(s)
        {
            return Ok(host);
        }
        if let Ok(arr) = <&[u8; 4]>::try_from(name) {
            return Ok(Self::Address(IpAddr::from(*arr)));
        }
        if let Ok(arr) = <&[u8; 16]>::try_from(name) {
            return Ok(Self::Address(IpAddr::from(*arr)));
        }
        Err(OpaqueError::from_static_str("parse host from bytes failed").into_box_error())
    }
}

impl serde::Serialize for Host {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum Is {
        Domain(&'static str),
        Ip(&'static str),
    }

    fn assert_is(host: Host, expected: Is) {
        match expected {
            Is::Domain(domain) => match host {
                Host::Address(address) => {
                    panic!("expected host address {address} to be the domain: {domain}",)
                }
                Host::Name(name) => assert_eq!(domain, name),
                Host::Uninterpreted(host) => {
                    panic!("expected host {host} to be the domain: {domain}")
                }
            },
            Is::Ip(ip) => match host {
                Host::Address(address) => assert_eq!(ip, address.to_string()),
                Host::Name(name) => panic!("expected host domain {name} to be the ip: {ip}"),
                Host::Uninterpreted(host) => {
                    panic!("expected uninterpreted host {host} to be the ip: {ip}")
                }
            },
        }
    }

    #[test]
    fn test_parse_specials() {
        for (str, expected) in [
            ("localhost", Is::Domain("localhost")),
            ("0.0.0.0", Is::Ip("0.0.0.0")),
            ("::1", Is::Ip("::1")),
            ("[::1]", Is::Ip("::1")),
            ("127.0.0.1", Is::Ip("127.0.0.1")),
            ("::", Is::Ip("::")),
            ("[::]", Is::Ip("::")),
        ] {
            let msg = format!("parsing {str}");
            assert_is(Host::try_from(str).expect(msg.as_str()), expected);
            assert_is(
                Host::try_from(str.to_owned()).expect(msg.as_str()),
                expected,
            );
            assert_is(
                Host::try_from(str.as_bytes()).expect(msg.as_str()),
                expected,
            );
            assert_is(
                Host::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                expected,
            );
        }
    }

    #[test]
    fn test_parse_bytes_valid() {
        for (bytes, expected) in [
            ("example.com".as_bytes(), Is::Domain("example.com")),
            ("aA1".as_bytes(), Is::Domain("aA1")),
            (&[127, 0, 0, 1], Is::Ip("127.0.0.1")),
            (&[19, 117, 63, 126], Is::Ip("19.117.63.126")),
            (
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                Is::Ip("::1"),
            ),
            (
                &[
                    32, 1, 13, 184, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136, 136,
                ],
                Is::Ip("2001:db8:3333:4444:5555:6666:7777:8888"),
            ),
        ] {
            let msg = format!("parsing {bytes:?}");
            assert_is(Host::try_from(bytes).expect(msg.as_str()), expected);
            assert_is(
                Host::try_from(bytes.to_vec()).expect(msg.as_str()),
                expected,
            );
        }
    }

    #[test]
    fn test_parse_valid() {
        for (str, expected) in [
            ("example.com", Is::Domain("example.com")),
            ("www.example.com", Is::Domain("www.example.com")),
            ("a-b-c.com", Is::Domain("a-b-c.com")),
            ("a-b-c.example.com", Is::Domain("a-b-c.example.com")),
            ("a-b-c.example", Is::Domain("a-b-c.example")),
            ("aA1", Is::Domain("aA1")),
            (".example.com", Is::Domain(".example.com")),
            ("example.com.", Is::Domain("example.com.")),
            (".example.com.", Is::Domain(".example.com.")),
            ("127.0.0.1", Is::Ip("127.0.0.1")),
            ("127.00.1", Is::Domain("127.00.1")),
            ("::1", Is::Ip("::1")),
            ("[::1]", Is::Ip("::1")),
            (
                "2001:db8:3333:4444:5555:6666:7777:8888",
                Is::Ip("2001:db8:3333:4444:5555:6666:7777:8888"),
            ),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]",
                Is::Ip("2001:db8:3333:4444:5555:6666:7777:8888"),
            ),
            ("::", Is::Ip("::")),
            ("[::]", Is::Ip("::")),
            ("19.117.63.126", Is::Ip("19.117.63.126")),
        ] {
            let msg = format!("parsing {str}");
            assert_is(Host::try_from(str).expect(msg.as_str()), expected);
            assert_is(
                Host::try_from(str.to_owned()).expect(msg.as_str()),
                expected,
            );
            assert_is(
                Host::try_from(str.as_bytes()).expect(msg.as_str()),
                expected,
            );
            assert_is(
                Host::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                expected,
            );
        }
    }

    #[test]
    fn test_parse_str_invalid() {
        for str in [
            // Empty input is always invalid.
            "", // Unbalanced brackets — IP-literal grammar requires both.
            "[::", "::]", // `@` is the userinfo terminator, not a host byte.
            "@",
        ] {
            assert!(Host::try_from(str).is_err(), "parsing {str}");
            assert!(Host::try_from(str.to_owned()).is_err(), "parsing {str}");
        }
    }

    #[test]
    fn is_loopback_for_ip_addresses() {
        for s in ["127.0.0.1", "127.0.0.2", "127.1.2.3", "::1", "[::1]"] {
            assert!(
                s.parse::<Host>().unwrap().is_loopback(),
                "{s} should be loopback",
            );
        }
        for s in ["0.0.0.0", "8.8.8.8", "::", "192.168.0.1"] {
            assert!(
                !s.parse::<Host>().unwrap().is_loopback(),
                "{s} should not be loopback",
            );
        }
        // IPv4-mapped IPv6 loopback follows std semantics: not loopback.
        let mapped = Host::Address(IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!mapped.is_loopback());
    }

    #[test]
    fn is_loopback_for_localhost_names() {
        for s in [
            "localhost",
            "LOCALHOST",
            "LocalHost",
            "foo.localhost",
            "a.b.localhost",
            "localhost.",
            ".localhost",
        ] {
            assert!(
                s.parse::<Host>().unwrap().is_loopback(),
                "{s} should be a loopback name",
            );
        }
        for s in [
            "example.com",
            "localhost.example.com",
            "mylocalhost",
            "localhostx",
            "localhost.com",
        ] {
            assert!(
                !s.parse::<Host>().unwrap().is_loopback(),
                "{s} should not be a loopback name",
            );
        }
    }

    #[test]
    fn is_loopback_bridges_uninterpreted_variant() {
        // pct-encoded `localhost` reg-name bridges to the localhost name.
        assert!(reg_host(b"%6C%6F%63%61%6C%68%6F%73%74").is_loopback());
        // reg-name bytes that are a loopback dotted-quad bridge to the IP.
        assert!(reg_host(b"127.0.0.1").is_loopback());
        // non-loopback reg-name, non-loopback IP, and bracketed IPvFuture
        // (no typed counterpart) are all reported as not loopback.
        assert!(!reg_host(b"example.com").is_loopback());
        assert!(!reg_host(b"8.8.8.8").is_loopback());
        assert!(!bracketed_host(b"v1.fe80::a").is_loopback());
    }

    #[test]
    fn compare_host_with_ipv4_bidirectional() {
        let test_cases = [
            (
                true,
                "127.0.0.1".parse::<Host>().unwrap(),
                Ipv4Addr::LOCALHOST,
            ),
            (
                false,
                "127.0.0.2".parse::<Host>().unwrap(),
                Ipv4Addr::LOCALHOST,
            ),
            (
                false,
                "127.0.0.1".parse::<Host>().unwrap(),
                Ipv4Addr::new(127, 0, 0, 2),
            ),
        ];
        for (expected, a, b) in test_cases {
            assert_eq!(expected, a == b, "a[{a}] == b[{b}]");
            assert_eq!(expected, b == a, "b[{b}] == a[{a}]");
        }
    }

    #[test]
    fn compare_host_with_ipv6_bidirectional() {
        let test_cases = [
            (true, "::1".parse::<Host>().unwrap(), Ipv6Addr::LOCALHOST),
            (false, "::2".parse::<Host>().unwrap(), Ipv6Addr::LOCALHOST),
            (
                false,
                "::1".parse::<Host>().unwrap(),
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
            ),
        ];
        for (expected, a, b) in test_cases {
            assert_eq!(expected, a == b, "a[{a}] == b[{b}]");
            assert_eq!(expected, b == a, "b[{b}] == a[{a}]");
        }
    }

    #[test]
    fn compare_host_with_ip_bidirectional() {
        let test_cases = [
            (true, "127.0.0.1".parse::<Host>().unwrap(), IPV4_LOCALHOST),
            (false, "127.0.0.2".parse::<Host>().unwrap(), IPV4_LOCALHOST),
            (
                false,
                "127.0.0.1".parse::<Host>().unwrap(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ),
            (false, "::2".parse::<Host>().unwrap(), IPV4_LOCALHOST),
        ];
        for (expected, a, b) in test_cases {
            assert_eq!(expected, a == b, "a[{a}] == b[{b}]");
            assert_eq!(expected, b == a, "b[{b}] == a[{a}]");
        }
    }

    #[test]
    fn host_labels_delegates_to_domain() {
        let h = Host::Name(Domain::from_static("www.example.com"));
        let labels: Vec<&str> = h.labels().map(|l| l.as_str()).collect();
        assert_eq!(labels, vec!["www", "example", "com"]);
        assert_eq!(h.label_count(), 3);

        // is_subdomain_of works through Host
        let parent_h = Host::Name(Domain::from_static("example.com"));
        assert!(h.is_subdomain_of(&parent_h));

        // parent() returns owned Domain
        let p = h.parent().expect("parent");
        assert_eq!(p.as_str(), "example.com");
    }

    #[test]
    fn host_labels_ip_is_empty_and_never_subdomain() {
        let h = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(h.labels().count(), 0);
        assert_eq!(h.label_count(), 0);
        assert!(h.parent().is_none());

        // An IP is never a subdomain of any non-empty parent.
        let parent = Host::Name(Domain::from_static("example.com"));
        assert!(!h.is_subdomain_of(&parent));
        // And a non-empty domain is never a subdomain of an IP host (empty parent).
        let d_host = Host::Name(Domain::from_static("example.com"));
        assert!(!d_host.is_subdomain_of(&h));
    }

    /// Regression: IPv6 zone-ids (RFC 6874 `fe80::1%eth0`) must never be
    /// accepted via the `Host` entry points. Today the rejection comes for
    /// free because `std::net::Ipv6Addr::from_str` refuses any `%` and
    /// `Domain` validation refuses `%` too, but this test pins that
    /// behaviour so any future "graceful zone-id allow" patch trips a
    /// failing test instead of silently letting RFC 6874 scoped addresses
    /// traverse a proxy.
    #[test]
    fn regression_host_rejects_ipv6_zone_id() {
        for input in [
            "fe80::1%eth0",
            "fe80::1%25eth0",
            "[fe80::1%eth0]",
            "[fe80::1%25eth0]",
            "::1%0",
        ] {
            assert!(
                Host::try_from(input).is_err(),
                "host should reject zone-id input {input:?}",
            );
        }
    }

    // ---- Uninterpreted variant: PartialEq behaviour --------------------
    //
    // Wire-fidelity preservation means callers comparing against a
    // semantic value (IP address, decoded string) get equivalence —
    // pct-encoded bytes decode through to match — but the comparison
    // stays cheap on the common all-ASCII no-`%` path.

    fn reg_host(bytes: &'static [u8]) -> Host {
        Host::Uninterpreted(UninterpretedHost::from_validated_bytes(
            rama_core::bytes::Bytes::from_static(bytes),
            false,
        ))
    }

    fn bracketed_host(bytes: &'static [u8]) -> Host {
        Host::Uninterpreted(UninterpretedHost::from_validated_bytes(
            rama_core::bytes::Bytes::from_static(bytes),
            true,
        ))
    }

    #[test]
    fn eq_str_byte_compares_raw_form() {
        // Fast path — no `%` in bytes, byte-compare is exact.
        let h = reg_host(b"example.com");
        assert!(h == "example.com");
        assert!(h != "other.com");
    }

    // ---- PartialEq<str> case-insensitive (§6.2.2.1) -------------------

    #[test]
    fn eq_str_is_case_insensitive_for_named_host() {
        // `Domain::Eq` is case-insensitive; `Host == str` follows.
        let h = Host::Name(Domain::from_static("example.com"));
        assert!(h == "EXAMPLE.com");
        assert!(h == "Example.Com");
        assert!(h == "example.com");
    }

    #[test]
    fn eq_str_is_case_insensitive_for_uninterpreted_reg_name() {
        let h = reg_host(b"tag,WITH,commas");
        assert!(h == "tag,with,commas");
        assert!(h == "TAG,WITH,COMMAS");
    }

    #[test]
    fn eq_str_is_case_insensitive_through_pct_decode() {
        // `exa%6Dple.com` pct-decodes to `example.com`; the decoded
        // path also case-folds.
        let h = reg_host(b"exa%6Dple.com");
        assert!(h == "EXAMPLE.com");
    }

    #[test]
    fn eq_str_is_case_insensitive_for_bracketed_ipvfuture() {
        let h = bracketed_host(b"v1.FE80::A");
        assert!(h == "[v1.fe80::a]");
        assert!(h == "[V1.fe80::a]");
    }

    #[test]
    fn eq_str_byte_compares_pct_encoded_raw_first() {
        // Comparing the literal pct-encoded form should match without
        // any decoding work (byte-compare hits first).
        let h = reg_host(b"exa%6Dple.com");
        assert!(h == "exa%6Dple.com");
    }

    #[test]
    fn eq_str_decodes_pct_when_byte_compare_fails() {
        // When raw bytes don't match, fall through to decoded compare.
        let h = reg_host(b"exa%6Dple.com");
        assert!(h == "example.com");
    }

    #[test]
    fn eq_str_no_decode_when_no_pct_in_bytes() {
        // Bytes without `%` short-circuit at byte-compare — no decode
        // pass. Semantically: a host like `example.com` can never match
        // anything else, so we don't waste cycles on `as_unicode`.
        let h = reg_host(b"example.com");
        assert!(h != "something.completely.different");
    }

    #[test]
    fn eq_str_address_ipv6_mixed_case() {
        // §6.2.2.1: hosts are case-insensitive. `Host::Address` parses
        // the right-hand side via `IpAddr::from_str`, which already
        // accepts mixed-case hex — verify both Display-form and
        // mixed-case forms compare equal.
        let h = Host::Address("fe80::1".parse().unwrap());
        assert!(h == "fe80::1");
        assert!(h == "FE80::1");
        assert!(h == "Fe80::1");
        // Canonical equivalent (fully-expanded) also matches via parse-equality.
        assert!(h == "fe80:0:0:0:0:0:0:1");
        // Different address — no match.
        assert!(h != "fe80::2");
    }

    #[test]
    fn eq_str_address_ipv4_mapped_ipv6_kept_distinct() {
        // `127.0.0.1` parses as `IpAddr::V4`; `::ffff:127.0.0.1` parses
        // as `IpAddr::V6`. They're different addresses to `std`, so
        // `Host::Address(V4)` does not match the v4-mapped-v6 string.
        // Pin behavior so a future relaxation is a conscious change.
        let h4 = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert!(h4 == "127.0.0.1");
        assert!(h4 != "::ffff:127.0.0.1");

        let h6 = Host::Address("::ffff:127.0.0.1".parse().unwrap());
        assert!(h6 == "::ffff:127.0.0.1");
        assert!(h6 != "127.0.0.1");
    }

    #[test]
    fn eq_str_brackets_compared_without_allocation() {
        // Bracketed form: stored bytes don't include `[...]`; the str
        // side must. We strip from `other` rather than `to_string()`
        // the host. Hence no allocation in the comparison path.
        let h = bracketed_host(b"v1.fe80::a");
        assert!(h == "[v1.fe80::a]");
        // Without brackets on the str side → no match.
        assert!(h != "v1.fe80::a");
        // Mismatched bytes inside brackets → no match.
        assert!(h != "[v2.fe80::a]");
        // Edge: empty / too-short str inputs.
        assert!(h != "");
        assert!(h != "[]");
    }

    #[test]
    fn eq_ipv4_decodes_pct_encoded_dotted_quad() {
        // `%31%32%37.0.0.1` pct-decodes to `127.0.0.1` which equals
        // the Ipv4Addr value.
        let h = reg_host(b"%31%32%37.0.0.1");
        assert!(h == Ipv4Addr::new(127, 0, 0, 1));
        assert!(Ipv4Addr::new(127, 0, 0, 1) == h);
        assert!(h != Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn eq_ipv4_matches_unencoded_dotted_quad_too() {
        let h = reg_host(b"127.0.0.1");
        assert!(h == Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn eq_ipv6_decodes_pct_encoded_colon_form() {
        // Pct-encoding `:` (%3A) inside an IPv6 literal — niche but legal.
        let h = reg_host(b"2001%3Adb8%3A%3A1");
        assert!(h == "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn eq_ipv4_mapped_v6_via_pct_encoded_v4() {
        // `127.0.0.1` decodes to v4 dotted-quad; comparing against the
        // IPv6 mapped form must succeed.
        let h = reg_host(b"%31%32%37.0.0.1");
        let mapped = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
        assert!(h == mapped);
    }

    #[test]
    fn eq_ipvfuture_never_matches_any_ip() {
        // Bracketed IPvFuture can't decode to v4 or v6.
        let h = bracketed_host(b"v1.fe80::a");
        assert!(h != Ipv4Addr::new(127, 0, 0, 1));
        assert!(h != "::1".parse::<Ipv6Addr>().unwrap());
        let any: IpAddr = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        assert!(h != any);
    }

    #[test]
    fn eq_reg_name_never_matches_ip_when_not_decodable() {
        // A genuine DNS-shaped reg-name doesn't decode to any IP.
        let h = reg_host(b"example.com");
        assert!(h != Ipv4Addr::new(127, 0, 0, 1));
        assert!(h != "::1".parse::<Ipv6Addr>().unwrap());
    }

    // ---- HostRef: Display ergonomics -----------------------------------

    #[test]
    fn host_ref_display_matches_owned_host() {
        // `Display` on the borrowed view must render the same string as
        // the owned form — callers can `format!("{}", uri.host()?)`
        // without first promoting.
        for owned in [
            Host::Name(Domain::from_static("example.com")),
            Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
            Host::Address("::1".parse().unwrap()),
            reg_host(b"exa%6Dple.com"),
            bracketed_host(b"v1.fe80::a"),
        ] {
            let r: HostRef<'_> = (&owned).into();
            assert_eq!(format!("{r}"), format!("{owned}"));
        }
    }

    // ---- Cross-variant Eq / Hash / Ord (RFC 3986 §6.2.2.2) -------------

    #[test]
    fn cross_variant_name_eq_uninterpreted_via_pct_decode() {
        // `exa%6Dple.com` pct-decodes to `example.com` — same host per
        // §6.2.2.2. Promote-then-compare bridges the variant boundary.
        let typed = Host::Name(Domain::from_static("example.com"));
        let pct = reg_host(b"exa%6Dple.com");
        assert_eq!(typed, pct);
        assert_eq!(pct, typed);
    }

    #[test]
    fn cross_variant_name_eq_uninterpreted_case_insensitive() {
        // `EXAMPLE.com` (Uninterpreted) ≡ `example.com` (Name).
        // Domain case-folding + variant bridging compose.
        let typed = Host::Name(Domain::from_static("example.com"));
        let upper_pct = reg_host(b"EXa%6Dple.COM");
        assert_eq!(typed, upper_pct);
    }

    #[test]
    fn cross_variant_address_eq_uninterpreted_via_pct_decode() {
        // `%31%32%37.0.0.1` pct-decodes to `127.0.0.1` — same IPv4.
        let typed = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        let pct = reg_host(b"%31%32%37.0.0.1");
        assert_eq!(typed, pct);
    }

    #[test]
    fn cross_variant_bracketed_ipvfuture_never_eq_typed() {
        // Bracketed IPvFuture has no typed counterpart — must NOT
        // compare equal to any Name or Address.
        let bracketed = bracketed_host(b"v1.fe80::a");
        let domain = Host::Name(Domain::from_static("v1"));
        assert_ne!(bracketed, domain);
        let v6 = Host::Address("fe80::a".parse().unwrap());
        assert_ne!(bracketed, v6);
    }

    #[test]
    fn cross_variant_opaque_uninterpreted_never_eq_typed() {
        // Sub-delim reg-name (`tag,with,commas`) has no typed canonical
        // form. Must not bridge to anything else.
        let opaque = reg_host(b"tag,with,commas");
        assert_ne!(opaque, Host::Name(Domain::from_static("tag")));
        assert_ne!(
            opaque,
            Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn cross_variant_hash_agrees_with_eq() {
        use ahash::{HashMap, HashMapExt as _};
        let mut m: HashMap<Host, &'static str> = HashMap::new();
        m.insert(Host::Name(Domain::from_static("example.com")), "value");
        // Insert as Name, look up via pct-encoded Uninterpreted form.
        assert_eq!(m.get(&reg_host(b"exa%6Dple.com")), Some(&"value"));
        // ... and uppercase pct-encoded.
        assert_eq!(m.get(&reg_host(b"EXa%6Dple.COM")), Some(&"value"));
    }

    #[test]
    fn cross_variant_hash_address_via_uninterpreted() {
        use ahash::{HashMap, HashMapExt as _};
        let mut m: HashMap<Host, ()> = HashMap::new();
        m.insert(
            Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
            (),
        );
        // Lookup via pct-encoded Uninterpreted IPv4 form.
        assert!(m.contains_key(&reg_host(b"%31%32%37.0.0.1")));
    }

    #[test]
    fn cross_variant_ord_promotion_groups_typed_together() {
        // After canonical projection, the ordering tag is (Domain,
        // Address, Opaque). So a pct-encoded Uninterpreted reg-name
        // that decodes to a Domain sorts WITH the Domain variant, not
        // with the other Uninterpreted hosts.
        let mut v = [
            reg_host(b"tag,with,commas"), // Opaque (tag 2)
            reg_host(b"exa%6Dple.com"),   // Promotes to Domain (tag 0)
            Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap()), // Address (tag 1)
            Host::Name(Domain::from_static("aaaa.example")), // Domain (tag 0)
        ];
        v.sort();
        // First two slots: Domain-class (alphabetical by Domain ord).
        assert!(matches!(&v[0], Host::Name(d) if d.as_str() == "aaaa.example"));
        // The pct-encoded reg-name canonicalises to a Domain so it
        // sorts in the Domain group too.
        assert!(matches!(&v[1], Host::Uninterpreted(_)));
        // Then Address-class.
        assert!(matches!(&v[2], Host::Address(_)));
        // Then Opaque-class.
        assert!(matches!(&v[3], Host::Uninterpreted(u) if u.as_str() == "tag,with,commas"));
    }

    // ---- Eq transitivity across the UTS#46 / pct-encoding boundary ---------

    #[cfg(feature = "idna")]
    #[test]
    fn eq_transitive_uts46_via_non_ascii_uninterpreted() {
        // Two distinct UTF-8 surface forms of the same domain
        // (`ß` U+00DF vs `ẞ` U+1E9E) canonicalize to the same ACE
        // label. Same-variant byte compare would say they differ;
        // both must still equal the typed Domain that IDN produces.
        let a = reg_host("ß.de".as_bytes()); // U+00DF
        let b = reg_host("ẞ.de".as_bytes()); // U+1E9E
        let c = Host::Name(Domain::try_from("ß.de").unwrap());

        assert_eq!(a, c);
        assert_eq!(b, c);
        assert_eq!(a, b, "Eq must be transitive — A==C ∧ B==C ⇒ A==B");
    }

    #[cfg(feature = "idna")]
    #[test]
    fn eq_transitive_uts46_via_pct_encoded_non_ascii() {
        // Pct-encoded forms of the same Unicode label must also bridge.
        let a = reg_host(b"%E1%BA%9E.de"); // pct-encoded U+1E9E
        let b = reg_host(b"%C3%9F.de"); // pct-encoded U+00DF
        let c = Host::Name(Domain::try_from("ß.de").unwrap());

        assert_eq!(a, c);
        assert_eq!(b, c);
        assert_eq!(a, b);
    }

    // ---- H7: Hash determinism + Ord transitivity ---------------------------

    #[test]
    fn hash_determinism_bracketed_ipvfuture() {
        // Two `HostRef::Uninterpreted` instances built from the same
        // bracketed IPvFuture bytes must hash identically.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as _, Hasher};

        let h1 = bracketed_host(b"v1.fe80::a");
        let h2 = bracketed_host(b"v1.fe80::a");
        let mut s1 = DefaultHasher::new();
        h1.hash(&mut s1);
        let mut s2 = DefaultHasher::new();
        h2.hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    #[test]
    fn ord_transitive_across_bridge() {
        // Three values, one from each side of the typed↔Uninterpreted
        // bridge, must satisfy a<b ∧ b<c ⇒ a<c.
        let a = Host::Name(Domain::from_static("aaaa.example"));
        let b = reg_host(b"bbbb.example"); // promotes to Domain
        let c = Host::Name(Domain::from_static("cccc.example"));

        assert!(a < b);
        assert!(b < c);
        assert!(a < c, "Ord must be transitive across the bridge");
    }

    // ---- try_as_domain / try_into_domain / try_as_ip bridges --------------

    #[test]
    fn try_as_domain_name_returns_borrowed() {
        // The contract: `Host::Name → Cow::Borrowed`. Pin the no-alloc
        // path so a future refactor can't silently start cloning.
        let h = Host::Name(Domain::from_static("example.com"));
        let cow = h.try_as_domain().unwrap();
        assert!(
            matches!(cow, std::borrow::Cow::Borrowed(_)),
            "expected Cow::Borrowed for the Name variant"
        );
        assert_eq!(cow.as_str(), "example.com");
    }

    #[test]
    fn try_as_domain_address_errors() {
        let h = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        h.try_as_domain().unwrap_err();
        let h6 = Host::Address("::1".parse().unwrap());
        h6.try_as_domain().unwrap_err();
    }

    #[test]
    fn try_as_domain_uninterpreted_pct_decodes() {
        let h = reg_host(b"exa%6Dple.com");
        let cow = h.try_as_domain().unwrap();
        assert!(matches!(cow, std::borrow::Cow::Owned(_)));
        assert_eq!(cow.as_str(), "example.com");
    }

    #[cfg(feature = "idna")]
    #[test]
    fn try_as_domain_uninterpreted_idn_normalizes() {
        let h = reg_host("ß.de".as_bytes());
        let d = h.try_as_domain().unwrap();
        assert_eq!(d.as_str(), "xn--zca.de");
    }

    #[test]
    fn try_as_domain_uninterpreted_ipvfuture_errors() {
        let h = bracketed_host(b"v1.fe80::a");
        h.try_as_domain().unwrap_err();
    }

    #[test]
    fn try_as_domain_uninterpreted_subdelim_errors() {
        let h = reg_host(b"tag,with,commas");
        h.try_as_domain().unwrap_err();
    }

    #[test]
    fn try_into_domain_agrees_with_try_as_domain() {
        for h in [
            Host::Name(Domain::from_static("example.com")),
            reg_host(b"exa%6Dple.com"),
        ] {
            let by_ref = h.try_as_domain().map(|c| c.as_str().to_owned());
            let by_val = h.clone().try_into_domain().map(|d| d.as_str().to_owned());
            assert_eq!(by_ref.unwrap(), by_val.unwrap());
        }
        for h in [
            Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
            reg_host(b"tag,with,commas"),
            bracketed_host(b"v1.fe80::a"),
        ] {
            h.try_as_domain().unwrap_err();
            h.clone().try_into_domain().unwrap_err();
        }
    }

    #[test]
    fn try_as_ip_address_returns_value() {
        let h = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(
            h.try_as_ip().unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn try_as_ip_name_errors() {
        let h = Host::Name(Domain::from_static("example.com"));
        h.try_as_ip().unwrap_err();
    }

    #[test]
    fn try_as_ip_uninterpreted_pct_encoded_ipv4() {
        // `%31%32%37.0.0.1` decodes to `127.0.0.1` → bridges to IP.
        let h = reg_host(b"%31%32%37.0.0.1");
        assert_eq!(
            h.try_as_ip().unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn try_as_ip_uninterpreted_ipvfuture_errors() {
        let h = bracketed_host(b"v1.fe80::a");
        h.try_as_ip().unwrap_err();
    }

    #[test]
    fn try_as_ip_uninterpreted_subdelim_errors() {
        let h = reg_host(b"tag,with,commas");
        h.try_as_ip().unwrap_err();
    }

    // ---- HostRef::try_as_* mirror suite -----------------------------------

    #[test]
    fn host_ref_try_as_domain_name_returns_owned() {
        // HostRef has no Domain to lend (DomainRef is borrowed), so
        // the bridge always materializes an owned Domain.
        let owned = Host::Name(Domain::from_static("example.com"));
        let r = HostRef::from(&owned);
        let d = r.try_as_domain().unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn host_ref_try_as_ip_bridges_pct_encoded_ipv4() {
        let owned = reg_host(b"%31%32%37.0.0.1");
        let r = HostRef::from(&owned);
        assert_eq!(
            r.try_as_ip().unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn host_ref_try_as_domain_address_errors() {
        let owned = Host::Address("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        let r = HostRef::from(&owned);
        r.try_as_domain().unwrap_err();
    }

    // ---- Display ↔ try_from round-trip for Uninterpreted ----------------

    #[test]
    fn host_try_from_recovers_uninterpreted_pct_encoded() {
        // `exa%6Dple.com` is not a typed Domain (the validator rejects
        // `%`) and not an IP. Must round-trip as `Host::Uninterpreted`.
        let h: Host = "exa%6Dple.com".parse().unwrap();
        assert!(matches!(h, Host::Uninterpreted(_)));
        assert_eq!(h.to_string(), "exa%6Dple.com");
    }

    #[test]
    fn host_try_from_recovers_uninterpreted_subdelim() {
        let h: Host = "tag,with,commas".parse().unwrap();
        assert!(matches!(h, Host::Uninterpreted(_)));
        assert_eq!(h.to_string(), "tag,with,commas");
    }

    #[test]
    fn host_try_from_recovers_bracketed_ipvfuture() {
        let h: Host = "[v1.fe80::a]".parse().unwrap();
        assert!(matches!(h, Host::Uninterpreted(_)));
        assert_eq!(h.to_string(), "[v1.fe80::a]");
    }

    #[test]
    fn host_try_from_recovers_bracketed_ipv6() {
        let h: Host = "[::1]".parse().unwrap();
        assert!(matches!(h, Host::Address(IpAddr::V6(_))));
    }

    #[test]
    fn host_serde_roundtrip_through_uninterpreted() {
        // Auditor's regression: Serialize via Display, Deserialize via
        // try_from. Both must round-trip the Uninterpreted shape.
        let original = "exa%6Dple.com".parse::<Host>().unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let round: Host = serde_json::from_str(&json).unwrap();
        assert_eq!(original, round);
    }
}
