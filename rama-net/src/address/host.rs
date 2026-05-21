use super::domain::{DomainLabelIter, DomainLabels, Label};
use super::{Domain, UninterpretedHost, UninterpretedHostRef, parse_utils};
use crate::address::ip::{
    IPV4_BROADCAST, IPV4_LOCALHOST, IPV4_UNSPECIFIED, IPV6_LOCALHOST, IPV6_UNSPECIFIED,
};
use rama_core::error::{BoxError, ErrorContext};
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Returns `true` if [`Host`] is a [`Domain`].
    #[must_use]
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Name(_))
    }

    #[must_use]
    pub fn as_domain(&self) -> Option<&Domain> {
        match self {
            Self::Name(domain) => Some(domain),
            Self::Address(_) | Self::Uninterpreted(_) => None,
        }
    }

    #[must_use]
    pub fn into_domain(self) -> Option<Domain> {
        match self {
            Self::Name(domain) => Some(domain),
            Self::Address(_) | Self::Uninterpreted(_) => None,
        }
    }

    /// Returns `true` if [`Host`] is a [`IpAddr`].
    #[must_use]
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Address(_))
    }

    #[must_use]
    pub fn as_ip(&self) -> Option<&IpAddr> {
        match self {
            Self::Name(_) | Self::Uninterpreted(_) => None,
            Self::Address(addr) => Some(addr),
        }
    }

    #[must_use]
    pub fn into_ip(self) -> Option<IpAddr> {
        match self {
            Self::Name(_) | Self::Uninterpreted(_) => None,
            Self::Address(addr) => Some(addr),
        }
    }

    /// Returns `true` if [`Host`] is an [`UninterpretedHost`] — preserved
    /// reg-name / IP-literal bytes that aren't a typed [`Domain`] or [`IpAddr`].
    #[must_use]
    pub fn is_uninterpreted(&self) -> bool {
        matches!(self, Self::Uninterpreted(_))
    }

    #[must_use]
    pub fn as_uninterpreted(&self) -> Option<&UninterpretedHost> {
        match self {
            Self::Uninterpreted(host) => Some(host),
            Self::Name(_) | Self::Address(_) => None,
        }
    }

    #[must_use]
    pub fn into_uninterpreted(self) -> Option<UninterpretedHost> {
        match self {
            Self::Uninterpreted(host) => Some(host),
            Self::Name(_) | Self::Address(_) => None,
        }
    }

    /// Returns `true` if [`Host`] is a [`IpAddr::V4`].
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::Address(IpAddr::V4(_)))
    }

    /// Returns `true` if [`Host`] is a [`IpAddr::V6`].
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::Address(IpAddr::V6(_)))
    }

    /// Returns [`Host`] as a string, only allocated if we need to render it.
    #[must_use]
    pub fn to_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Name(domain) => domain.as_str().into(),
            Self::Address(ip_addr) => ip_addr.to_string().into(),
            // Bracketed forms (IPvFuture) need brackets in the string
            // form to match URI authority syntax — defer to Display.
            Self::Uninterpreted(host) if host.is_bracketed() => host.to_string().into(),
            // Non-bracketed reg-name bytes are valid UTF-8 — borrow directly.
            Self::Uninterpreted(host) => host.as_str().into(),
        }
    }

    /// Returns the Unicode (display) form of this host. For named hosts,
    /// any `xn--` A-labels are inverse-encoded via UTS #46. IP addresses
    /// are rendered to their standard textual form.
    ///
    /// Cheap when no conversion is needed — returns `Cow::Borrowed`
    /// pointing at the domain bytes; allocates only for IP addresses or
    /// IDN A-labels that actually require decoding.
    #[cfg(feature = "idna")]
    #[cfg_attr(docsrs, doc(cfg(feature = "idna")))]
    #[must_use]
    pub fn as_unicode(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Name(d) => d.as_unicode(),
            Self::Address(ip) => ip.to_string().into(),
            // Bracketed forms need wrapping brackets to match URI syntax.
            Self::Uninterpreted(host) if host.is_bracketed() => host.to_string().into(),
            // Non-bracketed: pct-decode on demand. Returns the decoded
            // form when `%XX` is present, otherwise borrows the raw
            // bytes (already valid UTF-8 per the parser invariant).
            Self::Uninterpreted(host) => host.as_unicode(),
        }
    }
}

impl Host {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRef<'a> {
    /// A DNS-style name.
    Name(super::domain::DomainRef<'a>),
    /// A literal IPv4 or IPv6 address.
    Address(IpAddr),
    /// Borrowed view of an [`UninterpretedHost`] — reg-name bytes
    /// preserved verbatim or a bracketed IP-literal.
    Uninterpreted(UninterpretedHostRef<'a>),
}

impl HostRef<'_> {
    /// Returns this host as a string. Domain names are returned as
    /// `Cow::Borrowed` (no allocation); IP addresses are formatted into
    /// a fresh `String`.
    #[must_use]
    pub fn to_str(&self) -> std::borrow::Cow<'_, str> {
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
    pub fn as_unicode(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Name(d) => d.as_unicode(),
            Self::Address(ip) => ip.to_string().into(),
            Self::Uninterpreted(host) if host.is_bracketed() => host.to_string().into(),
            Self::Uninterpreted(host) => host.as_unicode(),
        }
    }

    /// Returns an owned [`Host`] containing a copy of the underlying bytes
    /// (or, for the IP variants, a copy of the address value).
    #[must_use]
    pub fn to_owned(&self) -> Host {
        match *self {
            Self::Name(d) => Host::Name(d.to_owned()),
            Self::Address(ip) => Host::Address(ip),
            Self::Uninterpreted(host) => Host::Uninterpreted(host.to_owned()),
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
    fn eq(&self, other: &str) -> bool {
        match self {
            Self::Name(domain) => domain.as_str() == other,
            // Compare via address parsing rather than `ip.to_string()`, so
            // we avoid allocating a `String` on every comparison *and*
            // canonicalize the right-hand side (e.g. `"::1"` and
            // `"0:0:0:0:0:0:0:1"` are equal, `"127.0.0.001"` is not equal
            // to `127.0.0.1` because std rejects leading-zero octets).
            Self::Address(ip) => other.parse::<IpAddr>().is_ok_and(|parsed| parsed == *ip),
            Self::Uninterpreted(host) if host.is_bracketed() => {
                // Bracketed forms (e.g. `[v1.fe80::a]`) store bytes
                // without the surrounding brackets. Strip the brackets
                // from `other` and byte-compare the inside — no
                // allocation, no `to_string()`.
                let o = other.as_bytes();
                o.len() >= 2
                    && o[0] == b'['
                    && o[o.len() - 1] == b']'
                    && &o[1..o.len() - 1] == host.as_bytes()
            }
            Self::Uninterpreted(host) => {
                // Fast path — byte-compare on the raw wire form.
                let bytes = host.as_bytes();
                if bytes == other.as_bytes() {
                    return true;
                }
                // Semantic path — when pct-encoding is present, the
                // decoded form might match. Only allocate when there's
                // actually `%` to decode.
                if bytes.contains(&b'%')
                    && let s = host.as_unicode()
                    && s.as_ref() == other
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

impl std::str::FromStr for Host {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Host {
    type Error = BoxError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        parse_utils::try_to_parse_str_to_ip(name.as_str())
            .map(Host::Address)
            .or_else(|| Domain::try_from(name).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<&str> for Host {
    type Error = BoxError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        parse_utils::try_to_parse_str_to_ip(name)
            .map(Host::Address)
            .or_else(|| Domain::try_from(name.to_owned()).ok().map(Host::Name))
            .context("parse host from string")
    }
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
        try_to_parse_bytes_to_ip(name.as_slice())
            .map(Host::Address)
            .or_else(|| Domain::try_from(name).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<&[u8]> for Host {
    type Error = BoxError;

    fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
        try_to_parse_bytes_to_ip(name)
            .map(Host::Address)
            .or_else(|| Domain::try_from(name.to_owned()).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl serde::Serialize for Host {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let host = self.to_string();
        host.serialize(serializer)
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

fn try_to_parse_bytes_to_ip(value: &[u8]) -> Option<IpAddr> {
    if let Some(ip) = std::str::from_utf8(value)
        .ok()
        .and_then(parse_utils::try_to_parse_str_to_ip)
    {
        return Some(ip);
    }

    if let Ok(ip) = TryInto::<&[u8; 4]>::try_into(value).map(|bytes| IpAddr::from(*bytes)) {
        return Some(ip);
    }

    if let Ok(ip) = TryInto::<&[u8; 16]>::try_into(value).map(|bytes| IpAddr::from(*bytes)) {
        return Some(ip);
    }

    None
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
            "",
            ".",
            "-",
            ".-",
            "-.",
            ".-.",
            "[::",
            "::]",
            "@",
            // Non-ASCII inputs are invalid only when the `idna` feature is off.
            #[cfg(not(feature = "idna"))]
            "こんにちは",
            #[cfg(not(feature = "idna"))]
            "こんにちは.com",
        ] {
            assert!(Host::try_from(str).is_err(), "parsing {str}");
            assert!(Host::try_from(str.to_owned()).is_err(), "parsing {str}");
        }
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
        let h = Host::Address("127.0.0.1".parse().unwrap());
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
        let any: IpAddr = "127.0.0.1".parse().unwrap();
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
            Host::Address("127.0.0.1".parse().unwrap()),
            Host::Address("::1".parse().unwrap()),
            reg_host(b"exa%6Dple.com"),
            bracketed_host(b"v1.fe80::a"),
        ] {
            let r: HostRef<'_> = (&owned).into();
            assert_eq!(format!("{r}"), format!("{owned}"));
        }
    }
}
