use super::{Domain, parse_utils};
use crate::address::ip::{
    IPV4_BROADCAST, IPV4_LOCALHOST, IPV4_UNSPECIFIED, IPV6_LOCALHOST, IPV6_UNSPECIFIED,
};
use rama_core::error::{ErrorContext, OpaqueError};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "http")]
use rama_http_types::HeaderValue;

/// Either a [`Domain`] or an [`IpAddr`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// A domain.
    Name(Domain),

    /// An IP address.
    Address(IpAddr),
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
            Self::Address(_) => None,
        }
    }

    #[must_use]
    pub fn into_domain(self) -> Option<Domain> {
        match self {
            Self::Name(domain) => Some(domain),
            Self::Address(_) => None,
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
            Self::Name(_) => None,
            Self::Address(addr) => Some(addr),
        }
    }

    #[must_use]
    pub fn into_ip(self) -> Option<IpAddr> {
        match self {
            Self::Name(_) => None,
            Self::Address(addr) => Some(addr),
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
        matches!(self, Self::Address(IpAddr::V4(_)))
    }

    /// Returns [`Host`] as a string, only allocated if we need to render it.
    #[must_use]
    pub fn to_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Name(domain) => domain.as_str().into(),
            Self::Address(ip_addr) => ip_addr.to_string().into(),
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

impl PartialEq<str> for Host {
    fn eq(&self, other: &str) -> bool {
        match self {
            Self::Name(domain) => domain.as_str() == other,
            Self::Address(ip) => ip.to_string() == other,
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
        }
    }
}

impl std::str::FromStr for Host {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Host {
    type Error = OpaqueError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        parse_utils::try_to_parse_str_to_ip(name.as_str())
            .map(Host::Address)
            .or_else(|| Domain::try_from(name).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<&str> for Host {
    type Error = OpaqueError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        parse_utils::try_to_parse_str_to_ip(name)
            .map(Host::Address)
            .or_else(|| Domain::try_from(name.to_owned()).ok().map(Host::Name))
            .context("parse host from string")
    }
}

#[cfg(feature = "http")]
impl TryFrom<HeaderValue> for Host {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

#[cfg(feature = "http")]
impl TryFrom<&HeaderValue> for Host {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        header.to_str().context("convert header to str")?.try_into()
    }
}

impl TryFrom<Vec<u8>> for Host {
    type Error = OpaqueError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        try_to_parse_bytes_to_ip(name.as_slice())
            .map(Host::Address)
            .or_else(|| Domain::try_from(name).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<&[u8]> for Host {
    type Error = OpaqueError;

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
#[allow(clippy::expect_fun_call)]
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
            },
            Is::Ip(ip) => match host {
                Host::Address(address) => assert_eq!(ip, address.to_string()),
                Host::Name(name) => panic!("expected host domain {name} to be the ip: {ip}"),
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
            "こんにちは",
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
}
