use super::Domain;
use crate::error::{ErrorContext, OpaqueError};
use crate::http::HeaderValue;
use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};

/// Either a [`Domain`] or an [`IpAddr`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// A domain.
    Name(Domain),

    /// An IP address.
    Address(IpAddr),
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
    fn eq(&self, other: &Host) -> bool {
        other == *self
    }
}

impl PartialEq<String> for Host {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<Host> for String {
    fn eq(&self, other: &Host) -> bool {
        other == self.as_str()
    }
}

impl From<Domain> for Host {
    fn from(domain: Domain) -> Self {
        Host::Name(domain)
    }
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        Host::Address(ip)
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
        Host::try_from(s)
    }
}

impl TryFrom<String> for Host {
    type Error = OpaqueError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        try_to_parse_str_to_ip(name.as_str())
            .map(Host::Address)
            .or_else(|| Domain::try_from(name).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<&str> for Host {
    type Error = OpaqueError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        try_to_parse_str_to_ip(name)
            .map(Host::Address)
            .or_else(|| Domain::try_from(name.to_owned()).ok().map(Host::Name))
            .context("parse host from string")
    }
}

impl TryFrom<HeaderValue> for Host {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

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
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

fn try_to_parse_str_to_ip(value: &str) -> Option<IpAddr> {
    if value.starts_with('[') || value.ends_with(']') {
        let value = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))?;
        Some(IpAddr::V6(value.parse::<Ipv6Addr>().ok()?))
    } else {
        value.parse::<IpAddr>().ok()
    }
}

fn try_to_parse_bytes_to_ip(value: &[u8]) -> Option<IpAddr> {
    if let Some(ip) = std::str::from_utf8(value)
        .ok()
        .and_then(try_to_parse_str_to_ip)
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
                Host::Address(address) => panic!(
                    "expected host address {} to be the domain: {}",
                    address, domain
                ),
                Host::Name(name) => assert_eq!(domain, name),
            },
            Is::Ip(ip) => match host {
                Host::Address(address) => assert_eq!(ip, address.to_string()),
                Host::Name(name) => panic!("expected host domain {} to be the ip: {}", name, ip),
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
            let msg = format!("parsing {}", str);
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
            let msg = format!("parsing {:?}", bytes);
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
            let msg = format!("parsing {}", str);
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
            assert!(Host::try_from(str).is_err(), "parsing {}", str);
            assert!(Host::try_from(str.to_owned()).is_err(), "parsing {}", str);
        }
    }
}
