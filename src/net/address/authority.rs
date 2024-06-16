use super::Host;
use crate::error::{ErrorContext, ErrorExt, OpaqueError};
use crate::http::HeaderValue;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with an associated port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority {
    host: Host,
    port: u16,
}

impl Authority {
    /// Creates a new [`Authority`].
    pub fn new(host: Host, port: u16) -> Self {
        Authority { host, port }
    }

    /// Gets the [`Host`] reference.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Consumes the [`Authority`] and returns the [`Host`].
    pub fn into_host(self) -> Host {
        self.host
    }

    /// Gets the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Consume self into its parts: `(host, port)`
    pub fn into_parts(self) -> (Host, u16) {
        (self.host, self.port)
    }
}

impl From<(Host, u16)> for Authority {
    fn from((host, port): (Host, u16)) -> Self {
        Authority { host, port }
    }
}

impl From<Authority> for Host {
    fn from(authority: Authority) -> Host {
        authority.host
    }
}

impl From<SocketAddr> for Authority {
    fn from(addr: SocketAddr) -> Self {
        Authority {
            host: Host::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl From<&SocketAddr> for Authority {
    fn from(addr: &SocketAddr) -> Self {
        Authority {
            host: Host::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Name(domain) => write!(f, "{}:{}", domain, self.port),
            Host::Address(ip) => match ip {
                std::net::IpAddr::V4(ip) => write!(f, "{}:{}", ip, self.port),
                std::net::IpAddr::V6(ip) => write!(f, "[{}]:{}", ip, self.port),
            },
        }
    }
}

impl std::str::FromStr for Authority {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Authority::try_from(s)
    }
}

impl TryFrom<String> for Authority {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&str> for Authority {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (host, port) = split_port_from_str(s)?;
        let host = Host::try_from(host).context("parse host from authority")?;
        match host {
            Host::Address(IpAddr::V6(_)) if !s.starts_with('[') => Err(OpaqueError::from_display(
                "missing brackets for IPv6 address with port",
            )),
            _ => Ok(Authority { host, port }),
        }
    }
}

impl TryFrom<HeaderValue> for Authority {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

impl TryFrom<&HeaderValue> for Authority {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        header.to_str().context("convert header to str")?.try_into()
    }
}

impl TryFrom<Vec<u8>> for Authority {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse authority from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for Authority {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse authority from bytes")?;
        s.try_into()
    }
}

fn split_port_from_str(s: &str) -> Result<(&str, u16), OpaqueError> {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => Ok((&s[..colon], port)),
            Err(err) => Err(err.context("parse port as u16")),
        }
    } else {
        Err(OpaqueError::from_display("missing port"))
    }
}

impl serde::Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_eq(s: &str, authority: Authority, host: &str, port: u16) {
        assert_eq!(authority.host(), &host, "parsing: {}", s);
        assert_eq!(authority.port(), port, "parsing: {}", s);
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_host, expected_port)) in [
            ("example.com:80", ("example.com", 80)),
            ("[::1]:80", ("::1", 80)),
            ("127.0.0.1:80", ("127.0.0.1", 80)),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                ("2001:db8:3333:4444:5555:6666:7777:8888", 80),
            ),
        ] {
            let msg = format!("parsing '{}'", s);

            assert_eq(s, s.parse().expect(&msg), expected_host, expected_port);
            assert_eq(s, s.try_into().expect(&msg), expected_host, expected_port);
            assert_eq(
                s,
                s.to_owned().try_into().expect(&msg),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().try_into().expect(&msg),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().to_vec().try_into().expect(&msg),
                expected_host,
                expected_port,
            );
        }
    }

    #[test]
    fn test_parse_invalid() {
        for s in [
            "",
            "-",
            ".",
            ":",
            ":80",
            "-.",
            ".-",
            "::1",
            "127.0.0.1",
            "[::1]",
            "2001:db8:3333:4444:5555:6666:7777:8888",
            "[2001:db8:3333:4444:5555:6666:7777:8888]",
            "example.com",
            "example.com:",
            "example.com:-1",
            "example.com:999999",
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
        ] {
            let msg = format!("parsing '{}'", s);
            assert!(s.parse::<Authority>().is_err(), "{}", msg);
            assert!(Authority::try_from(s).is_err(), "{}", msg);
            assert!(Authority::try_from(s.to_owned()).is_err(), "{}", msg);
            assert!(Authority::try_from(s.as_bytes()).is_err(), "{}", msg);
            assert!(
                Authority::try_from(s.as_bytes().to_vec()).is_err(),
                "{}",
                msg
            );
        }
    }

    #[test]
    fn test_parse_display() {
        for (s, expected) in [
            ("example.com:80", "example.com:80"),
            ("[::1]:80", "[::1]:80"),
            ("127.0.0.1:80", "127.0.0.1:80"),
        ] {
            let msg = format!("parsing '{}'", s);
            let authority: Authority = s.parse().expect(&msg);
            assert_eq!(authority.to_string(), expected, "{}", msg);
        }
    }
}
