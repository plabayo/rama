use super::Host;
use crate::error::{ErrorContext, OpaqueError};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with an associated port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority {
    host: Host,
    port: Option<u16>,
}

impl Authority {
    /// Creates a new [`Authority`].
    pub fn new(host: Host, port: Option<u16>) -> Self {
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

    /// Creates a new [`Authority`] with the given port.
    pub fn with_port(self, port: u16) -> Self {
        Authority {
            host: self.host,
            port: Some(port),
        }
    }

    /// Gets the port, if defined
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl From<Host> for Authority {
    fn from(host: Host) -> Self {
        Authority { host, port: None }
    }
}

impl From<(Host, u16)> for Authority {
    fn from((host, port): (Host, u16)) -> Self {
        Authority {
            host,
            port: Some(port),
        }
    }
}

impl From<(Host, Option<u16>)> for Authority {
    fn from((host, port): (Host, Option<u16>)) -> Self {
        Authority { host, port }
    }
}

impl From<Authority> for (Host, Option<u16>) {
    fn from(authority: Authority) -> (Host, Option<u16>) {
        (authority.host, authority.port)
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
            port: Some(addr.port()),
        }
    }
}

impl From<&SocketAddr> for Authority {
    fn from(addr: &SocketAddr) -> Self {
        Authority {
            host: Host::Address(addr.ip()),
            port: Some(addr.port()),
        }
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => match &self.host {
                Host::Name(domain) => write!(f, "{}:{}", domain, port),
                Host::Address(ip) => match ip {
                    std::net::IpAddr::V4(ip) => write!(f, "{}:{}", ip, port),
                    std::net::IpAddr::V6(ip) => write!(f, "[{}]:{}", ip, port),
                },
            },
            None => self.host.fmt(f),
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
        if let Ok(host) = Host::try_from(s) {
            // give priority to this, as to ensure that we do not eagerly parse
            // the port if it is not intended
            return Ok(Authority { host, port: None });
        }

        let (host, port) = try_to_split_port_from_str(s)?;
        let host = Host::try_from(host).context("parse host from authority")?;
        match host {
            Host::Address(IpAddr::V6(_)) if port.is_some() && !s.starts_with('[') => Err(
                OpaqueError::from_display("missing brackets for IPv6 address with port"),
            ),
            _ => Ok(Authority { host, port }),
        }
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

fn try_to_split_port_from_str(s: &str) -> Result<(&str, Option<u16>), OpaqueError> {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        Ok(match s[colon + 1..].parse() {
            Ok(port) => (&s[..colon], Some(port)),
            Err(_) => (s, None),
        })
    } else {
        Ok((s, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_eq(s: &str, authority: Authority, host: &str, port: Option<u16>) {
        assert_eq!(authority.host(), &host, "parsing: {}", s);
        assert_eq!(authority.port(), port, "parsing: {}", s);
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_host, expected_port)) in [
            ("example.com", ("example.com", None)),
            ("example.com:80", ("example.com", Some(80))),
            ("[::1]", ("::1", None)),
            ("[::1]:80", ("::1", Some(80))),
            ("127.0.0.1", ("127.0.0.1", None)),
            ("127.0.0.1:80", ("127.0.0.1", Some(80))),
            (
                "2001:db8:3333:4444:5555:6666:7777:8888",
                ("2001:db8:3333:4444:5555:6666:7777:8888", None),
            ),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]",
                ("2001:db8:3333:4444:5555:6666:7777:8888", None),
            ),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                ("2001:db8:3333:4444:5555:6666:7777:8888", Some(80)),
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
            ("example.com", "example.com"),
            ("example.com:80", "example.com:80"),
            ("::1", "::1"),
            ("[::1]", "::1"),
            ("::1:80", "::1:80"), // no port here!
            ("[::1]:80", "[::1]:80"),
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.0.1:80", "127.0.0.1:80"),
        ] {
            let msg = format!("parsing '{}'", s);
            let authority: Authority = s.parse().expect(&msg);
            assert_eq!(authority.to_string(), expected, "{}", msg);
        }
    }
}
