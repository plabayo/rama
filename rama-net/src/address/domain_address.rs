use crate::Protocol;
use crate::address::{Domain, parse_utils};
use rama_core::error::{BoxError, ErrorContext};
use rama_utils::macros::generate_set_and_with;
use std::fmt;
use std::str::FromStr;

/// A [`Domain`] with an associated port (u16)
///
/// Example: `example.com:80`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainAddress {
    pub domain: Domain,
    pub port: u16,
}

impl DomainAddress {
    /// Creates a new [`DomainAddress`].
    #[must_use]
    #[inline(always)]
    pub const fn new(domain: Domain, port: u16) -> Self {
        Self { domain, port }
    }

    /// Creates a new example [`DomainAddress`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_http() -> Self {
        Self {
            domain: Domain::example(),
            port: Protocol::HTTP_DEFAULT_PORT,
        }
    }

    /// Creates a new example [`DomainAddress`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_https() -> Self {
        Self {
            domain: Domain::example(),
            port: Protocol::HTTPS_DEFAULT_PORT,
        }
    }

    /// Creates a new example [`DomainAddress`] for given port.
    #[must_use]
    #[inline(always)]
    pub const fn example_with_port(port: u16) -> Self {
        Self {
            domain: Domain::example(),
            port,
        }
    }

    /// Creates a new localhost [`DomainAddress`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_http() -> Self {
        Self {
            domain: Domain::tld_localhost(),
            port: Protocol::HTTP_DEFAULT_PORT,
        }
    }

    /// Creates a new localhost [`DomainAddress`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_https() -> Self {
        Self {
            domain: Domain::tld_localhost(),
            port: Protocol::HTTPS_DEFAULT_PORT,
        }
    }

    /// Creates a new localhost [`DomainAddress`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_with_port(port: u16) -> Self {
        Self {
            domain: Domain::tld_localhost(),
            port,
        }
    }

    generate_set_and_with! {
        /// Set [`Domain`] of [`DomainAddress`]
        pub fn domain(mut self, domain: Domain) -> Self {
            self.domain = domain;
            self
        }
    }

    generate_set_and_with! {
        /// Set port (u16) of [`DomainAddress`]
        pub fn port(mut self, port: u16) -> Self {
            self.port = port;
            self
        }
    }
}

impl From<(Domain, u16)> for DomainAddress {
    #[inline]
    fn from((domain, port): (Domain, u16)) -> Self {
        Self::new(domain, port)
    }
}

impl fmt::Display for DomainAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.domain, self.port)
    }
}

impl FromStr for DomainAddress {
    type Err = BoxError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for DomainAddress {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (domain, port) = parse_utils::split_port_from_str(s)?;
        let domain = Domain::from_str(domain)?;
        Ok(Self::new(domain, port))
    }
}

impl TryFrom<String> for DomainAddress {
    type Error = BoxError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (domain, port) = parse_utils::split_port_from_str(&s)?;
        let domain = Domain::from_str(domain)?;
        Ok(Self::new(domain, port))
    }
}
impl TryFrom<Vec<u8>> for DomainAddress {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse domain_address from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for DomainAddress {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse domain_address from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for DomainAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DomainAddress {
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

    #[allow(clippy::needless_pass_by_value)]
    fn assert_eq(s: &str, domain_address: DomainAddress, domain: &str, port: u16) {
        assert_eq!(domain_address.domain.as_str(), domain, "parsing: {s}");
        assert_eq!(domain_address.port, port, "parsing: {s}");
    }

    #[test]
    fn test_valid_domain_address() {
        for (s, (expected_domain, expected_port)) in [
            ("example.com:80", ("example.com", 80)),
            ("subdomain.example.com:443", ("subdomain.example.com", 443)),
            ("127.0.0.1:8080", ("127.0.0.1", 8080)),
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq(s, s.parse().expect(&msg), expected_domain, expected_port);
            assert_eq(s, s.try_into().expect(&msg), expected_domain, expected_port);
            assert_eq(
                s,
                s.to_owned().try_into().expect(&msg),
                expected_domain,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().try_into().expect(&msg),
                expected_domain,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().to_vec().try_into().expect(&msg),
                expected_domain,
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
            "::1:8080",
            "127.0.0.1",
            "[::1]",
            "example",
            "exa$mple.com:8080",
            "2001:db8:3333:4444:5555:6666:7777:8888:8080",
            "2001:db8:3333:4444:5555:6666:7777:8888",
            "[2001:db8:3333:4444:5555:6666:7777:8888]",
            "[2001:db8:3333:4444:5555:6666:7777:8888]:8080",
            "example.com",
            "example.com:",
            "example.com:-1",
            "example.com:999999",
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
        ] {
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<DomainAddress>().is_err(), "{msg}");
            assert!(DomainAddress::try_from(s).is_err(), "{msg}");
            assert!(DomainAddress::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(DomainAddress::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(
                DomainAddress::try_from(s.as_bytes().to_vec()).is_err(),
                "{msg}"
            );
        }
    }

    #[test]
    fn test_parse_display() {
        for (s, expected) in [
            ("example.com:80", "example.com:80"),
            ("subdomain.example.com:443", "subdomain.example.com:443"),
        ] {
            let msg = format!("parsing '{s}'");
            let domain_address: DomainAddress = s.parse().expect(&msg);
            assert_eq!(domain_address.to_string(), expected, "{msg}");
        }
    }
}
