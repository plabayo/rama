use crate::Protocol;

use super::{Domain, DomainAddress, Host, SocketAddress, parse_utils};
use rama_core::error::{ErrorContext, OpaqueError};
use rama_utils::macros::generate_set_and_with;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with an associated port.
///
/// ## Examples
///
/// - `example.com:80`
/// - `127.0.0.1:80`
/// - `[::]:80`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostWithPort {
    pub host: Host,
    pub port: u16,
}

impl HostWithPort {
    /// Creates a new [`HostWithPort`].
    #[must_use]
    #[inline(always)]
    pub const fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// creates a new local ipv4 [`HostWithPort`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithPort;
    ///
    /// let addr = HostWithPort::local_ipv4(8080);
    /// assert_eq!("127.0.0.1:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv4(port: u16) -> Self {
        Self {
            host: Host::LOCALHOST_IPV4,
            port,
        }
    }

    /// creates a new local ipv6 [`HostWithPort`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithPort;
    ///
    /// let addr = HostWithPort::local_ipv6(8080);
    /// assert_eq!("[::1]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv6(port: u16) -> Self {
        Self {
            host: Host::LOCALHOST_IPV6,
            port,
        }
    }

    /// creates a new default ipv4 [`HostWithPort`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithPort;
    ///
    /// let addr = HostWithPort::default_ipv4(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv4(port: u16) -> Self {
        Self {
            host: Host::DEFAULT_IPV4,
            port,
        }
    }

    /// creates a new default ipv6 [`HostWithPort`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithPort;
    ///
    /// let addr = HostWithPort::default_ipv6(8080);
    /// assert_eq!("[::]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv6(port: u16) -> Self {
        Self {
            host: Host::DEFAULT_IPV6,
            port,
        }
    }

    /// creates a new broadcast ipv4 [`HostWithPort`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithPort;
    ///
    /// let addr = HostWithPort::broadcast_ipv4(8080);
    /// assert_eq!("255.255.255.255:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn broadcast_ipv4(port: u16) -> Self {
        Self {
            host: Host::BROADCAST_IPV4,
            port,
        }
    }

    /// Creates a new example domain [`HostWithPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_http() -> Self {
        Self::example_domain_with_port(Protocol::HTTP_DEFAULT_PORT)
    }

    /// Creates a new example [`HostWithPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_https() -> Self {
        Self::example_domain_with_port(Protocol::HTTPS_DEFAULT_PORT)
    }

    /// Creates a new example [`HostWithPort`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_with_port(port: u16) -> Self {
        Self {
            host: Host::EXAMPLE_NAME,
            port,
        }
    }

    /// Creates a new localhost [`HostWithPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_http() -> Self {
        Self::localhost_domain_with_port(Protocol::HTTP_DEFAULT_PORT)
    }

    /// Creates a new localhost [`HostWithPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_https() -> Self {
        Self::localhost_domain_with_port(Protocol::HTTPS_DEFAULT_PORT)
    }

    /// Creates a new localhost [`DomainAddress`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_with_port(port: u16) -> Self {
        Self {
            host: Host::LOCALHOST_NAME,
            port,
        }
    }

    generate_set_and_with! {
        /// Set [`Host`] of [`HostWithPort`]
        pub fn host(mut self, host: Host) -> Self {
            self.host = host;
            self
        }
    }

    generate_set_and_with! {
        /// Set port (u16) of [`HostWithPort`]
        pub fn port(mut self, port: u16) -> Self {
            self.port = port;
            self
        }
    }
}

impl From<(Domain, u16)> for HostWithPort {
    #[inline]
    fn from((domain, port): (Domain, u16)) -> Self {
        (Host::Name(domain), port).into()
    }
}

impl From<(IpAddr, u16)> for HostWithPort {
    #[inline]
    fn from((ip, port): (IpAddr, u16)) -> Self {
        (Host::Address(ip), port).into()
    }
}

impl From<(Ipv4Addr, u16)> for HostWithPort {
    #[inline]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        (Host::Address(IpAddr::V4(ip)), port).into()
    }
}

impl From<([u8; 4], u16)> for HostWithPort {
    #[inline]
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        (Host::Address(IpAddr::V4(ip.into())), port).into()
    }
}

impl From<(Ipv6Addr, u16)> for HostWithPort {
    #[inline]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        (Host::Address(IpAddr::V6(ip)), port).into()
    }
}

impl From<([u8; 16], u16)> for HostWithPort {
    #[inline]
    fn from((ip, port): ([u8; 16], u16)) -> Self {
        (Host::Address(IpAddr::V6(ip.into())), port).into()
    }
}

impl From<(Host, u16)> for HostWithPort {
    fn from((host, port): (Host, u16)) -> Self {
        Self { host, port }
    }
}

impl From<HostWithPort> for Host {
    fn from(hwp: HostWithPort) -> Self {
        hwp.host
    }
}

impl From<SocketAddr> for HostWithPort {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: Host::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl From<&SocketAddr> for HostWithPort {
    fn from(addr: &SocketAddr) -> Self {
        Self {
            host: Host::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl From<SocketAddress> for HostWithPort {
    fn from(addr: SocketAddress) -> Self {
        let SocketAddress { ip_addr, port } = addr;
        Self {
            host: Host::Address(ip_addr),
            port,
        }
    }
}

impl From<&SocketAddress> for HostWithPort {
    fn from(addr: &SocketAddress) -> Self {
        Self {
            host: Host::Address(addr.ip_addr),
            port: addr.port,
        }
    }
}

impl From<DomainAddress> for HostWithPort {
    fn from(addr: DomainAddress) -> Self {
        let DomainAddress { domain, port } = addr;
        Self::from((domain, port))
    }
}

impl fmt::Display for HostWithPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Name(domain) => write!(f, "{}:{}", domain, self.port),
            Host::Address(ip) => match ip {
                IpAddr::V4(ip) => write!(f, "{}:{}", ip, self.port),
                IpAddr::V6(ip) => write!(f, "[{}]:{}", ip, self.port),
            },
        }
    }
}

impl std::str::FromStr for HostWithPort {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for HostWithPort {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&str> for HostWithPort {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (host, port) = parse_utils::split_port_from_str(s)?;
        let host = Host::try_from(host).context("parse host from host-with-port")?;
        match host {
            Host::Address(IpAddr::V6(_)) if !s.starts_with('[') => Err(OpaqueError::from_display(
                "missing brackets for IPv6 address with port (in host-with-port)",
            )),
            _ => Ok(Self { host, port }),
        }
    }
}

impl TryFrom<Vec<u8>> for HostWithPort {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse host-with-port from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for HostWithPort {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse host-with-port from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for HostWithPort {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for HostWithPort {
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
    fn assert_eq(s: &str, host_with_port: HostWithPort, host: &str, port: u16) {
        assert_eq!(host_with_port.host, host, "parsing: {s}");
        assert_eq!(host_with_port.port, port, "parsing: {s}");
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
            let msg = format!("parsing '{s}'");

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
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<HostWithPort>().is_err(), "{msg}");
            assert!(HostWithPort::try_from(s).is_err(), "{msg}");
            assert!(HostWithPort::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(HostWithPort::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(
                HostWithPort::try_from(s.as_bytes().to_vec()).is_err(),
                "{msg}"
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
            let msg = format!("parsing '{s}'");
            let host_with_port: HostWithPort = s.parse().expect(&msg);
            assert_eq!(host_with_port.to_string(), expected, "{msg}");
        }
    }
}
