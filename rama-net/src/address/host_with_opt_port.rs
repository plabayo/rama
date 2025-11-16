use crate::Protocol;
use crate::address::HostWithPort;

use super::{Domain, DomainAddress, Host, SocketAddress};
use rama_core::error::{ErrorContext, OpaqueError};
use rama_utils::macros::generate_set_and_with;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with optionally a port.
///
/// ## Examples
///
/// - `example.com`
/// - `127.0.0.1`
/// - `::`
/// - `example.com:80`
/// - `127.0.0.1:80`
/// - `[::]:80`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostWithOptPort {
    pub host: Host,
    pub port: Option<u16>,
}

impl HostWithOptPort {
    /// Creates a new [`HostWithOptPort`] from a [`Host`].
    #[must_use]
    #[inline(always)]
    pub const fn new(host: Host) -> Self {
        Self { host, port: None }
    }

    /// Creates a new [`HostWithOptPort`] from a [`Host`] and port.
    #[must_use]
    #[inline(always)]
    pub const fn new_with_port(host: Host, port: u16) -> Self {
        Self {
            host,
            port: Some(port),
        }
    }

    /// creates a new local ipv4 [`HostWithOptPort`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::local_ipv4();
    /// assert_eq!("127.0.0.1", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv4() -> Self {
        Self::new(Host::LOCALHOST_IPV4)
    }

    /// creates a new local ipv4 [`HostWithOptPort`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::local_ipv4_with_port(8080);
    /// assert_eq!("127.0.0.1:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv4_with_port(port: u16) -> Self {
        Self::new_with_port(Host::LOCALHOST_IPV4, port)
    }

    /// creates a new local ipv6 [`HostWithOptPort`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::local_ipv6();
    /// assert_eq!("::1", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv6() -> Self {
        Self::new(Host::LOCALHOST_IPV6)
    }

    /// creates a new local ipv6 [`HostWithOptPort`] with the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::local_ipv6_with_port(8080);
    /// assert_eq!("[::1]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv6_with_port(port: u16) -> Self {
        Self::new_with_port(Host::LOCALHOST_IPV6, port)
    }

    /// creates a default ipv4 [`HostWithOptPort`] without a port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::default_ipv4_with_port(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv4() -> Self {
        Self::new(Host::DEFAULT_IPV4)
    }

    /// creates a default ipv4 [`HostWithOptPort`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::default_ipv4_with_port(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv4_with_port(port: u16) -> Self {
        Self::new_with_port(Host::DEFAULT_IPV4, port)
    }

    /// creates a new default ipv6 [`HostWithOptPort`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::default_ipv6();
    /// assert_eq!("::", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv6() -> Self {
        Self::new(Host::DEFAULT_IPV6)
    }

    /// creates a new default ipv6 [`HostWithOptPort`] with the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::default_ipv6_with_port(8080);
    /// assert_eq!("[::]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv6_with_port(port: u16) -> Self {
        Self::new_with_port(Host::DEFAULT_IPV6, port)
    }

    /// creates a new broadcast ipv4 [`HostWithOptPort`] without a port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::broadcast_ipv4();
    /// assert_eq!("255.255.255.255", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn broadcast_ipv4() -> Self {
        Self::new(Host::BROADCAST_IPV4)
    }

    /// creates a new broadcast ipv4 [`HostWithOptPort`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::HostWithOptPort;
    ///
    /// let addr = HostWithOptPort::broadcast_ipv4_with_port(8080);
    /// assert_eq!("255.255.255.255:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn broadcast_ipv4_with_port(port: u16) -> Self {
        Self::new_with_port(Host::BROADCAST_IPV4, port)
    }

    /// Creates a new example domain [`HostWithOptPort`] without a port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain() -> Self {
        Self {
            host: Host::EXAMPLE_NAME,
            port: None,
        }
    }

    /// Creates a new example domain [`HostWithOptPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_http() -> Self {
        Self::example_domain_with_port(Protocol::HTTP_DEFAULT_PORT)
    }

    /// Creates a new example domain [`HostWithOptPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_https() -> Self {
        Self::example_domain_with_port(Protocol::HTTPS_DEFAULT_PORT)
    }

    /// Creates a new example domain [`HostWithOptPort`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_with_port(port: u16) -> Self {
        Self {
            host: Host::EXAMPLE_NAME,
            port: Some(port),
        }
    }

    /// Creates a new localhost domain [`HostWithOptPort`] without a port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain() -> Self {
        Self {
            host: Host::LOCALHOST_NAME,
            port: None,
        }
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_http() -> Self {
        Self::localhost_domain_with_port(Protocol::HTTP_DEFAULT_PORT)
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_https() -> Self {
        Self::localhost_domain_with_port(Protocol::HTTPS_DEFAULT_PORT)
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_with_port(port: u16) -> Self {
        Self {
            host: Host::LOCALHOST_NAME,
            port: Some(port),
        }
    }

    generate_set_and_with! {
        /// Set [`Host`] of [`HostWithOptPort`]
        pub fn host(mut self, host: Host) -> Self {
            self.host = host;
            self
        }
    }

    generate_set_and_with! {
        /// (un)set port (u16) of [`HostWithOptPort`]
        pub fn port(mut self, port: Option<u16>) -> Self {
            self.port = port;
            self
        }
    }
}

impl From<(Domain, u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((domain, port): (Domain, u16)) -> Self {
        (Host::Name(domain), port).into()
    }
}

impl From<(IpAddr, u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((ip, port): (IpAddr, u16)) -> Self {
        (Host::Address(ip), port).into()
    }
}

impl From<(Ipv4Addr, u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        (Host::Address(IpAddr::V4(ip)), port).into()
    }
}

impl From<([u8; 4], u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        (Host::Address(IpAddr::V4(ip.into())), port).into()
    }
}

impl From<(Ipv6Addr, u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        (Host::Address(IpAddr::V6(ip)), port).into()
    }
}

impl From<([u8; 16], u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((ip, port): ([u8; 16], u16)) -> Self {
        (Host::Address(IpAddr::V6(ip.into())), port).into()
    }
}

impl From<Host> for HostWithOptPort {
    #[inline(always)]
    fn from(host: Host) -> Self {
        Self::new(host)
    }
}

impl From<(Host, u16)> for HostWithOptPort {
    #[inline(always)]
    fn from((host, port): (Host, u16)) -> Self {
        Self::new_with_port(host, port)
    }
}

impl From<HostWithOptPort> for Host {
    #[inline(always)]
    fn from(hwop: HostWithOptPort) -> Self {
        hwop.host
    }
}

impl From<SocketAddr> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: SocketAddr) -> Self {
        Self::new_with_port(Host::Address(addr.ip()), addr.port())
    }
}

impl From<&SocketAddr> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: &SocketAddr) -> Self {
        Self::new_with_port(Host::Address(addr.ip()), addr.port())
    }
}

impl From<HostWithPort> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: HostWithPort) -> Self {
        let HostWithPort { host, port } = addr;
        Self::new_with_port(host, port)
    }
}

impl From<SocketAddress> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: SocketAddress) -> Self {
        let SocketAddress { ip_addr, port } = addr;
        Self::new_with_port(Host::Address(ip_addr), port)
    }
}

impl From<&SocketAddress> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: &SocketAddress) -> Self {
        Self::new_with_port(Host::Address(addr.ip_addr), addr.port)
    }
}

impl From<DomainAddress> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: DomainAddress) -> Self {
        let DomainAddress { domain, port } = addr;
        Self::from((domain, port))
    }
}

impl fmt::Display for HostWithOptPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            host @ (Host::Name(_) | Host::Address(IpAddr::V4(_))) => host.fmt(f)?,
            Host::Address(IpAddr::V6(ip)) => {
                if self.port.is_some() {
                    write!(f, "[{ip}]")
                } else {
                    ip.fmt(f)
                }?
            }
        }

        if let Some(port) = self.port {
            write!(f, ":{port}")?
        }

        Ok(())
    }
}

impl std::str::FromStr for HostWithOptPort {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for HostWithOptPort {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        try_from_maybe_borrowed_str(s.into())
    }
}

impl TryFrom<&str> for HostWithOptPort {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        try_from_maybe_borrowed_str(s.into())
    }
}

fn try_from_maybe_borrowed_str(
    maybe_borrowed: Cow<'_, str>,
) -> Result<HostWithOptPort, OpaqueError> {
    let s = maybe_borrowed.as_ref();

    if s.is_empty() {
        return Err(OpaqueError::from_display(
            "empty string is invalid host (with opt port)",
        ));
    }

    let host;
    let mut port = None;

    if let Some(last_colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        let first_part = &s[..last_colon];
        if first_part.contains(':') {
            // ipv6
            if first_part.starts_with('[') || first_part.ends_with(']') {
                let value = first_part
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .context("strip brackets from host-with-opt-port ipv6 host w/ trailing port")?;
                host = Host::Address(IpAddr::V6(
                    value
                        .parse::<Ipv6Addr>()
                        .context("parse host-with-opt-port' host as Ipv6 w/ trailing port")?,
                ));

                port = Some(
                    s[last_colon + 1..]
                        .parse()
                        .context("parse host-with-opt-port's port string as u16")?,
                );
            } else {
                host = Host::Address(IpAddr::V6(
                    s.parse::<Ipv6Addr>()
                        .context("parse host-with-opt-port's host as ipv6 w/o trailing port")?,
                ));
            };
        } else {
            port = Some(
                s[last_colon + 1..]
                    .parse()
                    .context("parse host-with-opt-port's port string as u16")?,
            );

            // try ipv4 first, domain afterwards
            host = if let Ok(ipv4) = first_part.parse::<Ipv4Addr>() {
                Host::Address(IpAddr::V4(ipv4))
            } else {
                let mut owned_vec = maybe_borrowed.into_owned().into_bytes();
                owned_vec.truncate(last_colon);
                let owned_str = String::from_utf8(owned_vec)
                    .context("interpret host-with-opt-port's host as utf-8 str")?;
                Host::Name(Domain::try_from(owned_str).context(
                    "parse host-with-opt-port's host utf-8 str as domain w/ trailing port",
                )?)
            };
        };
    } else {
        // no port, so either IpAddr or Domain, in that order
        host =
            if let Ok(ip) = s.parse::<IpAddr>() {
                Host::Address(ip)
            } else {
                let owned_str = maybe_borrowed.into_owned();
                Host::Name(Domain::try_from(owned_str).context(
                    "parse host utf-8 str as domain w/o trailing port (host-with-opt-port)",
                )?)
            };
    }

    Ok(HostWithOptPort { host, port })
}

impl TryFrom<Vec<u8>> for HostWithOptPort {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse host-with-opt-port from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for HostWithOptPort {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse host-with-opt-port from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for HostWithOptPort {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for HostWithOptPort {
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
    fn assert_eq(s: &str, hwop: HostWithOptPort, host: &str, port: Option<u16>) {
        assert_eq!(hwop.host, host, "parsing: {s}");
        assert_eq!(hwop.port, port, "parsing: {s}");
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_host, expected_port)) in [
            ("example.com", ("example.com", None)),
            ("example.com:80", ("example.com", Some(80))),
            ("::1", ("::1", None)),
            ("[::1]:80", ("::1", Some(80))),
            ("127.0.0.1", ("127.0.0.1", None)),
            ("127.0.0.1:80", ("127.0.0.1", Some(80))),
            (
                "2001:db8:3333:4444:5555:6666:7777:8888",
                ("2001:db8:3333:4444:5555:6666:7777:8888", None),
            ),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                ("2001:db8:3333:4444:5555:6666:7777:8888", Some(80)),
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
            "[::1]",
            "2001:db8:3333:4444:5555:6666:7777:8888]",
            "[2001:db8:3333:4444:5555:6666:7777:8888]",
            "[2001:db8:3333:4444:5555:6666:7777:8888",
            "example.com:",
            "example.com:-1",
            "example.com:999999",
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
        ] {
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<HostWithOptPort>().is_err(), "{msg}");
            assert!(HostWithOptPort::try_from(s).is_err(), "{msg}");
            assert!(HostWithOptPort::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(HostWithOptPort::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(
                HostWithOptPort::try_from(s.as_bytes().to_vec()).is_err(),
                "{msg}"
            );
        }
    }

    #[test]
    fn test_parse_display() {
        for (s, expected) in [
            ("example.com", "example.com"),
            ("example.com:80", "example.com:80"),
            ("[::1]:80", "[::1]:80"),
            ("::1", "::1"),
            ("127.0.0.1:80", "127.0.0.1:80"),
            ("127.0.0.1", "127.0.0.1"),
        ] {
            let msg = format!("parsing '{s}'");
            let hwop: HostWithOptPort = s.parse().expect(&msg);
            assert_eq!(hwop.to_string(), expected, "{msg}");
        }
    }
}
