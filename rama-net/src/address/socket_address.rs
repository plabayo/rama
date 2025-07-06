use crate::address::parse_utils::try_to_parse_str_to_ip;
use rama_core::error::{ErrorContext, OpaqueError};
#[cfg(feature = "http")]
use rama_http_types::HeaderValue;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

/// An [`IpAddr`] with an associated port
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddress {
    ip_addr: IpAddr,
    port: u16,
}

impl SocketAddress {
    /// creates a new [`SocketAddress`]
    pub const fn new(ip_addr: IpAddr, port: u16) -> Self {
        SocketAddress { ip_addr, port }
    }

    /// creates a new local ipv4 [`SocketAddress`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::SocketAddress;
    ///
    /// let addr = SocketAddress::local_ipv4(8080);
    /// assert_eq!("127.0.0.1:8080", addr.to_string());
    /// ```
    pub const fn local_ipv4(port: u16) -> Self {
        SocketAddress {
            ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        }
    }

    /// creates a new local ipv6 [`SocketAddress`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::SocketAddress;
    ///
    /// let addr = SocketAddress::local_ipv6(8080);
    /// assert_eq!("[::1]:8080", addr.to_string());
    /// ```
    pub const fn local_ipv6(port: u16) -> Self {
        SocketAddress {
            ip_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            port,
        }
    }

    /// creates a new default ipv4 [`SocketAddress`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::SocketAddress;
    ///
    /// let addr = SocketAddress::default_ipv4(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    pub const fn default_ipv4(port: u16) -> Self {
        SocketAddress {
            ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port,
        }
    }

    /// creates a new default ipv6 [`SocketAddress`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::SocketAddress;
    ///
    /// let addr = SocketAddress::default_ipv6(8080);
    /// assert_eq!("[::]:8080", addr.to_string());
    /// ```
    pub const fn default_ipv6(port: u16) -> Self {
        SocketAddress {
            ip_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            port,
        }
    }

    /// creates a new broadcast ipv4 [`SocketAddress`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::SocketAddress;
    ///
    /// let addr = SocketAddress::broadcast_ipv4(8080);
    /// assert_eq!("255.255.255.255:8080", addr.to_string());
    /// ```
    pub const fn broadcast_ipv4(port: u16) -> Self {
        SocketAddress {
            ip_addr: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            port,
        }
    }

    /// Gets the [`IpAddr`] reference.
    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    /// Gets the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Consume self into its parts: `(ip_addr, port)`
    pub fn into_parts(self) -> (IpAddr, u16) {
        (self.ip_addr, self.port)
    }
}

impl From<SocketAddress> for crate::socket::core::SockAddr {
    #[inline]
    fn from(addr: SocketAddress) -> Self {
        let std_addr: SocketAddr = addr.into();
        std_addr.into()
    }
}

impl From<&SocketAddress> for crate::socket::core::SockAddr {
    #[inline]
    fn from(addr: &SocketAddress) -> Self {
        let std_addr: SocketAddr = (*addr).into();
        std_addr.into()
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(addr: SocketAddr) -> Self {
        SocketAddress {
            ip_addr: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<&SocketAddr> for SocketAddress {
    fn from(addr: &SocketAddr) -> Self {
        SocketAddress {
            ip_addr: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<SocketAddrV4> for SocketAddress {
    fn from(value: SocketAddrV4) -> Self {
        SocketAddress {
            ip_addr: (*value.ip()).into(),
            port: value.port(),
        }
    }
}

impl From<SocketAddrV6> for SocketAddress {
    fn from(value: SocketAddrV6) -> Self {
        SocketAddress {
            ip_addr: (*value.ip()).into(),
            port: value.port(),
        }
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(addr: SocketAddress) -> Self {
        SocketAddr::new(addr.ip_addr, addr.port)
    }
}

impl From<(IpAddr, u16)> for SocketAddress {
    #[inline]
    fn from((ip_addr, port): (IpAddr, u16)) -> Self {
        Self { ip_addr, port }
    }
}

impl From<(Ipv4Addr, u16)> for SocketAddress {
    #[inline]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        Self {
            ip_addr: ip.into(),
            port,
        }
    }
}

impl From<([u8; 4], u16)> for SocketAddress {
    #[inline]
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        let ip: IpAddr = ip.into();
        (ip, port).into()
    }
}

impl From<(Ipv6Addr, u16)> for SocketAddress {
    #[inline]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        Self {
            ip_addr: ip.into(),
            port,
        }
    }
}

impl From<([u8; 16], u16)> for SocketAddress {
    #[inline]
    fn from((ip, port): ([u8; 16], u16)) -> Self {
        let ip: IpAddr = ip.into();
        (ip, port).into()
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ip_addr {
            IpAddr::V4(ip) => write!(f, "{}:{}", ip, self.port),
            IpAddr::V6(ip) => write!(f, "[{}]:{}", ip, self.port),
        }
    }
}

impl FromStr for SocketAddress {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddress::try_from(s)
    }
}

impl TryFrom<String> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&String> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (ip_addr, port) = crate::address::parse_utils::split_port_from_str(s)?;
        let ip_addr =
            try_to_parse_str_to_ip(ip_addr).context("parse ip address from socket address")?;
        match ip_addr {
            IpAddr::V6(_) if !s.starts_with('[') => Err(OpaqueError::from_display(
                "missing brackets for IPv6 address with port",
            )),
            _ => Ok(SocketAddress { ip_addr, port }),
        }
    }
}

#[cfg(feature = "http")]
impl TryFrom<HeaderValue> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

#[cfg(feature = "http")]
impl TryFrom<&HeaderValue> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        header.to_str().context("convert header to str")?.try_into()
    }
}

impl TryFrom<Vec<u8>> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for SocketAddress {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse sock address from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for SocketAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SocketAddress {
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

    fn assert_eq(s: &str, sock_address: SocketAddress, ip_addr: &str, port: u16) {
        assert_eq!(sock_address.ip_addr().to_string(), ip_addr, "parsing: {s}");
        assert_eq!(sock_address.port(), port, "parsing: {s}");
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_ip_addr, expected_port)) in [
            ("[::1]:80", ("::1", 80)),
            ("127.0.0.1:80", ("127.0.0.1", 80)),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                ("2001:db8:3333:4444:5555:6666:7777:8888", 80),
            ),
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq(s, s.parse().expect(&msg), expected_ip_addr, expected_port);
            assert_eq(
                s,
                s.try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq(
                s,
                s.to_owned().try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().to_vec().try_into().expect(&msg),
                expected_ip_addr,
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
            "example.com:80",
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
        ] {
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<SocketAddress>().is_err(), "{msg}");
            assert!(SocketAddress::try_from(s).is_err(), "{msg}");
            assert!(SocketAddress::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(SocketAddress::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(
                SocketAddress::try_from(s.as_bytes().to_vec()).is_err(),
                "{msg}",
            );
        }
    }

    #[test]
    fn test_parse_display() {
        for (s, expected) in [("[::1]:80", "[::1]:80"), ("127.0.0.1:80", "127.0.0.1:80")] {
            let msg = format!("parsing '{s}'");
            let socket_address: SocketAddress = s.parse().expect(&msg);
            assert_eq!(socket_address.to_string(), expected, "{msg}");
        }
    }
}
