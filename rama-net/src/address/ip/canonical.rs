use std::net::{IpAddr, SocketAddr};

use crate::address::{Authority, Host, HostWithOptPort, HostWithPort, ProxyAddress, SocketAddress};

/// Converts an IP address into a canonical representation.
///
/// Canonical means:
/// - IPv4 stays IPv4.
/// - IPv6 stays IPv6, except when the IPv6 address is an IPv4 mapped address.
///   In that cases we convert it to the embedded IPv4 address.
pub trait IntoCanonicalIpAddr {
    fn into_canonical_ip_addr(self) -> Self;
}

impl IntoCanonicalIpAddr for IpAddr {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        self.to_canonical()
    }
}

impl IntoCanonicalIpAddr for SocketAddress {
    #[inline(always)]
    fn into_canonical_ip_addr(mut self) -> Self {
        self.ip_addr = self.ip_addr.into_canonical_ip_addr();
        self
    }
}

impl IntoCanonicalIpAddr for SocketAddr {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        let ip_addr = self.ip().into_canonical_ip_addr();
        Self::new(ip_addr, self.port())
    }
}

impl IntoCanonicalIpAddr for Host {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        match self {
            Self::Name(_) => self,
            Self::Address(ip_addr) => Self::Address(ip_addr.into_canonical_ip_addr()),
        }
    }
}

impl IntoCanonicalIpAddr for HostWithPort {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        Self {
            host: self.host.into_canonical_ip_addr(),
            port: self.port,
        }
    }
}

impl IntoCanonicalIpAddr for HostWithOptPort {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        Self {
            host: self.host.into_canonical_ip_addr(),
            port: self.port,
        }
    }
}

impl IntoCanonicalIpAddr for ProxyAddress {
    #[inline(always)]
    fn into_canonical_ip_addr(self) -> Self {
        Self {
            protocol: self.protocol,
            address: self.address.into_canonical_ip_addr(),
            credential: self.credential,
        }
    }
}

impl IntoCanonicalIpAddr for Authority {
    fn into_canonical_ip_addr(self) -> Self {
        Self {
            user_info: self.user_info,
            address: self.address.into_canonical_ip_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_loopback_is_unchanged() {
        let socket_addr = SocketAddress::local_ipv4(8080);
        assert_eq!(socket_addr.into_canonical_ip_addr(), socket_addr);
    }

    #[test]
    fn ipv6_loopback_is_unchanged() {
        let socket_addr = SocketAddress::local_ipv6(8080);
        assert_eq!(socket_addr.into_canonical_ip_addr(), socket_addr);
    }

    #[test]
    fn ipv4_is_unchanged() {
        let socket_addr = SocketAddress::from(([192, 168, 1, 1], 8080));
        assert_eq!(socket_addr.into_canonical_ip_addr(), socket_addr);
    }

    #[test]
    fn ipv6_is_unchanged() {
        let socket_addr = SocketAddress::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0xdead, 0xbeef], 8080));
        assert_eq!(socket_addr.into_canonical_ip_addr(), socket_addr);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_converted_to_ipv4() {
        // ::ffff:192.10.2.255
        let socket_addr = SocketAddress::from(([0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x02ff], 8080));
        assert_eq!(
            socket_addr.into_canonical_ip_addr(),
            SocketAddress::from(([192, 10, 2, 255], 8080))
        );
    }

    #[test]
    fn ipv4_mapped_loopback_ipv6_is_converted_to_ipv4() {
        // ::ffff:127.0.0.1
        let socket_addr = SocketAddress::from(([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001], 8080));
        assert_eq!(
            socket_addr.into_canonical_ip_addr(),
            SocketAddress::from(([127, 0, 0, 1], 8080))
        );
    }

    #[test]
    fn ipv4_compatible_ipv6_is_not_converted_to_ipv4() {
        // ::192.0.2.33, represented as 0:0:0:0:0:0:c000:0221
        let socket_addr = SocketAddress::from(([0, 0, 0, 0, 0, 0, 0xc000, 0x0221], 8080));
        assert_eq!(socket_addr.into_canonical_ip_addr(), socket_addr);
    }

    #[test]
    fn ipv4_mapped_zero_zero_zero_one_is_converted_to_ipv4() {
        // ::ffff:0.0.0.1
        let socket_addr = SocketAddress::from(([0, 0, 0, 0, 0, 0xffff, 0x0000, 0x0001], 8080));
        assert_eq!(
            socket_addr.into_canonical_ip_addr(),
            SocketAddress::from(([0, 0, 0, 1], 8080))
        );
    }
}
