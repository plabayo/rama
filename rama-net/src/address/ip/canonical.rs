use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::address::{Authority, Host, HostWithOptPort, HostWithPort, ProxyAddress, SocketAddress};

/// Trait to convert an IP address into its canonical form
pub trait IntoCanonicalIpAddr {
    fn into_canonical_ip_addr(self) -> Self;
}

impl IntoCanonicalIpAddr for IpAddr {
    fn into_canonical_ip_addr(self) -> Self {
        match self {
            IpAddr::V4(_) => self,
            IpAddr::V6(v6) => match v6.to_ipv4() {
                Some(mapped) => {
                    if mapped == Ipv4Addr::new(0, 0, 0, 1) {
                        self
                    } else {
                        IpAddr::V4(mapped)
                    }
                }
                None => self,
            },
        }
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
    fn ipv4_loopback_to_canonical() {
        let socket = SocketAddress::local_ipv4(8080);
        assert_eq!(socket.into_canonical_ip_addr(), socket);
    }

    #[test]
    fn ipv6_loopback_to_canonical() {
        let socket = SocketAddress::local_ipv6(8080);
        assert_eq!(socket.into_canonical_ip_addr(), socket);
    }

    #[test]
    fn ipv4_to_canonical() {
        let socket = SocketAddress::from(([192, 168, 1, 1], 8080));
        assert_eq!(socket.into_canonical_ip_addr(), socket);
    }

    #[test]
    fn ipv6_to_canonical() {
        let socket = SocketAddress::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0xdead, 0xbeef], 8080));
        assert_eq!(socket.into_canonical_ip_addr(), socket);
    }

    #[test]
    fn ipv4_mapped_to_ipv6_to_canonical() {
        let socket = SocketAddress::from(([0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff], 8080));
        assert_eq!(
            socket.into_canonical_ip_addr(),
            SocketAddress::from(([192, 10, 2, 255], 8080))
        );
    }
}
