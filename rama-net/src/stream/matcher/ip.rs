//! ip matcher and utilities

pub use crate::address::ip::ipnet::{IpNet, Ipv4Net, Ipv6Net};

use rama_core::extensions::Extensions;

#[derive(Debug, Clone)]
/// Matcher based on whether or not the [`IpNet`] contains the [`SocketAddr`] of the peer.
///
/// [`SocketAddr`]: core::net::SocketAddr
pub struct IpNetMatcher {
    net: IpNet,
    optional: bool,
}

impl IpNetMatcher {
    /// create a new IP network matcher to match on an IP Network.
    ///
    /// This matcher will not match in case socket address could not be found,
    /// if you want to match in case socket address could not be found,
    /// use the [`IpNetMatcher::optional`] constructor..
    pub fn new(net: impl IntoIpNet) -> Self {
        Self {
            net: net.into_ip_net(),
            optional: false,
        }
    }

    /// create a new IP network matcher to match on an IP network
    ///
    /// This matcher will match in case socket address could not be found.
    /// Use the [`IpNetMatcher::new`] constructor if you want do not want
    /// to match in case socket address could not be found.
    pub fn optional(net: impl IntoIpNet) -> Self {
        Self {
            net: net.into_ip_net(),
            optional: true,
        }
    }
}

impl<Socket> rama_core::matcher::Matcher<Socket> for IpNetMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, _ext: Option<&Extensions>, stream: &Socket) -> bool {
        stream
            .peer_addr()
            .map(|addr| self.net.contains(&IpNet::from(addr.ip_addr)))
            .unwrap_or(self.optional)
    }
}

/// utility trait to consume a tpe into an [`IpNet`]
pub trait IntoIpNet: private::Sealed {}

macro_rules! impl_ip_net_from_ip_addr_into_all {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IntoIpNet for $ty {}
        )+
    };
}

impl_ip_net_from_ip_addr_into_all!(
    Ipv4Net,
    Ipv6Net,
    IpNet,
    core::net::IpAddr,
    core::net::Ipv4Addr,
    core::net::Ipv6Addr,
    [u16; 8],
    [u8; 16],
    [u8; 4],
);

mod private {
    use super::*;

    pub trait Sealed {
        /// Consume `self` into an [`IpNet`]
        fn into_ip_net(self) -> IpNet;
    }

    impl Sealed for Ipv4Net {
        fn into_ip_net(self) -> IpNet {
            IpNet::V4(self)
        }
    }

    impl Sealed for Ipv6Net {
        fn into_ip_net(self) -> IpNet {
            IpNet::V6(self)
        }
    }

    impl Sealed for IpNet {
        fn into_ip_net(self) -> IpNet {
            self
        }
    }

    macro_rules! impl_sealed_from_ip_addr_into_all {
        ($($ty:ty),+ $(,)?) => {
            $(
                impl Sealed for $ty {
                    fn into_ip_net(self) -> IpNet {
                        let ip_addr: core::net::IpAddr = self.into();
                        ip_addr.into()
                    }
                }
            )+
        };
    }

    impl_sealed_from_ip_addr_into_all!(
        core::net::IpAddr,
        core::net::Ipv4Addr,
        core::net::Ipv6Addr,
        [u16; 8],
        [u8; 16],
        [u8; 4],
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address::SocketAddress;

    use rama_core::matcher::Matcher;

    const SUBNET_IPV4: &str = "192.168.0.0/24";
    const SUBNET_IPV4_VALID_CASES: [&str; 2] = ["192.168.0.0/25", "192.168.0.1"];
    const SUBNET_IPV4_INVALID_CASES: [&str; 2] = ["192.167.0.0/23", "192.168.1.0"];

    const SUBNET_IPV6: &str = "fd00::/16";
    const SUBNET_IPV6_VALID_CASES: [&str; 2] = ["fd00::/17", "fd00::1"];
    const SUBNET_IPV6_INVALID_CASES: [&str; 2] = ["fd01::/15", "fd01::"];

    fn socket_addr_from_case(s: &str) -> SocketAddress {
        if s.contains('/') {
            let ip_net: IpNet = s.parse().unwrap();
            SocketAddress::new(ip_net.addr(), 60000)
        } else {
            let ip_addr: core::net::IpAddr = s.parse().unwrap();
            SocketAddress::new(ip_addr, 60000)
        }
    }

    #[test]
    fn test_ip_net_matcher_socket_trait() {
        let matcher = IpNetMatcher::new([127, 0, 0, 1]);

        struct FakeSocket {
            local_addr: Option<SocketAddress>,
            peer_addr: Option<SocketAddress>,
        }

        impl crate::stream::Socket for FakeSocket {
            fn local_addr(&self) -> std::io::Result<SocketAddress> {
                match &self.local_addr {
                    Some(addr) => Ok(*addr),
                    None => Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
                }
            }

            fn peer_addr(&self) -> std::io::Result<SocketAddress> {
                match &self.peer_addr {
                    Some(addr) => Ok(*addr),
                    None => Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
                }
            }
        }

        let mut socket = FakeSocket {
            local_addr: None,
            peer_addr: Some(([127, 0, 0, 1], 8081).into()),
        };

        // test #1: no match: test with different socket info (ip addr difference)
        socket.peer_addr = Some(([127, 0, 0, 2], 8080).into());
        assert!(!matcher.matches(None, &socket));

        // test #2: match: test with correct address
        socket.peer_addr = Some(([127, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #3: match: test with missing socket info, but it's seen as optional
        let matcher = IpNetMatcher::optional([127, 0, 0, 1]);
        socket.peer_addr = None;
        assert!(matcher.matches(None, &socket));

        // test #4: match: valid ipv4 subnets
        let matcher = IpNetMatcher::new(SUBNET_IPV4.parse::<IpNet>().unwrap());
        for subnet in SUBNET_IPV4_VALID_CASES.iter() {
            let addr = socket_addr_from_case(subnet);
            socket.peer_addr = Some(addr);
            assert!(
                matcher.matches(None, &socket),
                "valid ipv4 subnets => {SUBNET_IPV4} >=? {addr} ({subnet})",
            );
        }

        // test #5: match: valid ipv6 subnets
        let matcher = IpNetMatcher::new(SUBNET_IPV6.parse::<IpNet>().unwrap());
        for subnet in SUBNET_IPV6_VALID_CASES.iter() {
            let addr = socket_addr_from_case(subnet);
            socket.peer_addr = Some(addr);
            assert!(
                matcher.matches(None, &socket),
                "valid ipv6 subnets => {SUBNET_IPV6} >=? {addr} ({subnet})",
            );
        }

        // test #6: match: invalid ipv4 subnets
        let matcher = IpNetMatcher::new(SUBNET_IPV4.parse::<IpNet>().unwrap());
        for subnet in SUBNET_IPV4_INVALID_CASES.iter() {
            let addr = socket_addr_from_case(subnet);
            socket.peer_addr = Some(addr);
            assert!(
                !matcher.matches(None, &socket),
                "invalid ipv4 subnets => {SUBNET_IPV4} >=? {addr} ({subnet})",
            );
        }

        // test #7: match: invalid ipv6 subnets
        let matcher = IpNetMatcher::new(SUBNET_IPV6.parse::<IpNet>().unwrap());
        for subnet in SUBNET_IPV6_INVALID_CASES.iter() {
            let addr = socket_addr_from_case(subnet);
            socket.peer_addr = Some(addr);
            assert!(
                !matcher.matches(None, &socket),
                "invalid ipv6 subnets => {SUBNET_IPV6} >=? {addr} ({subnet})",
            );
        }
    }
}
