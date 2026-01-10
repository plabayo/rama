use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::stream::dep::ipnet::IpNet;
use rama_core::extensions::Extensions;

#[cfg(feature = "http")]
use {crate::stream::SocketInfo, rama_core::extensions::ExtensionsRef, rama_http_types::Request};

#[derive(Debug, Clone)]
/// Matcher based on the ip part of the [`SocketAddr`] of the peer,
/// matching only if the IP is considered a private address.
///
/// Whether or not an address is considered private is determined by the following
/// RFCs:
///
/// - [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918): Address Allocation for Private Internets (IPv4)
/// - [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193): Unique Local IPv6 Unicast Addresses
/// - [RFC 3927](https://datatracker.ietf.org/doc/html/rfc3927): Dynamic Configuration of IPv4 Link-Local Addresses
/// - [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291): IP Version 6 Addressing Architecture
/// - [RFC 1122](https://datatracker.ietf.org/doc/html/rfc1122): Requirements for Internet Hosts -- Communication Layers
/// - [RFC 6890](https://datatracker.ietf.org/doc/html/rfc6890): Special-Purpose IP Address Registries
/// - [RFC rfc6598](https://datatracker.ietf.org/doc/html/rfc6598): IANA-Reserved IPv4 Prefix for Shared Address Space
///
/// [`SocketAddr`]: std::net::SocketAddr
pub struct PrivateIpNetMatcher {
    matchers: [IpNet; 11],
    optional: bool,
}

impl PrivateIpNetMatcher {
    /// create a new loopback matcher to match on the ip part a [`SocketAddr`],
    /// matching only if the IP is considered a private address.
    ///
    /// This matcher will not match in case socket address could not be found,
    /// if you want to match in case socket address could not be found,
    /// use the [`PrivateIpNetMatcher::optional`] constructor..
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    #[must_use]
    pub const fn new() -> Self {
        Self::inner_new(false)
    }

    /// create a new loopback matcher to match on the ip part a [`SocketAddr`],
    /// matching only if the IP is considered a private address or no socket address could be found.
    ///
    /// This matcher will match in case socket address could not be found.
    /// Use the [`PrivateIpNetMatcher::new`] constructor if you want do not want
    /// to match in case socket address could not be found.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    #[must_use]
    pub const fn optional() -> Self {
        Self::inner_new(true)
    }

    const fn inner_new(optional: bool) -> Self {
        const MATCHERS: [IpNet; 11] = [
            // This host on this network
            // https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8), // 0.0.0.0/8
            // Private-Use
            // https://datatracker.ietf.org/doc/html/rfc1918
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8), // 10.0.0.0/8
            // Shared Address Space
            // https://datatracker.ietf.org/doc/html/rfc6598
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10), // 100.64.0.0/10
            // Loopback
            // https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8), // 127.0.0.0/8
            // Link Local
            // https://datatracker.ietf.org/doc/html/rfc3927
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16), // 169.254.0.0/16
            // Private-Use
            // https://datatracker.ietf.org/doc/html/rfc1918
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12), // 172.16.0.0/12
            // Private-Use
            // https://datatracker.ietf.org/doc/html/rfc1918
            IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16), // 192.168.0.0/16
            // Unique-Local
            // https://datatracker.ietf.org/doc/html/rfc4193
            IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7), // fc00::/7
            // Linked-Scoped Unicast
            // https://datatracker.ietf.org/doc/html/rfc4291
            IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10), // fe80::/10
            // Loopback Address
            // https://datatracker.ietf.org/doc/html/rfc4291
            IpNet::new_assert(IpAddr::V6(Ipv6Addr::LOCALHOST), 128), // ::1/128
            // Unspecified Address
            // https://datatracker.ietf.org/doc/html/rfc4291
            IpNet::new_assert(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128), // ::/128
        ];

        Self {
            matchers: MATCHERS,
            optional,
        }
    }
}

impl Default for PrivateIpNetMatcher {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
impl<Body> rama_core::matcher::Matcher<Request<Body>> for PrivateIpNetMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        req.extensions()
            .get::<SocketInfo>()
            .map(|info| {
                let peer_ip = IpNet::from(info.peer_addr().ip_addr);
                self.matchers.iter().any(|ip_net| ip_net.contains(&peer_ip))
            })
            .unwrap_or(self.optional)
    }
}

impl<Socket> rama_core::matcher::Matcher<Socket> for PrivateIpNetMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, _ext: Option<&mut Extensions>, stream: &Socket) -> bool {
        stream
            .peer_addr()
            .map(|addr| {
                let peer_ip = IpNet::from(addr.ip_addr);
                self.matchers.iter().any(|ip_net| ip_net.contains(&peer_ip))
            })
            .unwrap_or(self.optional)
    }
}

#[cfg(test)]
mod test {
    use crate::address::SocketAddress;

    use super::*;
    use rama_core::matcher::Matcher;

    #[cfg(feature = "http")]
    #[test]
    fn test_local_ip_net_matcher_http() {
        use rama_core::extensions::ExtensionsMut;

        let matcher = PrivateIpNetMatcher::new();

        let mut req = Request::builder()
            .method("GET")
            .uri("/hello")
            .body(())
            .unwrap();

        // test #1: no match: test with no socket info registered
        assert!(!matcher.matches(None, &req));

        // test #2: no match: test with remote network address (ipv4)
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([1, 1, 1, 1], 8080).into()));
        assert!(!matcher.matches(None, &req));

        // test #3: no match: test with remote network address (ipv6)
        req.extensions_mut().insert(SocketInfo::new(
            None,
            ([1, 1, 1, 1, 1, 1, 1, 1], 8080).into(),
        ));
        assert!(!matcher.matches(None, &req));

        // test #4: match: test with private address (ipv4)
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([127, 0, 0, 1], 8080).into()));
        assert!(matcher.matches(None, &req));

        // test #5: match: test with another private address (ipv4)
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([192, 168, 0, 24], 8080).into()));
        assert!(matcher.matches(None, &req));

        // test #6: match: test with private address (ipv6)
        req.extensions_mut().insert(SocketInfo::new(
            None,
            ([0, 0, 0, 0, 0, 0, 0, 1], 8080).into(),
        ));
        assert!(matcher.matches(None, &req));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = PrivateIpNetMatcher::optional();
        assert!(matcher.matches(None, &req));
    }

    #[test]
    fn test_local_ip_net_matcher_socket_trait() {
        let matcher = PrivateIpNetMatcher::new();

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
            peer_addr: None,
        };

        // test #1: no match: test with no socket info registered
        assert!(!matcher.matches(None, &socket));

        // test #2: no match: test with network address (ipv4)
        socket.peer_addr = Some(([1, 1, 1, 1], 8080).into());
        assert!(!matcher.matches(None, &socket));

        // test #3: no match: test with another network address (ipv6)
        socket.peer_addr = Some(([1, 1, 1, 1, 1, 1, 1, 1], 8080).into());
        assert!(!matcher.matches(None, &socket));

        // test #4: match: test with private address (ipv4)
        socket.peer_addr = Some(([192, 168, 0, 0], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #5: match: test with another private address (ipv4)
        socket.peer_addr = Some(([127, 3, 2, 1], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #6: match: test with yet another private address (ipv6)
        socket.peer_addr = Some(([0, 0, 0, 0, 0, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = PrivateIpNetMatcher::optional();
        socket.peer_addr = None;
        assert!(matcher.matches(None, &socket));
    }
}
