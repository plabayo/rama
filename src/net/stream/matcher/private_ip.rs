use http::Request;

use crate::net::stream::dep::ipnet::IpNet;
use crate::{
    net::stream::SocketInfo,
    service::{context::Extensions, Context},
};

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
    pub fn new() -> Self {
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
    pub fn optional() -> Self {
        Self::inner_new(true)
    }

    fn inner_new(optional: bool) -> Self {
        Self {
            matchers: [
                // This host on this network
                // https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
                "0.0.0.0/8"
                    .parse::<IpNet>()
                    .expect("parse 0.0.0.0/8 as IpNet"),
                // Private-Use
                // https://datatracker.ietf.org/doc/html/rfc1918
                "10.0.0.0/8"
                    .parse::<IpNet>()
                    .expect("parse 10.0.0.0/8 as IpNet"),
                // Shared Address Space
                // https://datatracker.ietf.org/doc/html/rfc6598
                "100.64.0.0/10"
                    .parse::<IpNet>()
                    .expect("parse 100.64.0.0/10 as IpNet"),
                // Loopback
                // https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
                "127.0.0.0/8"
                    .parse::<IpNet>()
                    .expect("parse 127.0.0.0/8 as IpNet"),
                // Link Local
                // https://datatracker.ietf.org/doc/html/rfc3927
                "169.254.0.0/16"
                    .parse::<IpNet>()
                    .expect("parse 169.254.0.0/16 as IpNet"),
                // Private-Use
                // https://datatracker.ietf.org/doc/html/rfc1918
                "172.16.0.0/12"
                    .parse::<IpNet>()
                    .expect("parse 172.16.0.0/12 as IpNet"),
                // Private-Use
                // https://datatracker.ietf.org/doc/html/rfc1918
                "192.168.0.0/16"
                    .parse::<IpNet>()
                    .expect("parse 192.168.0.0/16 as IpNet"),
                // Unique-Local
                // https://datatracker.ietf.org/doc/html/rfc4193
                "fc00::/7"
                    .parse::<IpNet>()
                    .expect("parse fc00::/7 as IpNet"),
                // Linked-Scoped Unicast
                // https://datatracker.ietf.org/doc/html/rfc4291
                "fe80::/10"
                    .parse::<IpNet>()
                    .expect("parse fe80::/10 as IpNet"),
                // Loopback Address
                // https://datatracker.ietf.org/doc/html/rfc4291
                "::1/128".parse::<IpNet>().expect("parse ::1/128 as IpNet"),
                // Unspecified Address
                // https://datatracker.ietf.org/doc/html/rfc4291
                "::/128".parse::<IpNet>().expect("parse ::/128 as IpNet"),
            ],
            optional,
        }
    }
}

impl Default for PrivateIpNetMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for PrivateIpNetMatcher {
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        _req: &Request<Body>,
    ) -> bool {
        ctx.get::<SocketInfo>()
            .map(|info| {
                let peer_ip = IpNet::from(info.peer_addr().ip());
                self.matchers.iter().any(|ip_net| ip_net.contains(&peer_ip))
            })
            .unwrap_or(self.optional)
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for PrivateIpNetMatcher
where
    Socket: crate::net::stream::Socket,
{
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        stream: &Socket,
    ) -> bool {
        stream
            .peer_addr()
            .map(|addr| {
                let peer_ip = IpNet::from(addr.ip());
                self.matchers.iter().any(|ip_net| ip_net.contains(&peer_ip))
            })
            .unwrap_or(self.optional)
    }
}

#[cfg(test)]
mod test {
    use crate::{http::Body, service::Matcher};
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn test_local_ip_net_matcher_http() {
        let matcher = PrivateIpNetMatcher::new();

        let mut ctx = Context::default();
        let req = Request::builder()
            .method("GET")
            .uri("/hello")
            .body(Body::empty())
            .unwrap();

        // test #1: no match: test with no socket info registered
        assert!(!matcher.matches(None, &ctx, &req));

        // test #2: no match: test with remote network address (ipv4)
        ctx.insert(SocketInfo::new(None, ([1, 1, 1, 1], 8080).into()));
        assert!(!matcher.matches(None, &ctx, &req));

        // test #3: no match: test with remote network address (ipv6)
        ctx.insert(SocketInfo::new(
            None,
            ([1, 1, 1, 1, 1, 1, 1, 1], 8080).into(),
        ));
        assert!(!matcher.matches(None, &ctx, &req));

        // test #4: match: test with private address (ipv4)
        ctx.insert(SocketInfo::new(None, ([127, 0, 0, 1], 8080).into()));
        assert!(matcher.matches(None, &ctx, &req));

        // test #5: match: test with another private address (ipv4)
        ctx.insert(SocketInfo::new(None, ([192, 168, 0, 24], 8080).into()));
        assert!(matcher.matches(None, &ctx, &req));

        // test #6: match: test with private address (ipv6)
        ctx.insert(SocketInfo::new(
            None,
            ([0, 0, 0, 0, 0, 0, 0, 1], 8080).into(),
        ));
        assert!(matcher.matches(None, &ctx, &req));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = PrivateIpNetMatcher::optional();
        let ctx = Context::default();
        assert!(matcher.matches(None, &ctx, &req));
    }

    #[test]
    fn test_local_ip_net_matcher_socket_trait() {
        let matcher = PrivateIpNetMatcher::new();

        let ctx = Context::default();

        struct FakeSocket {
            local_addr: Option<SocketAddr>,
            peer_addr: Option<SocketAddr>,
        }

        impl crate::net::stream::Socket for FakeSocket {
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                match &self.local_addr {
                    Some(addr) => Ok(*addr),
                    None => Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
                }
            }

            fn peer_addr(&self) -> std::io::Result<SocketAddr> {
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
        assert!(!matcher.matches(None, &ctx, &socket));

        // test #2: no match: test with network address (ipv4)
        socket.peer_addr = Some(([1, 1, 1, 1], 8080).into());
        assert!(!matcher.matches(None, &ctx, &socket));

        // test #3: no match: test with another network address (ipv6)
        socket.peer_addr = Some(([1, 1, 1, 1, 1, 1, 1, 1], 8080).into());
        assert!(!matcher.matches(None, &ctx, &socket));

        // test #4: match: test with private address (ipv4)
        socket.peer_addr = Some(([192, 168, 0, 0], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #5: match: test with another private address (ipv4)
        socket.peer_addr = Some(([127, 3, 2, 1], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #6: match: test with yet another private address (ipv6)
        socket.peer_addr = Some(([0, 0, 0, 0, 0, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = PrivateIpNetMatcher::optional();
        socket.peer_addr = None;
        assert!(matcher.matches(None, &ctx, &socket));
    }
}
