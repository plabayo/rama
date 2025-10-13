use rama_core::extensions::Extensions;

#[cfg(feature = "http")]
use {crate::stream::SocketInfo, rama_core::extensions::ExtensionsRef, rama_http_types::Request};

#[derive(Debug, Clone)]
/// Matcher based on the port part of the [`SocketAddr`] of the peer.
///
/// [`SocketAddr`]: std::net::SocketAddr
pub struct PortMatcher {
    port: u16,
    optional: bool,
}

impl PortMatcher {
    /// create a new port matcher to match on the port part a [`SocketAddr`]
    ///
    /// This matcher will not match in case socket address could not be found,
    /// if you want to match in case socket address could not be found,
    /// use the [`PortMatcher::optional`] constructor..
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            optional: false,
        }
    }

    /// create a new port matcher to match on the port part a [`SocketAddr`]
    ///
    /// This matcher will match in case socket address could not be found.
    /// Use the [`PortMatcher::new`] constructor if you want do not want
    /// to match in case socket address could not be found.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    #[must_use]
    pub const fn optional(port: u16) -> Self {
        Self {
            port,
            optional: true,
        }
    }
}

#[cfg(feature = "http")]
impl<Body> rama_core::matcher::Matcher<Request<Body>> for PortMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        req.extensions()
            .get::<SocketInfo>()
            .map(|info| info.peer_addr().port() == self.port)
            .unwrap_or(self.optional)
    }
}

impl<Socket> rama_core::matcher::Matcher<Socket> for PortMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, _ext: Option<&mut Extensions>, stream: &Socket) -> bool {
        stream
            .peer_addr()
            .map(|addr| addr.port() == self.port)
            .unwrap_or(self.optional)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rama_core::matcher::Matcher;
    use std::net::SocketAddr;

    #[cfg(feature = "http")]
    #[test]
    fn test_port_matcher_http() {
        use rama_core::extensions::ExtensionsMut;

        let matcher = PortMatcher::new(8080);

        let mut req = Request::builder()
            .method("GET")
            .uri("/hello")
            .body(())
            .unwrap();

        // test #1: no match: test with no socket info registered
        assert!(!matcher.matches(None, &req));

        // test #2: no match: test with different socket info (port difference)
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([127, 0, 0, 1], 8081).into()));
        assert!(!matcher.matches(None, &req));

        // test #3: match: test with matching port
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([127, 0, 0, 2], 8080).into()));
        assert!(matcher.matches(None, &req));

        // test #4: match: test with different ip, same port
        req.extensions_mut()
            .insert(SocketInfo::new(None, ([127, 0, 0, 1], 8080).into()));
        assert!(matcher.matches(None, &req));

        // test #5: match: test with missing socket info, but it's seen as optional
        let matcher = PortMatcher::optional(8080);
        assert!(matcher.matches(None, &req));
    }

    #[test]
    fn test_port_matcher_socket_trait() {
        let matcher = PortMatcher::new(8080);

        struct FakeSocket {
            local_addr: Option<SocketAddr>,
            peer_addr: Option<SocketAddr>,
        }

        impl crate::stream::Socket for FakeSocket {
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
            peer_addr: Some(([127, 0, 0, 1], 8081).into()),
        };

        // test #1: no match: test with different socket info (port difference)
        assert!(!matcher.matches(None, &socket));

        // test #2: match: test with correct port
        socket.peer_addr = Some(([127, 0, 0, 2], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #3: match: test with another correct address
        socket.peer_addr = Some(([127, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &socket));

        // test #5: match: test with missing socket info, but it's seen as optional
        let matcher = PortMatcher::optional(8080);
        socket.peer_addr = None;
        assert!(matcher.matches(None, &socket));
    }
}
