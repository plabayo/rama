use rama_core::extensions::Extensions;

#[derive(Debug, Clone)]
/// Matcher based on the port part of the [`SocketAddr`] of the peer.
///
/// [`SocketAddr`]: core::net::SocketAddr
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
    /// [`SocketAddr`]: core::net::SocketAddr
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
    /// [`SocketAddr`]: core::net::SocketAddr
    #[must_use]
    pub const fn optional(port: u16) -> Self {
        Self {
            port,
            optional: true,
        }
    }
}

impl<Socket> rama_core::matcher::Matcher<Socket> for PortMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, _ext: Option<&Extensions>, stream: &Socket) -> bool {
        stream
            .peer_addr()
            .map(|addr| addr.port == self.port)
            .unwrap_or(self.optional)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address::SocketAddress;

    use rama_core::matcher::Matcher;

    #[test]
    fn test_port_matcher_socket_trait() {
        let matcher = PortMatcher::new(8080);

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
