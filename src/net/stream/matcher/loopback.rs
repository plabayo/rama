use http::Request;

use crate::{
    net::stream::SocketInfo,
    service::{context::Extensions, Context},
};

#[derive(Debug, Clone)]
/// Matcher based on the ip part of the [`SocketAddr`] of the peer,
/// matching only if the ip is a loopback address.
///
/// [`SocketAddr`]: std::net::SocketAddr
pub struct LoopbackMatcher {
    optional: bool,
}

impl LoopbackMatcher {
    /// create a new loopback matcher to match on the ip part a [`SocketAddr`],
    /// matching only if the ip is a loopback address.
    ///
    /// This matcher will not match in case socket address could not be found,
    /// if you want to match in case socket address could not be found,
    /// use the [`LoopbackMatcher::optional`] constructor..
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn new() -> Self {
        Self { optional: false }
    }

    /// create a new loopback matcher to match on the ip part a [`SocketAddr`],
    /// matching only if the ip is a loopback address or no socket address could be found.
    ///
    /// This matcher will match in case socket address could not be found.
    /// Use the [`LoopbackMatcher::new`] constructor if you want do not want
    /// to match in case socket address could not be found.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn optional() -> Self {
        Self { optional: true }
    }
}

impl Default for LoopbackMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for LoopbackMatcher {
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        _req: &Request<Body>,
    ) -> bool {
        ctx.get::<SocketInfo>()
            .map(|info| info.peer_addr().ip().is_loopback())
            .unwrap_or(self.optional)
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for LoopbackMatcher
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
            .map(|addr| addr.ip().is_loopback())
            .unwrap_or(self.optional)
    }
}

#[cfg(test)]
mod test {
    use crate::{http::Body, service::Matcher};
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn test_loopback_matcher_http() {
        let matcher = LoopbackMatcher::new();

        let mut ctx = Context::default();
        let req = Request::builder()
            .method("GET")
            .uri("/hello")
            .body(Body::empty())
            .unwrap();

        // test #1: no match: test with no socket info registered
        assert!(!matcher.matches(None, &ctx, &req));

        // test #2: no match: test with network address (ipv4)
        ctx.insert(SocketInfo::new(None, ([192, 168, 0, 1], 8080).into()));
        assert!(!matcher.matches(None, &ctx, &req));

        // test #3: no match: test with network address (ipv6)
        ctx.insert(SocketInfo::new(
            None,
            ([1, 1, 1, 1, 1, 1, 1, 1], 8080).into(),
        ));
        assert!(!matcher.matches(None, &ctx, &req));

        // test #4: match: test with loopback address (ipv4)
        ctx.insert(SocketInfo::new(None, ([127, 0, 0, 1], 8080).into()));
        assert!(matcher.matches(None, &ctx, &req));

        // test #5: match: test with another loopback address (ipv4)
        ctx.insert(SocketInfo::new(None, ([127, 3, 2, 1], 8080).into()));
        assert!(matcher.matches(None, &ctx, &req));

        // test #6: match: test with loopback address (ipv6)
        ctx.insert(SocketInfo::new(
            None,
            ([0, 0, 0, 0, 0, 0, 0, 1], 8080).into(),
        ));
        assert!(matcher.matches(None, &ctx, &req));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = LoopbackMatcher::optional();
        let ctx = Context::default();
        assert!(matcher.matches(None, &ctx, &req));
    }

    #[test]
    fn test_loopback_matcher_socket_trait() {
        let matcher = LoopbackMatcher::new();

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
        socket.peer_addr = Some(([192, 168, 0, 1], 8080).into());
        assert!(!matcher.matches(None, &ctx, &socket));

        // test #3: no match: test with network address (ipv6)
        socket.peer_addr = Some(([1, 1, 1, 1, 1, 1, 1, 1], 8080).into());
        assert!(!matcher.matches(None, &ctx, &socket));

        // test #4: match: test with loopback address (ipv4)
        socket.peer_addr = Some(([127, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #5: match: test with another loopback address (ipv4)
        socket.peer_addr = Some(([127, 3, 2, 1], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #6: match: test with loopback address (ipv6)
        socket.peer_addr = Some(([0, 0, 0, 0, 0, 0, 0, 1], 8080).into());
        assert!(matcher.matches(None, &ctx, &socket));

        // test #7: match: test with missing socket info, but it's seen as optional
        let matcher = LoopbackMatcher::optional();
        socket.peer_addr = None;
        assert!(matcher.matches(None, &ctx, &socket));
    }
}
