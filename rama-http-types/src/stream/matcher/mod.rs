//! `Matcher<Request>` impls for `rama-net`'s socket matchers.
//!
//! The matcher *types* live in `rama_net::stream::matcher`; these blocks add
//! the HTTP-`Request` matching surface now that `Request` is local to
//! `rama-http-types`. Each impl pulls the peer [`SocketAddress`] from the
//! request's [`SocketInfo`] extension and delegates to the matcher's existing
//! [`Matcher<Socket>`] impl via a tiny [`Socket`] adapter — this keeps the
//! matchers' internals private to `rama-net` (orphan-rule safe), and preserves
//! the original behavior: when no [`SocketInfo`] is present the matcher's own
//! `optional` fallback is exercised (the adapter's `peer_addr` errors).
//!
//! [`Matcher<Socket>`]: rama_core::matcher::Matcher
//! [`SocketAddress`]: rama_net::address::SocketAddress
//! [`SocketInfo`]: rama_net::stream::SocketInfo
//! [`Socket`]: rama_net::stream::Socket

use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::matcher::Matcher;
use rama_net::address::SocketAddress;
use rama_net::stream::matcher::{
    IpNetMatcher, LoopbackMatcher, PortMatcher, PrivateIpNetMatcher, SocketAddressMatcher,
};
use rama_net::stream::{Socket, SocketInfo};

use crate::Request;

/// Adapter that exposes a request's optional peer [`SocketAddress`] as a
/// [`Socket`]. An absent peer addr makes `peer_addr` error, mirroring the
/// "no socket info" path so the socket matchers' `optional` fallback applies.
struct PeerSocket(Option<SocketAddress>);

impl Socket for PeerSocket {
    #[inline]
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))
    }

    #[inline]
    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.0
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))
    }
}

macro_rules! impl_request_matcher {
    ($matcher:ty) => {
        impl<Body> Matcher<Request<Body>> for $matcher {
            fn matches(&self, _ext: Option<&Extensions>, req: &Request<Body>) -> bool {
                let peer = req
                    .extensions()
                    .get_ref::<SocketInfo>()
                    .map(|info| info.peer_addr());
                self.matches(None, &PeerSocket(peer))
            }
        }
    };
}

impl_request_matcher!(SocketAddressMatcher);
impl_request_matcher!(IpNetMatcher);
impl_request_matcher!(LoopbackMatcher);
impl_request_matcher!(PortMatcher);
impl_request_matcher!(PrivateIpNetMatcher);
