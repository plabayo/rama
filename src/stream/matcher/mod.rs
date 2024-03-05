//! [`service::Matcher`]s implementations to match on [`Socket`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`Socket`]: crate::stream::Socket
//! [`service::matcher` module]: crate::service::matcher

mod socket;
#[doc(inline)]
pub use socket::SocketAddressFilter;

mod port;
#[doc(inline)]
pub use port::PortFilter;

mod ip;
#[doc(inline)]
pub use ip::IpNetFilter;

use crate::{
    http::Request,
    service::{context::Extensions, Context},
};

#[derive(Debug, Clone)]
/// A filter that is used to match an http [`Request`]
pub enum SocketMatcher {
    /// [`SocketAddressFilter`], a filter that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    SocketAddress(SocketAddressFilter),
    /// [`PortFilter`], a filter based on the port part of the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    Port(PortFilter),
    /// [`IpNetFilter`], a filter to match on whether or not
    /// the [`IpNet`] contains the [`SocketAddr`] of the peer.
    ///
    /// [`IpNet`]: ipnet::IpNet
    /// [`SocketAddr`]: std::net::SocketAddr
    IpNet(IpNetFilter),
}

impl SocketMatcher {
    /// Create a [`SocketMatcher::SocketAddress`] filter.
    pub fn socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self::SocketAddress(SocketAddressFilter::new(addr))
    }

    /// Create a [`SocketMatcher::Port`] filter.
    pub fn port(port: u16) -> Self {
        Self::Port(PortFilter::new(port))
    }

    /// Create a [`SocketMatcher::IpNet`] filter.
    pub fn ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self::IpNet(IpNetFilter::new(ip_net))
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for SocketMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            SocketMatcher::SocketAddress(filter) => filter.matches(ext, ctx, req),
            SocketMatcher::Port(filter) => filter.matches(ext, ctx, req),
            SocketMatcher::IpNet(filter) => filter.matches(ext, ctx, req),
        }
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, stream: &Socket) -> bool {
        match self {
            SocketMatcher::SocketAddress(filter) => filter.matches(ext, ctx, stream),
            SocketMatcher::Port(filter) => filter.matches(ext, ctx, stream),
            SocketMatcher::IpNet(filter) => filter.matches(ext, ctx, stream),
        }
    }
}
