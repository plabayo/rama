//! [`service::Matcher`]s implementations to match on [`Socket`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`Socket`]: crate::stream::Socket
//! [`service::matcher` module]: crate::service::matcher

mod socket;
#[doc(inline)]
pub use socket::SocketAddressMatcher;

mod port;
#[doc(inline)]
pub use port::PortMatcher;

mod loopback;
#[doc(inline)]
pub use loopback::LoopbackMatcher;

mod ip;
#[doc(inline)]
pub use ip::IpNetMatcher;

use crate::{
    http::Request,
    service::{context::Extensions, matcher::IteratorMatcherExt, Context},
};

#[derive(Debug, Clone)]
/// A matcher to match on a [`Socket`].
///
/// [`Socket`]: crate::stream::Socket
pub struct SocketMatcher {
    kind: SocketMatcherKind,
    negate: bool,
}

#[derive(Debug, Clone)]
/// The different kinds of socket matchers.
enum SocketMatcherKind {
    /// [`SocketAddressMatcher`], a matcher that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    SocketAddress(SocketAddressMatcher),
    /// [`LoopbackMatcher`], a matcher that matches if the peer address is a loopback address.
    Loopback(LoopbackMatcher),
    /// [`PortMatcher`], a matcher based on the port part of the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    Port(PortMatcher),
    /// [`IpNetMatcher`], a matcher to match on whether or not
    /// the [`IpNet`] contains the [`SocketAddr`] of the peer.
    ///
    /// [`IpNet`]: ipnet::IpNet
    /// [`SocketAddr`]: std::net::SocketAddr
    IpNet(IpNetMatcher),
    /// zero or more matchers that all need to match in order for the matcher to return `true`.
    All(Vec<SocketMatcherKind>),
    /// `true` if no matchers are defined, or any of the defined matcher match.
    Any(Vec<SocketMatcherKind>),
}

impl SocketMatcher {
    /// Create a new socket address matcher to filter on a socket address.
    ///
    /// See [`SocketAddressMatcher::new`] for more information.
    pub fn socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(addr)),
            negate: false,
        }
    }

    /// Create a new optional socket address matcher to filter on a socket address,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`SocketAddressMatcher::optional`] for more information.
    pub fn optional_socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketMatcherKind::SocketAddress(SocketAddressMatcher::optional(addr)),
            negate: false,
        }
    }

    /// Add a new socket address matcher to the existing [`SocketMatcher`] to also filter on a socket address.
    pub fn and_socket_addr(mut self, addr: impl Into<std::net::SocketAddr>) -> Self {
        match &mut self.kind {
            SocketMatcherKind::All(filters) => {
                filters.push(SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(
                    addr,
                )));
            }
            _ => {
                self.kind = SocketMatcherKind::All(vec![
                    self.kind,
                    SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(addr)),
                ]);
            }
        }
        self
    }

    /// Add a new socket address matcher to the existing [`SocketMatcher`] as an alternative filter to match on a socket address.
    ///
    /// See [`SocketAddressMatcher::new`] for more information.
    pub fn or_socket_addr(mut self, addr: impl Into<std::net::SocketAddr>) -> Self {
        match &mut self.kind {
            SocketMatcherKind::Any(filters) => {
                filters.push(SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(
                    addr,
                )));
            }
            _ => {
                self.kind = SocketMatcherKind::Any(vec![
                    self.kind,
                    SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(addr)),
                ]);
            }
        }
        self
    }

    /// create a new loopback matcher to filter on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn loopback() -> Self {
        Self {
            kind: SocketMatcherKind::Loopback(LoopbackMatcher::new()),
            negate: false,
        }
    }

    /// Create a new optional loopback matcher to filter on whether or not the peer address is a loopback address,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`LoopbackMatcher::optional`] for more information.
    pub fn optional_loopback() -> Self {
        Self {
            kind: SocketMatcherKind::Loopback(LoopbackMatcher::optional()),
            negate: false,
        }
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] to also filter on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn and_loopback(mut self) -> Self {
        match &mut self.kind {
            SocketMatcherKind::All(filters) => {
                filters.push(SocketMatcherKind::Loopback(LoopbackMatcher::new()));
            }
            _ => {
                self.kind = SocketMatcherKind::All(vec![
                    self.kind,
                    SocketMatcherKind::Loopback(LoopbackMatcher::new()),
                ]);
            }
        }
        self
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] as an alternative filter to match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn or_loopback(mut self) -> Self {
        match &mut self.kind {
            SocketMatcherKind::Any(filters) => {
                filters.push(SocketMatcherKind::Loopback(LoopbackMatcher::new()));
            }
            _ => {
                self.kind = SocketMatcherKind::Any(vec![
                    self.kind,
                    SocketMatcherKind::Loopback(LoopbackMatcher::new()),
                ]);
            }
        }
        self
    }

    /// create a new port matcher to filter on the port part a [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortMatcher::new`] for more information.
    pub fn port(port: u16) -> Self {
        Self {
            kind: SocketMatcherKind::Port(PortMatcher::new(port)),
            negate: false,
        }
    }

    /// Create a new optional port matcher to filter on the port part a [`SocketAddr`](std::net::SocketAddr),
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`PortMatcher::optional`] for more information.
    pub fn optional_port(port: u16) -> Self {
        Self {
            kind: SocketMatcherKind::Port(PortMatcher::optional(port)),
            negate: false,
        }
    }

    /// Add a new port matcher to the existing [`SocketMatcher`] to
    /// also matcher on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortMatcher::new`] for more information.
    pub fn and_port(mut self, port: u16) -> Self {
        match &mut self.kind {
            SocketMatcherKind::All(filters) => {
                filters.push(SocketMatcherKind::Port(PortMatcher::new(port)));
            }
            _ => {
                self.kind = SocketMatcherKind::All(vec![
                    self.kind,
                    SocketMatcherKind::Port(PortMatcher::new(port)),
                ]);
            }
        }
        self
    }

    /// Add a new port matcher to the existing [`SocketMatcher`] as an alternative filter
    /// to match on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///     
    /// See [`PortMatcher::new`] for more information.
    pub fn or_port(mut self, port: u16) -> Self {
        match &mut self.kind {
            SocketMatcherKind::Any(filters) => {
                filters.push(SocketMatcherKind::Port(PortMatcher::new(port)));
            }
            _ => {
                self.kind = SocketMatcherKind::Any(vec![
                    self.kind,
                    SocketMatcherKind::Port(PortMatcher::new(port)),
                ]);
            }
        }
        self
    }

    /// create a new IP network matcher to filter on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)),
            negate: false,
        }
    }

    /// Create a new optional IP network matcher to filter on an IP Network,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`IpNetMatcher::optional`] for more information.
    pub fn optional_ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketMatcherKind::IpNet(IpNetMatcher::optional(ip_net)),
            negate: false,
        }
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] to also filter on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn and_ip_net(mut self, ip_net: impl ip::IntoIpNet) -> Self {
        match &mut self.kind {
            SocketMatcherKind::All(filters) => {
                filters.push(SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)));
            }
            _ => {
                self.kind = SocketMatcherKind::All(vec![
                    self.kind,
                    SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)),
                ]);
            }
        }
        self
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] as an alternative filter to match on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn or_ip_net(mut self, ip_net: impl ip::IntoIpNet) -> Self {
        match &mut self.kind {
            SocketMatcherKind::Any(filters) => {
                filters.push(SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)));
            }
            _ => {
                self.kind = SocketMatcherKind::Any(vec![
                    self.kind,
                    SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)),
                ]);
            }
        }
        self
    }

    /// Negate the current matcher
    pub fn negate(self) -> Self {
        Self {
            kind: self.kind,
            negate: true,
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for SocketMatcherKind {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            SocketMatcherKind::SocketAddress(filter) => filter.matches(ext, ctx, req),
            SocketMatcherKind::IpNet(filter) => filter.matches(ext, ctx, req),
            SocketMatcherKind::Loopback(filter) => filter.matches(ext, ctx, req),
            SocketMatcherKind::All(filters) => filters.iter().matches_and(ext, ctx, req),
            SocketMatcherKind::Any(filters) => filters.iter().matches_or(ext, ctx, req),
            SocketMatcherKind::Port(filter) => filter.matches(ext, ctx, req),
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for SocketMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let result = self.kind.matches(ext, ctx, req);
        if self.negate {
            !result
        } else {
            result
        }
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketMatcherKind
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, stream: &Socket) -> bool {
        match self {
            SocketMatcherKind::SocketAddress(filter) => filter.matches(ext, ctx, stream),
            SocketMatcherKind::IpNet(filter) => filter.matches(ext, ctx, stream),
            SocketMatcherKind::Loopback(filter) => filter.matches(ext, ctx, stream),
            SocketMatcherKind::Port(filter) => filter.matches(ext, ctx, stream),
            SocketMatcherKind::All(filters) => filters.iter().matches_and(ext, ctx, stream),
            SocketMatcherKind::Any(filters) => filters.iter().matches_or(ext, ctx, stream),
        }
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketMatcher
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, stream: &Socket) -> bool {
        let result = self.kind.matches(ext, ctx, stream);
        if self.negate {
            !result
        } else {
            result
        }
    }
}
