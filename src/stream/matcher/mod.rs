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

mod loopback;
#[doc(inline)]
pub use loopback::LoopbackFilter;

mod ip;
#[doc(inline)]
pub use ip::IpNetFilter;

use crate::{
    http::Request,
    service::{context::Extensions, matcher::IteratorMatcherExt, Context},
};

#[derive(Debug, Clone)]
/// A filter to match on a [`Socket`].
///
/// [`Socket`]: crate::stream::Socket
pub struct SocketMatcher {
    kind: SocketFilterKind,
    negate: bool,
}

#[derive(Debug, Clone)]
/// The different kinds of socket filters.
enum SocketFilterKind {
    /// [`SocketAddressFilter`], a filter that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    SocketAddress(SocketAddressFilter),
    /// [`LoopbackFilter`], a filter that matches if the peer address is a loopback address.
    Loopback(LoopbackFilter),
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
    /// zero or more filters that all need to match in order for the filter to return `true`.
    All(Vec<SocketFilterKind>),
    /// `true` if no filters are defined, or any of the defined filters match.
    Any(Vec<SocketFilterKind>),
}

impl SocketMatcher {
    /// Create a new socket address filter to filter on a socket address.
    ///
    /// See [`SocketAddressFilter::new`] for more information.
    pub fn socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketFilterKind::SocketAddress(SocketAddressFilter::new(addr)),
            negate: false,
        }
    }

    /// Create a new optional socket address filter to filter on a socket address,
    /// this filter will match in case socket address could not be found.
    ///
    /// See [`SocketAddressFilter::optional`] for more information.
    pub fn optional_socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketFilterKind::SocketAddress(SocketAddressFilter::optional(addr)),
            negate: false,
        }
    }

    /// Add a new socket address filter to the existing [`SocketMatcher`] to also filter on a socket address.
    pub fn and_socket_addr(mut self, addr: impl Into<std::net::SocketAddr>) -> Self {
        match &mut self.kind {
            SocketFilterKind::All(filters) => {
                filters.push(SocketFilterKind::SocketAddress(SocketAddressFilter::new(
                    addr,
                )));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::SocketAddress(SocketAddressFilter::new(
                    addr,
                )));
                self.kind = SocketFilterKind::All(filters);
            }
        }
        self
    }

    /// Add a new socket address filter to the existing [`SocketMatcher`] as an alternative filter to match on a socket address.
    ///
    /// See [`SocketAddressFilter::new`] for more information.
    pub fn or_socket_addr(mut self, addr: impl Into<std::net::SocketAddr>) -> Self {
        match &mut self.kind {
            SocketFilterKind::Any(filters) => {
                filters.push(SocketFilterKind::SocketAddress(SocketAddressFilter::new(
                    addr,
                )));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::SocketAddress(SocketAddressFilter::new(
                    addr,
                )));
                self.kind = SocketFilterKind::Any(filters);
            }
        }
        self
    }

    /// create a new loopback filter to filter on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackFilter::new`] for more information.
    pub fn loopback() -> Self {
        Self {
            kind: SocketFilterKind::Loopback(LoopbackFilter::new()),
            negate: false,
        }
    }

    /// Create a new optional loopback filter to filter on whether or not the peer address is a loopback address,
    /// this filter will match in case socket address could not be found.
    ///
    /// See [`LoopbackFilter::optional`] for more information.
    pub fn optional_loopback() -> Self {
        Self {
            kind: SocketFilterKind::Loopback(LoopbackFilter::optional()),
            negate: false,
        }
    }

    /// Add a new loopback filter to the existing [`SocketMatcher`] to also filter on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackFilter::new`] for more information.
    pub fn and_loopback(mut self) -> Self {
        match &mut self.kind {
            SocketFilterKind::All(filters) => {
                filters.push(SocketFilterKind::Loopback(LoopbackFilter::new()));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::Loopback(LoopbackFilter::new()));
                self.kind = SocketFilterKind::All(filters);
            }
        }
        self
    }

    /// Add a new loopback filter to the existing [`SocketMatcher`] as an alternative filter to match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackFilter::new`] for more information.
    pub fn or_loopback(mut self) -> Self {
        match &mut self.kind {
            SocketFilterKind::Any(filters) => {
                filters.push(SocketFilterKind::Loopback(LoopbackFilter::new()));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::Loopback(LoopbackFilter::new()));
                self.kind = SocketFilterKind::Any(filters);
            }
        }
        self
    }

    /// create a new port filter to filter on the port part a [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortFilter::new`] for more information.
    pub fn port(port: u16) -> Self {
        Self {
            kind: SocketFilterKind::Port(PortFilter::new(port)),
            negate: false,
        }
    }

    /// Create a new optional port filter to filter on the port part a [`SocketAddr`](std::net::SocketAddr),
    /// this filter will match in case socket address could not be found.
    ///
    /// See [`PortFilter::optional`] for more information.
    pub fn optional_port(port: u16) -> Self {
        Self {
            kind: SocketFilterKind::Port(PortFilter::optional(port)),
            negate: false,
        }
    }

    /// Add a new port filter to the existing [`SocketMatcher`] to
    /// also filter on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortFilter::new`] for more information.
    pub fn and_port(mut self, port: u16) -> Self {
        match &mut self.kind {
            SocketFilterKind::All(filters) => {
                filters.push(SocketFilterKind::Port(PortFilter::new(port)));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::Port(PortFilter::new(port)));
                self.kind = SocketFilterKind::All(filters);
            }
        }
        self
    }

    /// Add a new port filter to the existing [`SocketMatcher`] as an alternative filter
    /// to match on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///     
    /// See [`PortFilter::new`] for more information.
    pub fn or_port(mut self, port: u16) -> Self {
        match &mut self.kind {
            SocketFilterKind::Any(filters) => {
                filters.push(SocketFilterKind::Port(PortFilter::new(port)));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::Port(PortFilter::new(port)));
                self.kind = SocketFilterKind::Any(filters);
            }
        }
        self
    }

    /// create a new IP network filter to filter on an IP Network.
    ///
    /// See [`IpNetFilter::new`] for more information.
    pub fn ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketFilterKind::IpNet(IpNetFilter::new(ip_net)),
            negate: false,
        }
    }

    /// Create a new optional IP network filter to filter on an IP Network,
    /// this filter will match in case socket address could not be found.
    ///
    /// See [`IpNetFilter::optional`] for more information.
    pub fn optional_ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketFilterKind::IpNet(IpNetFilter::optional(ip_net)),
            negate: false,
        }
    }

    /// Add a new IP network filter to the existing [`SocketMatcher`] to also filter on an IP Network.
    ///
    /// See [`IpNetFilter::new`] for more information.
    pub fn and_ip_net(mut self, ip_net: impl ip::IntoIpNet) -> Self {
        match &mut self.kind {
            SocketFilterKind::All(filters) => {
                filters.push(SocketFilterKind::IpNet(IpNetFilter::new(ip_net)));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::IpNet(IpNetFilter::new(ip_net)));
                self.kind = SocketFilterKind::All(filters);
            }
        }
        self
    }

    /// Add a new IP network filter to the existing [`SocketMatcher`] as an alternative filter to match on an IP Network.
    ///
    /// See [`IpNetFilter::new`] for more information.
    pub fn or_ip_net(mut self, ip_net: impl ip::IntoIpNet) -> Self {
        match &mut self.kind {
            SocketFilterKind::Any(filters) => {
                filters.push(SocketFilterKind::IpNet(IpNetFilter::new(ip_net)));
            }
            _ => {
                let mut filters = vec![self.kind];
                filters.push(SocketFilterKind::IpNet(IpNetFilter::new(ip_net)));
                self.kind = SocketFilterKind::Any(filters);
            }
        }
        self
    }

    /// Negate the current filter
    pub fn negate(self) -> Self {
        Self {
            kind: self.kind,
            negate: true,
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for SocketFilterKind {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            SocketFilterKind::SocketAddress(filter) => filter.matches(ext, ctx, req),
            SocketFilterKind::IpNet(filter) => filter.matches(ext, ctx, req),
            SocketFilterKind::Loopback(filter) => filter.matches(ext, ctx, req),
            SocketFilterKind::All(filters) => filters.iter().matches_and(ext, ctx, req),
            SocketFilterKind::Any(filters) => filters.iter().matches_or(ext, ctx, req),
            SocketFilterKind::Port(filter) => filter.matches(ext, ctx, req),
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

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketFilterKind
where
    Socket: crate::stream::Socket,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, stream: &Socket) -> bool {
        match self {
            SocketFilterKind::SocketAddress(filter) => filter.matches(ext, ctx, stream),
            SocketFilterKind::IpNet(filter) => filter.matches(ext, ctx, stream),
            SocketFilterKind::Loopback(filter) => filter.matches(ext, ctx, stream),
            SocketFilterKind::Port(filter) => filter.matches(ext, ctx, stream),
            SocketFilterKind::All(filters) => filters.iter().matches_and(ext, ctx, stream),
            SocketFilterKind::Any(filters) => filters.iter().matches_or(ext, ctx, stream),
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
