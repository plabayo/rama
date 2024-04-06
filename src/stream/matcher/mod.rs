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

mod private_ip;
#[doc(inline)]
pub use private_ip::PrivateIpNetMatcher;

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
use std::{fmt, sync::Arc};

/// A matcher to match on a [`Socket`].
///
/// [`Socket`]: crate::stream::Socket
pub struct SocketMatcher<State, Socket> {
    kind: SocketMatcherKind<State, Socket>,
    negate: bool,
}

impl<State, Socket> Clone for SocketMatcher<State, Socket> {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            negate: self.negate,
        }
    }
}

impl<State, Socket> fmt::Debug for SocketMatcher<State, Socket> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketMatcher")
            .field("kind", &self.kind)
            .field("negate", &self.negate)
            .finish()
    }
}

/// The different kinds of socket matchers.
enum SocketMatcherKind<State, Socket> {
    /// [`SocketAddressMatcher`], a matcher that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    SocketAddress(SocketAddressMatcher),
    /// [`LoopbackMatcher`], a matcher that matches if the peer address is a loopback address.
    Loopback(LoopbackMatcher),
    /// [`PrivateIpNetMatcher`], a matcher that matches if the peer address is a private address.
    PrivateIpNet(PrivateIpNetMatcher),
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
    All(Vec<SocketMatcher<State, Socket>>),
    /// `true` if no matchers are defined, or any of the defined matcher match.
    Any(Vec<SocketMatcher<State, Socket>>),
    /// A custom matcher that implements [`crate::service::Matcher`].
    Custom(Arc<dyn crate::service::Matcher<State, Socket>>),
}

impl<State, Socket> Clone for SocketMatcherKind<State, Socket> {
    fn clone(&self) -> Self {
        match self {
            Self::SocketAddress(matcher) => Self::SocketAddress(matcher.clone()),
            Self::Loopback(matcher) => Self::Loopback(matcher.clone()),
            Self::PrivateIpNet(matcher) => Self::PrivateIpNet(matcher.clone()),
            Self::Port(matcher) => Self::Port(matcher.clone()),
            Self::IpNet(matcher) => Self::IpNet(matcher.clone()),
            Self::All(matcher) => Self::All(matcher.clone()),
            Self::Any(matcher) => Self::Any(matcher.clone()),
            Self::Custom(matcher) => Self::Custom(matcher.clone()),
        }
    }
}

impl<State, Socket> fmt::Debug for SocketMatcherKind<State, Socket> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAddress(matcher) => f.debug_tuple("SocketAddress").field(matcher).finish(),
            Self::Loopback(matcher) => f.debug_tuple("Loopback").field(matcher).finish(),
            Self::PrivateIpNet(matcher) => f.debug_tuple("PrivateIpNet").field(matcher).finish(),
            Self::Port(matcher) => f.debug_tuple("Port").field(matcher).finish(),
            Self::IpNet(matcher) => f.debug_tuple("IpNet").field(matcher).finish(),
            Self::All(matcher) => f.debug_tuple("All").field(matcher).finish(),
            Self::Any(matcher) => f.debug_tuple("Any").field(matcher).finish(),
            Self::Custom(_) => f.debug_tuple("Custom").finish(),
        }
    }
}

impl<State, Socket> SocketMatcher<State, Socket> {
    /// Create a new socket address matcher to match on a socket address.
    ///
    /// See [`SocketAddressMatcher::new`] for more information.
    pub fn socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketMatcherKind::SocketAddress(SocketAddressMatcher::new(addr)),
            negate: false,
        }
    }

    /// Create a new optional socket address matcher to match on a socket address,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`SocketAddressMatcher::optional`] for more information.
    pub fn optional_socket_addr(addr: impl Into<std::net::SocketAddr>) -> Self {
        Self {
            kind: SocketMatcherKind::SocketAddress(SocketAddressMatcher::optional(addr)),
            negate: false,
        }
    }

    /// Add a new socket address matcher to the existing [`SocketMatcher`] to also match on a socket address.
    pub fn and_socket_addr(self, addr: impl Into<std::net::SocketAddr>) -> Self {
        self.and(Self::socket_addr(addr))
    }

    /// Add a new optional socket address matcher to the existing [`SocketMatcher`] to also match on a socket address.
    ///
    /// See [`SocketAddressMatcher::optional`] for more information.
    pub fn and_optional_socket_addr(self, addr: impl Into<std::net::SocketAddr>) -> Self {
        self.and(Self::optional_socket_addr(addr))
    }

    /// Add a new socket address matcher to the existing [`SocketMatcher`] as an alternative matcher to match on a socket address.
    ///
    /// See [`SocketAddressMatcher::new`] for more information.
    pub fn or_socket_addr(self, addr: impl Into<std::net::SocketAddr>) -> Self {
        self.or(Self::socket_addr(addr))
    }

    /// Add a new optional socket address matcher to the existing [`SocketMatcher`] as an alternative matcher to match on a socket address.
    ///
    /// See [`SocketAddressMatcher::optional`] for more information.
    pub fn or_optional_socket_addr(self, addr: impl Into<std::net::SocketAddr>) -> Self {
        self.or(Self::optional_socket_addr(addr))
    }

    /// create a new loopback matcher to match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn loopback() -> Self {
        Self {
            kind: SocketMatcherKind::Loopback(LoopbackMatcher::new()),
            negate: false,
        }
    }

    /// Create a new optional loopback matcher to match on whether or not the peer address is a loopback address,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`LoopbackMatcher::optional`] for more information.
    pub fn optional_loopback() -> Self {
        Self {
            kind: SocketMatcherKind::Loopback(LoopbackMatcher::optional()),
            negate: false,
        }
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] to also match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn and_loopback(self) -> Self {
        self.and(Self::loopback())
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] to also match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::optional`] for more information.
    pub fn and_optional_loopback(self) -> Self {
        self.and(Self::optional_loopback())
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] as an alternative matcher to match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::new`] for more information.
    pub fn or_loopback(self) -> Self {
        self.or(Self::loopback())
    }

    /// Add a new loopback matcher to the existing [`SocketMatcher`] as an alternative matcher to match on whether or not the peer address is a loopback address.
    ///
    /// See [`LoopbackMatcher::optional`] for more information.
    pub fn or_optional_loopback(self) -> Self {
        self.or(Self::optional_loopback())
    }

    /// create a new port matcher to match on the port part a [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortMatcher::new`] for more information.
    pub fn port(port: u16) -> Self {
        Self {
            kind: SocketMatcherKind::Port(PortMatcher::new(port)),
            negate: false,
        }
    }

    /// Create a new optional port matcher to match on the port part a [`SocketAddr`](std::net::SocketAddr),
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
    pub fn and_port(self, port: u16) -> Self {
        self.and(Self::port(port))
    }

    /// Add a new port matcher to the existing [`SocketMatcher`] as an alternative matcher
    /// to match on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///     
    /// See [`PortMatcher::optional`] for more information.
    pub fn and_optional_port(self, port: u16) -> Self {
        self.and(Self::optional_port(port))
    }

    /// Add a new port matcher to the existing [`SocketMatcher`] as an alternative matcher
    /// to match on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///     
    /// See [`PortMatcher::new`] for more information.
    pub fn or_port(self, port: u16) -> Self {
        self.or(Self::port(port))
    }

    /// Add a new port matcher to the existing [`SocketMatcher`] as an alternative matcher
    /// to match on the port part of the [`SocketAddr`](std::net::SocketAddr).
    ///
    /// See [`PortMatcher::optional`] for more information.
    pub fn or_optional_port(self, port: u16) -> Self {
        self.or(Self::optional_port(port))
    }

    /// create a new IP network matcher to match on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketMatcherKind::IpNet(IpNetMatcher::new(ip_net)),
            negate: false,
        }
    }

    /// Create a new optional IP network matcher to match on an IP Network,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`IpNetMatcher::optional`] for more information.
    pub fn optional_ip_net(ip_net: impl ip::IntoIpNet) -> Self {
        Self {
            kind: SocketMatcherKind::IpNet(IpNetMatcher::optional(ip_net)),
            negate: false,
        }
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] to also match on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn and_ip_net(self, ip_net: impl ip::IntoIpNet) -> Self {
        self.and(Self::ip_net(ip_net))
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] as an alternative matcher to match on an IP Network.
    ///
    /// See [`IpNetMatcher::optional`] for more information.
    pub fn and_optional_ip_net(self, ip_net: impl ip::IntoIpNet) -> Self {
        self.and(Self::optional_ip_net(ip_net))
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] as an alternative matcher to match on an IP Network.
    ///
    /// See [`IpNetMatcher::new`] for more information.
    pub fn or_ip_net(self, ip_net: impl ip::IntoIpNet) -> Self {
        self.or(Self::ip_net(ip_net))
    }

    /// Add a new IP network matcher to the existing [`SocketMatcher`] as an alternative matcher to match on an IP Network.
    ///
    /// See [`IpNetMatcher::optional`] for more information.
    pub fn or_optional_ip_net(self, ip_net: impl ip::IntoIpNet) -> Self {
        self.or(Self::optional_ip_net(ip_net))
    }

    /// create a new local IP network matcher to match on whether or not the peer address is a private address.
    ///
    /// See [`PrivateIpNetMatcher::new`] for more information.
    pub fn private_ip_net() -> Self {
        Self {
            kind: SocketMatcherKind::PrivateIpNet(PrivateIpNetMatcher::new()),
            negate: false,
        }
    }

    /// Create a new optional local IP network matcher to match on whether or not the peer address is a private address,
    /// this matcher will match in case socket address could not be found.
    ///
    /// See [`PrivateIpNetMatcher::optional`] for more information.
    pub fn optional_private_ip_net() -> Self {
        Self {
            kind: SocketMatcherKind::PrivateIpNet(PrivateIpNetMatcher::optional()),
            negate: false,
        }
    }

    /// Add a new local IP network matcher to the existing [`SocketMatcher`] to also match on whether or not the peer address is a private address.
    ///
    /// See [`PrivateIpNetMatcher::new`] for more information.
    pub fn and_private_ip_net(self) -> Self {
        self.and(Self::private_ip_net())
    }

    /// Add a new local IP network matcher to the existing [`SocketMatcher`] to also match on whether or not the peer address is a private address.
    ///
    /// See [`PrivateIpNetMatcher::optional`] for more information.
    pub fn and_optional_private_ip_net(self) -> Self {
        self.and(Self::optional_private_ip_net())
    }

    /// Add a new local IP network matcher to the existing [`SocketMatcher`] as an alternative matcher to match on whether or not the peer address is a private address.
    ///
    /// See [`PrivateIpNetMatcher::new`] for more information.
    pub fn or_private_ip_net(self) -> Self {
        self.or(Self::private_ip_net())
    }

    /// Add a new local IP network matcher to the existing [`SocketMatcher`] as an alternative matcher to match on whether or not the peer address is a private address.
    ///
    /// See [`PrivateIpNetMatcher::optional`] for more information.
    pub fn or_optional_private_ip_net(self) -> Self {
        self.or(Self::optional_private_ip_net())
    }

    /// Create a matcher that matches according to a custom predicate.
    ///
    /// See [`crate::service::Matcher`] for more information.
    pub fn custom<M>(matcher: M) -> Self
    where
        M: crate::service::Matcher<State, Socket>,
    {
        Self {
            kind: SocketMatcherKind::Custom(Arc::new(matcher)),
            negate: false,
        }
    }

    /// Add a custom matcher to match on top of the existing set of [`SocketMatcher`] matchers.
    ///
    /// See [`crate::service::Matcher`] for more information.
    pub fn and_custom<M>(self, matcher: M) -> Self
    where
        M: crate::service::Matcher<State, Socket>,
    {
        self.and(Self::custom(matcher))
    }

    /// Create a custom matcher to match as an alternative to the existing set of [`SocketMatcher`] matchers.
    ///
    /// See [`crate::service::Matcher`] for more information.
    pub fn or_custom<M>(self, matcher: M) -> Self
    where
        M: crate::service::Matcher<State, Socket>,
    {
        self.or(Self::custom(matcher))
    }

    /// Add a [`SocketMatcher`] to match on top of the existing set of [`SocketMatcher`] matchers.
    pub fn and(mut self, matcher: SocketMatcher<State, Socket>) -> Self {
        match (self.negate, &mut self.kind) {
            (false, SocketMatcherKind::All(v)) => {
                v.push(matcher);
                self
            }
            _ => SocketMatcher {
                kind: SocketMatcherKind::All(vec![self, matcher]),
                negate: false,
            },
        }
    }

    /// Create a [`SocketMatcher`] matcher to match as an alternative to the existing set of [`SocketMatcher`] matchers.
    pub fn or(mut self, matcher: SocketMatcher<State, Socket>) -> Self {
        match (self.negate, &mut self.kind) {
            (false, SocketMatcherKind::Any(v)) => {
                v.push(matcher);
                self
            }
            _ => SocketMatcher {
                kind: SocketMatcherKind::Any(vec![self, matcher]),
                negate: false,
            },
        }
    }

    /// Negate the current matcher
    pub fn negate(self) -> Self {
        Self {
            kind: self.kind,
            negate: true,
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>>
    for SocketMatcherKind<State, Request<Body>>
where
    State: 'static,
    Body: 'static,
{
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            SocketMatcherKind::SocketAddress(matcher) => matcher.matches(ext, ctx, req),
            SocketMatcherKind::IpNet(matcher) => matcher.matches(ext, ctx, req),
            SocketMatcherKind::Loopback(matcher) => matcher.matches(ext, ctx, req),
            SocketMatcherKind::PrivateIpNet(matcher) => matcher.matches(ext, ctx, req),
            SocketMatcherKind::All(matchers) => matchers.iter().matches_and(ext, ctx, req),
            SocketMatcherKind::Any(matchers) => matchers.iter().matches_or(ext, ctx, req),
            SocketMatcherKind::Port(matcher) => matcher.matches(ext, ctx, req),
            SocketMatcherKind::Custom(matcher) => matcher.matches(ext, ctx, req),
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>>
    for SocketMatcher<State, Request<Body>>
where
    State: 'static,
    Body: 'static,
{
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

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketMatcherKind<State, Socket>
where
    Socket: crate::stream::Socket,
    State: 'static,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, stream: &Socket) -> bool {
        match self {
            SocketMatcherKind::SocketAddress(matcher) => matcher.matches(ext, ctx, stream),
            SocketMatcherKind::IpNet(matcher) => matcher.matches(ext, ctx, stream),
            SocketMatcherKind::Loopback(matcher) => matcher.matches(ext, ctx, stream),
            SocketMatcherKind::PrivateIpNet(matcher) => matcher.matches(ext, ctx, stream),
            SocketMatcherKind::Port(matcher) => matcher.matches(ext, ctx, stream),
            SocketMatcherKind::All(matchers) => matchers.iter().matches_and(ext, ctx, stream),
            SocketMatcherKind::Any(matchers) => matchers.iter().matches_or(ext, ctx, stream),
            SocketMatcherKind::Custom(matcher) => matcher.matches(ext, ctx, stream),
        }
    }
}

impl<State, Socket> crate::service::Matcher<State, Socket> for SocketMatcher<State, Socket>
where
    Socket: crate::stream::Socket,
    State: 'static,
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

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use crate::service::Matcher;

    use super::*;

    struct BooleanMatcher(bool);

    impl Matcher<(), Request<()>> for BooleanMatcher {
        fn matches(
            &self,
            _ext: Option<&mut Extensions>,
            _ctx: &Context<()>,
            _req: &Request<()>,
        ) -> bool {
            self.0
        }
    }

    #[test]
    fn test_matcher_ands_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = v[0] && v[1] && v[2];
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.and(b).and(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_negation_with_ands_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !v[0] && v[1] && v[2];
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.negate().and(b).and(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_ands_combination_negated() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !(v[0] && v[1] && v[2]);
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.and(b).and(c).negate();
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_ors_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = v[0] || v[1] || v[2];
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.or(b).or(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_negation_with_ors_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !v[0] || v[1] || v[2];
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.negate().or(b).or(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_ors_combination_negated() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !(v[0] || v[1] || v[2]);
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.or(b).or(c).negate();
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }

    #[test]
    fn test_matcher_or_and_or_and_negation() {
        for v in [true, false].into_iter().permutations(5) {
            let expected = (v[0] || v[1]) && (v[2] || v[3]) && !v[4];
            let a = SocketMatcher::custom(BooleanMatcher(v[0]));
            let b = SocketMatcher::custom(BooleanMatcher(v[1]));
            let c = SocketMatcher::custom(BooleanMatcher(v[2]));
            let d = SocketMatcher::custom(BooleanMatcher(v[3]));
            let e = SocketMatcher::custom(BooleanMatcher(v[4]));

            let matcher = (a.or(b)).and(c.or(d)).and(e.negate());
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({:#?}).matches({:#?})",
                matcher,
                req
            );
        }
    }
}
