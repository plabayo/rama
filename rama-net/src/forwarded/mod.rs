//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

use core::{fmt, net::IpAddr};

use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef},
};
use rama_utils::macros::generate_set_and_with;

#[cfg(feature = "std")]
use crate::stream::SocketInfo;
use crate::{
    address::{SocketAddress, ip::ipnet::IpNet},
    std::{boxed::Box, string::String, sync::Arc, vec::Vec},
};

mod obfuscated;
#[doc(inline)]
use obfuscated::{ObfNode, ObfPort};

mod node;
#[doc(inline)]
pub use node::NodeId;

mod element;
#[doc(inline)]
pub use element::{ForwardedAuthority, ForwardedElement};

mod proto;
#[doc(inline)]
pub use proto::ForwardedProtocol;

mod version;
#[doc(inline)]
pub use version::ForwardedVersion;

/// Selects which element of a [`Forwarded`] chain describes the client.
///
/// A chain lists the client-most hop first and the hop nearest to this service last
/// (RFC 7239 §4). Only what a trusted proxy wrote can be relied on (RFC 7239 §8.1), and a
/// proxy appending to a header the client sent keeps the client's own claim in front, so the
/// default counts from the right, as established proxies and frameworks do.
///
/// Elements whose `for` address is a [trusted proxy](Self::with_trusted_proxies) are skipped,
/// then [`hops`](Self::with_hops) more are, counting from the [`side`](Self::with_side).
/// Without a remaining element there is no client, and callers fall back to the connection.
///
/// With trusted proxies set, a chain is only relied on when the connection it arrived on
/// comes from one of them (see [`trusts_peer`](Self::trusts_peer)): any other peer could
/// have written the chain itself, so it has no forwarded client and is its own client.
/// Without trusted proxies every peer is relied on, which fits a service only reachable
/// through its proxies.
///
/// It is an extension of its own, read by every consumer of [`Forwarded`] client information
/// (see [`ForwardedClientExt`]); layers that record forwarding information can install it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(net))]
pub struct ForwardedSelectionPolicy {
    side: ForwardedSide,
    hops: usize,
    trusted_proxies: Box<[IpNet]>,
}

/// The end of a [`Forwarded`] chain a [`ForwardedSelectionPolicy`] counts from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ForwardedSide {
    /// The nearest hop's element: all that a single trusted proxy vouches for.
    #[default]
    Rightmost,
    /// The original client's own claim, reliable only when every hop overwrites rather than
    /// appends.
    Leftmost,
}

impl ForwardedSelectionPolicy {
    /// The rightmost element, without skipping any.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// The end of the chain to count from.
        pub fn side(mut self, side: ForwardedSide) -> Self {
            self.side = side;
            self
        }
    }

    generate_set_and_with! {
        /// Elements to skip from the [side](Self::with_side), such as `1` behind two trusted
        /// proxies that each append.
        pub fn hops(mut self, hops: usize) -> Self {
            self.hops = hops;
            self
        }
    }

    generate_set_and_with! {
        /// Rely only on chains received from one of these proxies, and skip the elements
        /// whose `for` address is one of them.
        pub fn trusted_proxies(mut self, proxies: impl IntoIterator<Item = IpNet>) -> Self {
            self.trusted_proxies = proxies.into_iter().collect();
            self
        }
    }

    /// Install this shared policy in `extensions`, unless `keep_existing` and one is set
    /// already.
    pub fn install(self: &Arc<Self>, extensions: &Extensions, keep_existing: bool) {
        if !(keep_existing && extensions.contains::<Self>()) {
            extensions.insert_arc(self.clone());
        }
    }

    /// Whether `ip` is one of the trusted proxies, IPv4-mapped IPv6 addresses being IPv4 ones.
    #[must_use]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        // A network may be listed in either form of the same IPv4 range.
        let mapped = match ip {
            IpAddr::V4(ip) => Some(IpAddr::V6(ip.to_ipv6_mapped())),
            IpAddr::V6(_) => None,
        };
        self.trusted_proxies.iter().any(|proxy| {
            proxy.contains(&ip) || mapped.is_some_and(|mapped| proxy.contains(&mapped))
        })
    }

    /// Whether forwarding information received over the (ingress) connection of `extensions`
    /// can be relied on.
    ///
    /// Always without trusted proxies; with them only when the peer of that connection is
    /// one, so not when the peer is unknown.
    #[must_use]
    pub fn trusts_peer(&self, extensions: &Extensions) -> bool {
        if self.trusted_proxies.is_empty() {
            return true;
        }
        #[cfg(feature = "std")]
        {
            SocketInfo::ingress(extensions)
                .is_some_and(|info| self.is_trusted_proxy(info.peer_addr().ip_addr))
        }
        #[cfg(not(feature = "std"))]
        {
            // No transport peer is known here, so none can be a trusted proxy.
            let _ = extensions;
            false
        }
    }

    /// The element of `forwarded` describing the client, if any remains.
    ///
    /// The peer the chain was received from is not considered here, see
    /// [`trusts_peer`](Self::trusts_peer) and [`ForwardedClientExt`], which does.
    #[must_use]
    pub fn select<'a>(&self, forwarded: &'a Forwarded) -> Option<&'a ForwardedElement> {
        let trusted = |element: &ForwardedElement| {
            element
                .forwarded_for()
                .and_then(NodeId::ip)
                .is_some_and(|ip| self.is_trusted_proxy(ip))
        };
        let mut candidates = forwarded.iter().filter(|element| !trusted(element));
        match self.side {
            ForwardedSide::Leftmost => candidates.nth(self.hops),
            ForwardedSide::Rightmost => candidates.rev().nth(self.hops),
        }
    }
}

/// The client of the [`Forwarded`] chain in these extensions, selected by their
/// [`ForwardedSelectionPolicy`], else the default one (the rightmost element).
///
/// A chain received from a peer the policy [does not trust](ForwardedSelectionPolicy::trusts_peer)
/// has no client.
///
/// Implemented for every [`ExtensionsRef`]; sealed, as it only reads what the extensions hold.
/// Unlike [`ClientIp`](crate::ClientIp) it never falls back to the connection's peer.
pub trait ForwardedClientExt: ExtensionsRef + private::Sealed {
    /// The chain as recorded, unless it came from a peer the policy does not trust: what may
    /// be selected from, or passed on to the next hop as this connection's history.
    fn trusted_forwarded(&self) -> Option<&Forwarded> {
        let extensions = self.extensions();
        let forwarded = extensions.get_ref::<Forwarded>()?;
        match extensions.get_ref::<ForwardedSelectionPolicy>() {
            Some(policy) if !policy.trusts_peer(extensions) => None,
            _ => Some(forwarded),
        }
    }

    /// The element describing the client.
    fn forwarded_client(&self) -> Option<&ForwardedElement> {
        let forwarded = self.trusted_forwarded()?;
        match self.extensions().get_ref::<ForwardedSelectionPolicy>() {
            Some(policy) => policy.select(forwarded),
            None => ForwardedSelectionPolicy::default().select(forwarded),
        }
    }

    /// The client's IP, from its `for` node.
    fn forwarded_client_ip(&self) -> Option<IpAddr> {
        self.forwarded_client()?.forwarded_for()?.ip()
    }

    /// The client's IP and port, from its `for` node.
    fn forwarded_client_socket_addr(&self) -> Option<SocketAddress> {
        self.forwarded_client()?.forwarded_for()?.socket_address()
    }

    /// The host the client asked for.
    fn forwarded_client_host(&self) -> Option<&ForwardedAuthority> {
        self.forwarded_client()?.forwarded_host()
    }

    /// The protocol the client used.
    fn forwarded_client_proto(&self) -> Option<ForwardedProtocol> {
        self.forwarded_client()?.forwarded_proto()
    }

    /// The HTTP version the client used.
    fn forwarded_client_version(&self) -> Option<ForwardedVersion> {
        self.forwarded_client()?.forwarded_version()
    }
}

impl<T: ExtensionsRef + ?Sized> ForwardedClientExt for T {}

mod private {
    pub trait Sealed {}
    impl<T: rama_core::extensions::ExtensionsRef + ?Sized> Sealed for T {}
}

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(net))]
/// Forwarding information stored as a chain.
///
/// This extension (which can be stored and modified via the [`Extensions`])
/// allows to keep track of the forward information. E.g. what was the original
/// host used by the user, by which proxy it was forwarded, what was the intended
/// protocol (e.g. https), etc...
///
/// RFC: <https://datatracker.ietf.org/doc/html/rfc7239>
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct Forwarded {
    first: ForwardedElement,
    others: Vec<ForwardedElement>,
}

impl Forwarded {
    /// Create a new [`Forwarded`] extension for the given [`ForwardedElement`],
    /// the first (client-most) element of the chain.
    #[must_use]
    pub const fn new(element: ForwardedElement) -> Self {
        Self {
            first: element,
            others: Vec::new(),
        }
    }

    /// The element describing the client, per `policy`.
    #[must_use]
    pub fn client(&self, policy: &ForwardedSelectionPolicy) -> Option<&ForwardedElement> {
        policy.select(self)
    }

    /// Record the elements a source of forwarding information found into the chain of
    /// `extensions`.
    ///
    /// Sources are read from the nearest hop outwards, such as a PROXY protocol header before
    /// the HTTP headers it carries, so these elements go before those recorded already.
    pub fn record(extensions: &Extensions, elements: impl IntoIterator<Item = ForwardedElement>) {
        let mut elements = elements.into_iter();
        let Some(first) = elements.next() else {
            return;
        };
        let forwarded = if let Some(nearer) = extensions.get_ref::<Self>() {
            let mut forwarded = nearer.clone();
            forwarded.prepend(core::iter::once(first).chain(elements));
            forwarded
        } else {
            let mut forwarded = Self::new(first);
            forwarded.extend(elements);
            forwarded
        };
        extensions.insert(forwarded);
    }

    /// Prepend elements written by hops farther away than this chain's, keeping their order.
    pub fn prepend(&mut self, farther: impl IntoIterator<Item = ForwardedElement>) -> &mut Self {
        let mut farther = farther.into_iter();
        if let Some(first) = farther.next() {
            let nearer = core::mem::replace(&mut self.first, first);
            let rest: Vec<_> = farther.chain(Some(nearer)).collect();
            self.others.splice(0..0, rest);
        }
        self
    }

    /// Append a [`ForwardedElement`] to this [`Forwarded`] context.
    pub fn append(&mut self, element: ForwardedElement) -> &mut Self {
        self.others.push(element);
        self
    }

    /// Extend this [`Forwarded`] context with the given [`ForwardedElement`]s.
    pub fn extend(&mut self, elements: impl IntoIterator<Item = ForwardedElement>) -> &mut Self {
        self.others.extend(elements);
        self
    }

    /// Iterate over the [`ForwardedElement`]s in this [`Forwarded`] context.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &ForwardedElement> {
        core::iter::once(&self.first).chain(self.others.iter())
    }
}

impl IntoIterator for Forwarded {
    type Item = ForwardedElement;
    type IntoIter = core::iter::Chain<
        core::iter::Once<ForwardedElement>,
        crate::std::vec::IntoIter<ForwardedElement>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        let iter = self.others.into_iter();
        core::iter::once(self.first).chain(iter)
    }
}

impl From<ForwardedElement> for Forwarded {
    #[inline]
    fn from(value: ForwardedElement) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Forwarded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.first.fmt(f)?;
        for other in &self.others {
            write!(f, ",{other}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Forwarded {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<String> for Forwarded {
    type Error = BoxError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<&str> for Forwarded {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<Vec<u8>> for Forwarded {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes.as_ref())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<&[u8]> for Forwarded {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes)?;
        Ok(Self { first, others })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::HostWithOptPort;

    fn chain(nodes: &[&str]) -> Forwarded {
        let mut elements = nodes
            .iter()
            .map(|node| ForwardedElement::new_forwarded_for(NodeId::try_from(*node).unwrap()));
        let mut forwarded = Forwarded::new(elements.next().unwrap());
        forwarded.extend(elements);
        forwarded
    }

    fn selected(policy: &ForwardedSelectionPolicy, forwarded: &Forwarded) -> Option<String> {
        policy
            .select(forwarded)
            .and_then(ForwardedElement::forwarded_for)
            .map(|node| node.to_string())
    }

    #[test]
    fn selection_counts_hops_from_a_side_after_skipping_trusted_proxies() {
        let forwarded = chain(&["198.51.100.7", "10.0.0.2", "10.0.0.1"]);
        let trusted: IpNet = "10.0.0.0/8".parse().unwrap();
        for (policy, expected) in [
            (ForwardedSelectionPolicy::new(), Some("10.0.0.1")),
            (
                ForwardedSelectionPolicy::new().with_hops(1),
                Some("10.0.0.2"),
            ),
            (
                ForwardedSelectionPolicy::new().with_hops(2),
                Some("198.51.100.7"),
            ),
            // A chain shorter than the hops to pass names no client.
            (ForwardedSelectionPolicy::new().with_hops(3), None),
            (
                ForwardedSelectionPolicy::new().with_trusted_proxies([trusted]),
                Some("198.51.100.7"),
            ),
            (
                ForwardedSelectionPolicy::new()
                    .with_trusted_proxies([trusted])
                    .with_hops(1),
                None,
            ),
            (
                ForwardedSelectionPolicy::new().with_side(ForwardedSide::Leftmost),
                Some("198.51.100.7"),
            ),
            (
                ForwardedSelectionPolicy::new()
                    .with_side(ForwardedSide::Leftmost)
                    .with_hops(1),
                Some("10.0.0.2"),
            ),
        ] {
            assert_eq!(
                selected(&policy, &forwarded).as_deref(),
                expected,
                "{policy:?}"
            );
        }
        // Every element a trusted proxy: none is the client.
        let trusted_only = chain(&["10.0.0.2", "10.0.0.1"]);
        let policy = ForwardedSelectionPolicy::new().with_trusted_proxies([trusted]);
        assert_eq!(selected(&policy, &trusted_only), None);
    }

    #[test]
    fn the_extension_trait_reads_the_installed_policy() {
        let extensions = Extensions::new();
        extensions.insert(chain(&["198.51.100.7:4711", "10.0.0.1"]));
        assert_eq!(
            extensions.forwarded_client_ip(),
            Some(IpAddr::from([10, 0, 0, 1]))
        );
        assert_eq!(extensions.forwarded_client_socket_addr(), None);
        Arc::new(ForwardedSelectionPolicy::new().with_side(ForwardedSide::Leftmost))
            .install(&extensions, false);
        assert_eq!(
            extensions.forwarded_client_socket_addr(),
            Some(SocketAddress::new(IpAddr::from([198, 51, 100, 7]), 4711))
        );
        // An installed policy is kept when asked to.
        Arc::new(ForwardedSelectionPolicy::new()).install(&extensions, true);
        assert_eq!(
            extensions.forwarded_client_ip(),
            Some(IpAddr::from([198, 51, 100, 7]))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_chain_has_a_client_only_from_a_peer_the_policy_trusts() {
        let policy =
            ForwardedSelectionPolicy::new().with_trusted_proxies(["10.0.0.0/8".parse().unwrap()]);
        for (peer, trusted) in [
            (Some("10.0.0.1"), true),
            (Some("::ffff:10.0.0.1"), true),
            (Some("198.51.100.9"), false),
            (Some("::ffff:198.51.100.9"), false),
            (None, false),
        ] {
            let extensions = Extensions::new();
            extensions.insert(policy.clone());
            extensions.insert(chain(&["198.51.100.7", "10.0.0.1"]));
            if let Some(peer) = peer {
                extensions.insert(SocketInfo::new(
                    None,
                    SocketAddress::new(peer.parse().unwrap(), 0),
                ));
            }
            assert_eq!(policy.trusts_peer(&extensions), trusted, "{peer:?}");
            assert_eq!(
                extensions.trusted_forwarded().is_some(),
                trusted,
                "{peer:?}"
            );
            assert_eq!(
                extensions.forwarded_client_ip(),
                trusted.then_some(IpAddr::from([198, 51, 100, 7])),
                "{peer:?}"
            );
        }

        // Without trusted proxies any peer is relied on, a missing one included.
        let extensions = Extensions::new();
        extensions.insert(ForwardedSelectionPolicy::new());
        extensions.insert(chain(&["198.51.100.7"]));
        assert_eq!(
            extensions.forwarded_client_ip(),
            Some(IpAddr::from([198, 51, 100, 7]))
        );
    }

    #[test]
    fn a_trusted_network_matches_either_form_of_an_ipv4_address() {
        for network in ["10.0.0.0/8", "::ffff:10.0.0.0/104"] {
            let policy =
                ForwardedSelectionPolicy::new().with_trusted_proxies([network.parse().unwrap()]);
            for (ip, trusted) in [
                ("10.1.2.3", true),
                ("::ffff:10.1.2.3", true),
                ("11.0.0.1", false),
                ("::ffff:11.0.0.1", false),
            ] {
                assert_eq!(
                    policy.is_trusted_proxy(ip.parse().unwrap()),
                    trusted,
                    "{network} {ip}"
                );
            }
        }
    }

    #[test]
    fn a_later_source_records_hops_farther_away() {
        let extensions = Extensions::new();
        // A PROXY protocol header names the hop nearest to this service.
        Forwarded::record(&extensions, chain(&["10.0.0.1"]));
        // The HTTP headers it carries were written by hops before it.
        Forwarded::record(&extensions, chain(&["198.51.100.7", "10.0.0.2"]));
        let order: Vec<String> = extensions
            .get_ref::<Forwarded>()
            .unwrap()
            .iter()
            .map(|element| element.forwarded_for().unwrap().to_string())
            .collect();
        assert_eq!(order, ["198.51.100.7", "10.0.0.2", "10.0.0.1"]);
    }

    #[test]
    fn test_forwarded_parse_invalid() {
        for s in [
            "",
            "foobar",
            "127.0.0.1",
            "⌨️",
            "for=_foo;for=_bar",
            ",",
            "for=127.0.0.1,",
            "for=127.0.0.1,foobar",
            "for=127.0.0.1,127.0.0.1",
            "for=127.0.0.1,⌨️",
            "for=127.0.0.1,for=_foo;for=_bar",
            "foobar,for=127.0.0.1",
            "127.0.0.1,for=127.0.0.1",
            "⌨️,for=127.0.0.1",
            "for=_foo;for=_bar,for=127.0.0.1",
        ] {
            if let Ok(el) = Forwarded::try_from(s) {
                panic!("unexpected parse success: input {s}: {el:?}");
            }
        }
    }

    #[test]
    fn test_forwarded_parse_happy_spec() {
        for (s, expected) in [
            (
                r##"for="_gazonk""##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("_gazonk").unwrap(),
                    ),
                    others: Vec::new(),
                },
            ),
            (
                r##"for=192.0.2.43, for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![ForwardedElement::new_forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![ForwardedElement::new_forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=127.0.0.1"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("198.51.100.17").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("127.0.0.1").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("198.51.100.17").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43, for="[2001:db8:cafe::17]:4000", for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]:4000").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::try_from(
                            "for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
                        )
                        .unwrap(),
                    ],
                },
            ),
            (
                r##"for="192.0.2.43:4000",for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43:4000").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::try_from(
                            "for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
                        )
                        .unwrap(),
                    ],
                },
            ),
        ] {
            let element = match Forwarded::try_from(s) {
                Ok(el) => el,
                Err(err) => panic!("failed to parse happy spec el '{s}': {err}"),
            };
            assert_eq!(element, expected, "input: {s}");
        }
    }

    #[test]
    fn test_forwarded_client_authority() {
        for (s, expected) in [
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                None,
            ),
            (
                r##"host=example.com,for=195.2.34.12"##,
                Some(HostWithOptPort::example_domain()),
            ),
            (
                r##"host="example.com:443",for=195.2.34.12"##,
                Some(HostWithOptPort::example_domain_https()),
            ),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(
                forwarded
                    .iter()
                    .next()
                    .and_then(|el| el.forwarded_host())
                    .map(|authority| authority.0.clone()),
                expected
            );
        }
    }

    #[test]
    fn test_forwarded_client_protoy() {
        for (s, expected) in [
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                None,
            ),
            (
                r##"proto=http,for=195.2.34.12"##,
                Some(ForwardedProtocol::HTTP),
            ),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(
                forwarded.iter().next().and_then(|el| el.forwarded_proto()),
                expected
            );
        }
    }
}
