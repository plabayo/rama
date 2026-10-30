use std::{
    net::{IpAddr, Ipv4Addr},
    ops::RangeInclusive,
    sync::Arc,
};

use rama_core::extensions::Extensions;
use rama_net::address::{
    DomainTrie, Host, SocketAddress,
    ip::{
        IntoCanonicalIpAddr as _, TranslationPrefix, embedded_ipv4,
        ipnet::IpNet,
        scope::{IpScopes, ip_scope},
    },
};
use rama_utils::macros::{all_the_tuples_no_last_special_case, generate_set_and_with};

use super::ConnectUdpTarget;

/// A resolved address a CONNECT-UDP tunnel would send to, for a [`ConnectUdpPolicy`] to judge.
#[derive(Debug, Clone, Copy)]
pub struct ConnectUdpDestination<'a> {
    /// The target the client asked for.
    pub target: &'a ConnectUdpTarget,
    /// One resolved address of the target, IPv4-mapped IPv6 already canonicalized to IPv4.
    /// The tunnel sends to exactly this address when it is allowed.
    pub address: SocketAddress,
    /// The proxy's own address the request arrived on, when known.
    pub proxy_address: Option<SocketAddress>,
    /// The extensions of the CONNECT-UDP request, such as the
    /// [`UserId`](rama_net::user::UserId) an authentication layer in front inserted.
    pub extensions: &'a Extensions,
    /// The IPv4 addresses `address` carries for a translation or transition mechanism
    /// ([`embedded_ipv4`] and the proxy's translation prefixes): traffic to `address` can
    /// end at them, so policies judge them as well.
    pub embedded: &'a [Ipv4Addr],
    /// Whether `address` is inside one of the proxy's translation prefixes
    /// ([`ConnectUdpService::with_translation_prefix`](super::ConnectUdpService::with_translation_prefix)),
    /// whose translator the operator trusts.
    pub translated: bool,
}

impl ConnectUdpDestination<'_> {
    /// `address` and every IPv4 address it carries.
    pub fn ip_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        std::iter::once(self.address.ip_addr).chain(self.embedded.iter().copied().map(IpAddr::V4))
    }
}

/// The IPv4 addresses `address` carries and whether it is inside one of `prefixes`, or
/// `None` when a prefix contains it but it carries no valid IPv4 address there.
pub(super) fn embedded_destinations(
    address: IpAddr,
    prefixes: &[TranslationPrefix],
) -> Option<(Vec<Ipv4Addr>, bool)> {
    let IpAddr::V6(ipv6) = address else {
        return Some((Vec::new(), false));
    };
    let mut embedded = Vec::new();
    let mut translated = false;
    // Every containing prefix counts, so overlapping prefixes cannot hide an address.
    for prefix in prefixes.iter().filter(|prefix| prefix.contains(ipv6)) {
        translated = true;
        embedded.push(prefix.ipv4(ipv6)?);
    }
    if let Some(carried) = embedded_ipv4(ipv6) {
        embedded.extend(carried.addresses());
    }
    embedded.sort_unstable();
    embedded.dedup();
    Some((embedded, translated))
}

/// Decides which resolved addresses a CONNECT-UDP proxy may open tunnels to.
///
/// A tuple of policies allows a destination only when every member does.
pub trait ConnectUdpPolicy: Send + Sync + 'static {
    /// Whether the tunnel may send to `destination`.
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool;
}

impl<F> ConnectUdpPolicy for F
where
    F: Fn(&ConnectUdpDestination<'_>) -> bool + Send + Sync + 'static,
{
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
        self(destination)
    }
}

impl<P: ConnectUdpPolicy> ConnectUdpPolicy for Arc<P> {
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
        (**self).allows(destination)
    }
}

macro_rules! impl_connect_udp_policy_for_tuple {
    ($($ty:ident),+) => {
        impl<$($ty: ConnectUdpPolicy),+> ConnectUdpPolicy for ($($ty,)+) {
            fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
                let ($($ty,)+) = self;
                $($ty.allows(destination))&&+
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_connect_udp_policy_for_tuple);

/// The default [`ConnectUdpPolicy`]: refuses every non-global address and the proxy itself.
///
/// Denied by default are loopback, private and unique-local, link-local, shared (CGNAT),
/// unspecified, multicast, broadcast, documentation, benchmarking and reserved ranges
/// ([`IpScopes::NON_GLOBAL`]), and any port on the IP the request arrived on. The proxy's
/// own socket address is refused even when everything else is allowed: a tunnel to it
/// would loop.
///
/// An IPv6 address that carries IPv4 for a translation or transition mechanism (NAT64,
/// IPv4-compatible, 6to4, Teredo: [`ConnectUdpDestination::embedded`]) is allowed only when
/// every IPv4 address it carries is allowed too, as traffic to it can end there. An address
/// inside one of the proxy's own translation prefixes is judged by those IPv4 addresses
/// alone.
#[derive(Debug, Clone, Copy)]
pub struct DestinationScopePolicy {
    denied_scopes: IpScopes,
    deny_proxy_ip: bool,
}

impl Default for DestinationScopePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl DestinationScopePolicy {
    /// The safe default.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            denied_scopes: IpScopes::NON_GLOBAL,
            deny_proxy_ip: true,
        }
    }

    /// Allow private, local and loopback destinations, for a proxy into its own network.
    #[must_use]
    pub const fn allow_private() -> Self {
        Self {
            denied_scopes: IpScopes::empty(),
            deny_proxy_ip: false,
        }
    }

    generate_set_and_with! {
        /// The address scopes refused.
        pub fn denied_scopes(mut self, scopes: IpScopes) -> Self {
            self.denied_scopes = scopes;
            self
        }
    }

    generate_set_and_with! {
        /// Whether every port on the IP the request arrived on is refused.
        pub fn deny_proxy_ip(mut self, deny: bool) -> Self {
            self.deny_proxy_ip = deny;
            self
        }
    }

    /// Whether `ip` is the proxy itself: its socket, or any port on its IP when refused.
    fn is_proxy(self, ip: IpAddr, port: u16, proxy: Option<SocketAddress>) -> bool {
        proxy.is_some_and(|proxy| {
            proxy == SocketAddress::new(ip, port) || (self.deny_proxy_ip && proxy.ip_addr == ip)
        })
    }

    fn scope_denied(self, ip: IpAddr) -> bool {
        ip_scope(ip).intersects(self.denied_scopes)
    }
}

impl ConnectUdpPolicy for DestinationScopePolicy {
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
        let port = destination.address.port;
        let proxy = destination
            .proxy_address
            .map(|proxy| proxy.into_canonical_ip_addr());
        let outer = destination.address.ip_addr;
        // A trusted translation prefix overrides the outer scope only, never the self checks.
        !destination
            .ip_addrs()
            .any(|ip| self.is_proxy(ip, port, proxy))
            && (destination.translated || !self.scope_denied(outer))
            && !destination
                .embedded
                .iter()
                .any(|ip| self.scope_denied(IpAddr::V4(*ip)))
    }
}

/// What a matching [`ConnectUdpRule`] decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectUdpAction {
    /// The tunnel may send to the destination.
    Allow,
    /// The tunnel may not send to the destination.
    Deny,
}

/// One rule of [`ConnectUdpRules`]: it matches when each criterion it sets matches.
///
/// A rule without criteria matches every destination.
#[derive(Debug, Clone)]
pub struct ConnectUdpRule {
    action: ConnectUdpAction,
    networks: Vec<IpNet>,
    ports: Option<RangeInclusive<u16>>,
    names: Option<DomainTrie<()>>,
}

impl ConnectUdpRule {
    /// A rule allowing what it matches.
    #[must_use]
    pub const fn allow() -> Self {
        Self::new(ConnectUdpAction::Allow)
    }

    /// A rule denying what it matches.
    #[must_use]
    pub const fn deny() -> Self {
        Self::new(ConnectUdpAction::Deny)
    }

    const fn new(action: ConnectUdpAction) -> Self {
        Self {
            action,
            networks: Vec::new(),
            ports: None,
            names: None,
        }
    }

    generate_set_and_with! {
        /// Match addresses inside `network`; with several networks, any of them.
        pub fn network(mut self, network: IpNet) -> Self {
            self.networks.push(network.trunc());
            self
        }
    }

    generate_set_and_with! {
        /// Match target ports in `ports`.
        pub fn ports(mut self, ports: RangeInclusive<u16>) -> Self {
            self.ports = Some(ports);
            self
        }
    }

    generate_set_and_with! {
        /// Match targets requested by one of these names; `*.example.com` matches
        /// `example.com` and every name under it. Targets requested by IP never match.
        pub fn names(mut self, names: DomainTrie<()>) -> Self {
            self.names = Some(names);
            self
        }
    }

    fn matches(&self, destination: &ConnectUdpDestination<'_>, ip: IpAddr) -> bool {
        (self.networks.is_empty() || self.networks.iter().any(|network| network.contains(&ip)))
            && self
                .ports
                .as_ref()
                .is_none_or(|ports| ports.contains(&destination.address.port))
            && self
                .names
                .as_ref()
                .is_none_or(|names| match &destination.target.host {
                    Host::Name(domain) => names.is_match(domain),
                    _ => false,
                })
    }
}

/// An ordered list of [`ConnectUdpRule`]s: the first matching rule decides, and a
/// destination no rule matches gets the default action.
///
/// The rules judge the resolved address and, separately, every IPv4 address it carries
/// ([`ConnectUdpDestination::embedded`]); each must be allowed. So denying `8.8.8.8/32` also
/// denies its NAT64 form `64:ff9b::808:808`, and allowing that form takes rules allowing
/// both `64:ff9b::/96` and `8.8.8.8/32`.
///
/// Combine it with the address scope checks as a tuple, so both must allow:
/// `(DestinationScopePolicy::new(), rules)`.
#[derive(Debug, Clone)]
pub struct ConnectUdpRules {
    rules: Vec<ConnectUdpRule>,
    default: ConnectUdpAction,
}

impl ConnectUdpRules {
    /// Rules ending in `default` for destinations none of them match.
    #[must_use]
    pub const fn new(default: ConnectUdpAction) -> Self {
        Self {
            rules: Vec::new(),
            default,
        }
    }

    generate_set_and_with! {
        /// Append a rule, judged after the ones already added.
        pub fn rule(mut self, rule: ConnectUdpRule) -> Self {
            self.rules.push(rule);
            self
        }
    }
}

impl ConnectUdpPolicy for ConnectUdpRules {
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
        destination.ip_addrs().all(|ip| {
            let action = self
                .rules
                .iter()
                .find(|rule| rule.matches(destination, ip))
                .map_or(self.default, |rule| rule.action);
            action == ConnectUdpAction::Allow
        })
    }
}

#[cfg(test)]
mod tests;
