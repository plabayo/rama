use std::sync::Arc;

use rama_net::address::{
    SocketAddress,
    ip::{
        IntoCanonicalIpAddr as _,
        scope::{IpScopes, ip_scope},
    },
};
use rama_utils::macros::generate_set_and_with;

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
}

/// Decides which resolved addresses a CONNECT-UDP proxy may open tunnels to.
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

/// The default [`ConnectUdpPolicy`]: refuses every non-global address and the proxy itself.
///
/// Denied by default are loopback, private and unique-local, link-local, shared (CGNAT),
/// unspecified, multicast, broadcast, documentation, benchmarking and reserved ranges
/// ([`IpScopes::NON_GLOBAL`]), and any port on the IP the request arrived on. The proxy's
/// own socket address is refused even when everything else is allowed: a tunnel to it
/// would loop.
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
}

impl ConnectUdpPolicy for DestinationScopePolicy {
    fn allows(&self, destination: &ConnectUdpDestination<'_>) -> bool {
        let address = destination.address;
        if let Some(proxy) = destination
            .proxy_address
            .map(|proxy| proxy.into_canonical_ip_addr())
            && (address == proxy || (self.deny_proxy_ip && address.ip_addr == proxy.ip_addr))
        {
            return false;
        }
        !ip_scope(address.ip_addr).intersects(self.denied_scopes)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use rama_net::address::Host;

    use super::*;

    fn allows(policy: &impl ConnectUdpPolicy, address: &str, proxy: Option<&str>) -> bool {
        let target = ConnectUdpTarget::new(Host::LOCALHOST_NAME, NonZeroU16::MIN);
        policy.allows(&ConnectUdpDestination {
            target: &target,
            address: address.parse().unwrap(),
            proxy_address: proxy.map(|proxy| proxy.parse().unwrap()),
        })
    }

    #[test]
    fn the_default_refuses_non_global_addresses() {
        let policy = DestinationScopePolicy::default();
        for address in [
            "127.0.0.1:53",
            "10.0.0.1:53",
            "172.16.0.1:53",
            "192.168.1.1:53",
            "100.64.0.1:53",
            "169.254.169.254:53",
            "0.0.0.0:53",
            "224.0.0.251:5353",
            "255.255.255.255:53",
            "[::1]:53",
            "[::]:53",
            "[fe80::1]:53",
            "[fd00::1]:53",
            "[ff02::fb]:5353",
            "[::ffff:127.0.0.1]:53",
            "[::ffff:10.0.0.1]:53",
        ] {
            assert!(!allows(&policy, address, None), "{address}");
        }
        assert!(allows(&policy, "8.8.8.8:53", None));
        assert!(allows(&policy, "[2001:4860:4860::8888]:53", None));
    }

    #[test]
    fn the_default_refuses_the_proxy_ip_on_every_port() {
        let policy = DestinationScopePolicy::default();
        assert!(!allows(&policy, "203.0.113.7:53", Some("203.0.113.7:443")));
        assert!(allows(&policy, "8.8.8.8:53", Some("203.0.113.7:443")));
        let policy = policy.with_deny_proxy_ip(false);
        assert!(allows(&policy, "8.8.4.4:53", Some("8.8.4.4:443")));
    }

    #[test]
    fn allowing_private_still_refuses_the_proxy_socket() {
        let policy = DestinationScopePolicy::allow_private();
        assert!(allows(&policy, "127.0.0.1:53", Some("127.0.0.1:443")));
        assert!(allows(&policy, "[::1]:53", None));
        assert!(!allows(&policy, "127.0.0.1:443", Some("127.0.0.1:443")));
        // A dual-stack listener reports a v4-mapped local address.
        assert!(!allows(
            &policy,
            "127.0.0.1:443",
            Some("[::ffff:127.0.0.1]:443")
        ));
    }

    #[test]
    fn closures_are_policies() {
        let policy = |destination: &ConnectUdpDestination<'_>| destination.address.port == 53;
        assert!(allows(&policy, "127.0.0.1:53", None));
        assert!(!allows(&policy, "127.0.0.1:54", None));
    }
}
