use core::fmt::Debug;
use core::hash::Hash;
use std::net::IpAddr;

use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;

use crate::address::ip::ipnet::IpNet;

/// A key to rate limit on: the bucket-map key of a
/// [`KeyedRatePolicy`](super::KeyedRatePolicy).
pub trait RateKey: Hash + Eq + Clone + Debug + Send + Sync + 'static {
    /// Telemetry attributes identifying this key.
    #[cfg(feature = "opentelemetry")]
    fn attributes(
        &self,
    ) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> + '_ {
        core::iter::empty()
    }
}

impl RateKey for IpAddr {
    #[cfg(feature = "opentelemetry")]
    fn attributes(
        &self,
    ) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> + '_ {
        use rama_core::telemetry::opentelemetry::{KeyValue, semantic_conventions};
        core::iter::once(KeyValue::new(
            semantic_conventions::attribute::CLIENT_ADDRESS,
            self.to_string(),
        ))
    }
}

impl RateKey for String {}
impl RateKey for u64 {}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extensions;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_mapped_ipv6_collapses_to_ipv4() {
        let key = ClientIpRateKey::new();
        // the dual-stack peer form and the plain v4 form must key identically
        assert_eq!(key.key_for(ip("::ffff:203.0.113.5")), ip("203.0.113.5"));
        assert_eq!(
            key.key_for(ip("::ffff:203.0.113.5")),
            key.key_for(ip("203.0.113.5"))
        );
    }

    #[test]
    fn ipv6_aggregates_to_prefix() {
        let key = ClientIpRateKey::new(); // default /64
        // two addresses in the same /64 share one bucket ...
        assert_eq!(
            key.key_for(ip("2001:db8:1:2::1")),
            key.key_for(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_eq!(key.key_for(ip("2001:db8:1:2::1")), ip("2001:db8:1:2::"));
        // ... a different /64 does not
        assert_ne!(
            key.key_for(ip("2001:db8:1:2::1")),
            key.key_for(ip("2001:db8:1:3::1"))
        );
    }

    #[test]
    fn ipv6_prefix_128_keys_exact_address() {
        let key = ClientIpRateKey::new().with_ipv6_prefix(128);
        assert_eq!(key.key_for(ip("2001:db8:1:2::1")), ip("2001:db8:1:2::1"));
        assert_ne!(
            key.key_for(ip("2001:db8:1:2::1")),
            key.key_for(ip("2001:db8:1:2::2"))
        );
    }

    #[test]
    fn ipv4_is_never_aggregated() {
        let key = ClientIpRateKey::new().with_ipv6_prefix(1);
        assert_eq!(key.key_for(ip("203.0.113.5")), ip("203.0.113.5"));
    }

    #[test]
    fn ipv6_prefix_is_clamped() {
        assert_eq!(ClientIpRateKey::new().with_ipv6_prefix(0).ipv6_prefix, 1);
        assert_eq!(
            ClientIpRateKey::new().with_ipv6_prefix(200).ipv6_prefix,
            128
        );
    }

    #[test]
    fn extractor_reads_and_canonicalises_client_ip() {
        use crate::address::SocketAddress;
        use crate::stream::SocketInfo;

        let ext = Extensions::new();
        ext.insert(SocketInfo::new(
            None,
            SocketAddress::new(ip("::ffff:203.0.113.5"), 0),
        ));
        let got = ClientIpRateKey::new().rate_key(&ext).unwrap();
        assert_eq!(got, Some(ip("203.0.113.5")));
    }
}

/// Derives the [`RateKey`] of an input for a
/// [`KeyedRatePolicy`](super::KeyedRatePolicy).
///
/// `Ok(None)` means the key cannot be derived for this input (e.g. no
/// client IP is known); how that is handled is up to the policy
/// ([`KeyedRatePolicy::with_missing_key_allowed`](super::KeyedRatePolicy)).
///
/// Any `Fn(&Input) -> Result<Option<K>, BoxError>` is an extractor.
pub trait InputToRateKey<Input>: Send + Sync + 'static {
    /// The key type produced by this extractor.
    type Key: RateKey;

    /// Derive the rate key from the given input.
    fn rate_key(&self, input: &Input) -> Result<Option<Self::Key>, BoxError>;
}

impl<Input, K, F> InputToRateKey<Input> for F
where
    F: Fn(&Input) -> Result<Option<K>, BoxError> + Send + Sync + 'static,
    K: RateKey,
{
    type Key = K;

    fn rate_key(&self, input: &Input) -> Result<Option<Self::Key>, BoxError> {
        (self)(input)
    }
}

/// The usual IPv6 end-site allocation, used as the default aggregation
/// prefix so a client cannot dodge its bucket by rotating within its /64.
const DEFAULT_IPV6_PREFIX: u8 = 64;

/// An [`InputToRateKey`] extractor keying on the client IP address,
/// resolved via [`client_ip`](crate::client_ip::client_ip):
/// [`Forwarded`](crate::forwarded::Forwarded) information (populated by
/// e.g. forwarded-header or PROXY-protocol layers) wins over the
/// transport peer address ([`SocketInfo`](crate::stream::SocketInfo)).
/// Only populate `Forwarded` from a trusted proxy boundary: accepting a
/// client-supplied forwarding header lets that client choose and rotate its
/// own rate key.
///
/// The resolved address is canonicalised before keying: IPv4-mapped IPv6
/// peers (`::ffff:a.b.c.d`) collapse to their IPv4 form, and IPv6 clients
/// are aggregated to [`with_ipv6_prefix`](Self::with_ipv6_prefix) (default
/// `/64`). Without this a single client keys to `2^64` distinct buckets and
/// per-client limiting is a no-op against exactly the clients most able to
/// abuse it.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ClientIpRateKey {
    ipv6_prefix: u8,
}

impl ClientIpRateKey {
    /// Create a new [`ClientIpRateKey`], aggregating IPv6 clients to `/64`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Aggregate IPv6 client addresses to this prefix length (clamped
        /// to `1..=128`) before keying; `128` keys on the exact address.
        /// IPv4 clients are always keyed on the exact address.
        pub fn ipv6_prefix(mut self, prefix: u8) -> Self {
            self.ipv6_prefix = prefix.clamp(1, 128);
            self
        }
    }

    /// Canonicalise and aggregate a resolved client IP into its bucket key.
    fn key_for(self, ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) if self.ipv6_prefix < 128 => {
                IpNet::new(IpAddr::V6(v6), self.ipv6_prefix)
                    .map(|net| net.trunc().addr())
                    .unwrap_or(IpAddr::V6(v6))
            }
            canonical => canonical,
        }
    }
}

impl Default for ClientIpRateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl<Input> InputToRateKey<Input> for ClientIpRateKey
where
    Input: ExtensionsRef + Send + Sync + 'static,
{
    type Key = IpAddr;

    fn rate_key(&self, input: &Input) -> Result<Option<Self::Key>, BoxError> {
        Ok(crate::client_ip::client_ip(input).map(|ip| self.key_for(ip)))
    }
}
