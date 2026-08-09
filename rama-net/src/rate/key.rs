use core::fmt::Debug;
use core::hash::Hash;
use std::net::IpAddr;

use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;

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

/// An [`InputToRateKey`] extractor keying on the client IP address,
/// resolved via [`client_ip`](crate::client_ip::client_ip):
/// [`Forwarded`](crate::forwarded::Forwarded) information (populated by
/// e.g. forwarded-header or PROXY-protocol layers) wins over the
/// transport peer address ([`SocketInfo`](crate::stream::SocketInfo)).
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ClientIpRateKey;

impl ClientIpRateKey {
    /// Create a new [`ClientIpRateKey`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<Input> InputToRateKey<Input> for ClientIpRateKey
where
    Input: ExtensionsRef + Send + Sync + 'static,
{
    type Key = IpAddr;

    fn rate_key(&self, input: &Input) -> Result<Option<Self::Key>, BoxError> {
        Ok(crate::client_ip::client_ip(input))
    }
}
