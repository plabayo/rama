//! Keyed (per-client) rate limiting.
//!
//! [`KeyedRatePolicy`] is the per-key sibling of
//! [`RatePolicy`](rama_core::layer::limit::policy::RatePolicy): instead of
//! one shared token bucket, every key — typically the client IP, see
//! [`ClientIpRateKey`] — gets its own lazily-created bucket, stored in a
//! bounded, idle-evicting cache.

mod key;
#[doc(inline)]
pub use key::{ClientIpRateKey, InputToRateKey, RateKey};

mod keyed;
#[doc(inline)]
pub use keyed::{KeyedRatePolicy, MissingRateKey, RateKeyCapacityReached};
