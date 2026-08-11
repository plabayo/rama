//! Rate primitives: express "N units per period" and enforce it.
//!
//! The core of this module is sans-IO and `no_std`: [`TokenBucket`] never
//! reads a clock, the caller provides time as monotonic nanoseconds. This
//! keeps it trivially testable and embeddable in other sans-IO state
//! machines (e.g. a send scheduler pacing datagrams).
//!
//! On top (behind the `std` feature) [`RateLimiter`] wraps a [`TokenBucket`]
//! in a cheap-to-clone shared handle that can wait (pace) or reject
//! (rate limit) using tokio timers.
//!
//! Units are whatever you want them to be: requests, connections,
//! messages, bytes.

mod bucket;
#[doc(inline)]
pub use bucket::TokenBucket;

#[cfg(feature = "std")]
mod limiter;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use limiter::{RateLimiter, RefundWait};

use core::time::Duration;

/// A rate: `units` per `per` period.
///
/// Units are dimensionless: use it for requests, connections, messages
/// or bytes alike. For byte rates [`Rate::per_sec`] *is* bytes/sec;
/// compose with [`crate::octets`] helpers for larger units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rate {
    units: u64,
    per: Duration,
}

impl Rate {
    /// Create a new [`Rate`] of `units` per `per` period.
    ///
    /// # Panics
    ///
    /// Panics if `units` is zero, `per` is zero, or `per` exceeds
    /// `u64::MAX` nanoseconds (~584 years). In const contexts this is
    /// a compile-time error. Use [`Rate::try_new`] for fallible
    /// construction from dynamic input.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use rama_utils::rate::Rate;
    ///
    /// const RATE: Rate = Rate::new(100, Duration::from_millis(250));
    /// assert_eq!(RATE.units(), 100);
    /// assert_eq!(RATE.per(), Duration::from_millis(250));
    /// ```
    #[must_use]
    pub const fn new(units: u64, per: Duration) -> Self {
        assert!(units != 0, "Rate: units must be non-zero");
        assert!(
            per.as_nanos() != 0 && per.as_nanos() <= u64::MAX as u128,
            "Rate: per must be non-zero and at most u64::MAX nanos"
        );
        Self { units, per }
    }

    /// Create a new [`Rate`] of `units` per `per` period,
    /// or `None` for the invalid inputs that make [`Rate::new`] panic.
    #[must_use]
    pub const fn try_new(units: u64, per: Duration) -> Option<Self> {
        if units == 0 || per.as_nanos() == 0 || per.as_nanos() > u64::MAX as u128 {
            return None;
        }
        Some(Self { units, per })
    }

    /// Create a new [`Rate`] of `units` per second.
    ///
    /// For byte rates this *is* bytes per second; combine with
    /// [`crate::octets::kib_u64`], [`crate::octets::mib_u64`] and
    /// [`crate::octets::gib_u64`] for KiB/MiB/GiB rates, and with
    /// [`crate::octets::from_bits_u64`] for link rates expressed in bits.
    ///
    /// # Panics
    ///
    /// Panics if `units` is zero (compile-time error in const contexts).
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::{octets, rate::Rate};
    ///
    /// // 100 requests per second
    /// const REQ_RATE: Rate = Rate::per_sec(100);
    /// # let _ = REQ_RATE;
    /// // 10 MiB per second
    /// const BYTE_RATE: Rate = Rate::per_sec(octets::mib_u64(10));
    /// # let _ = BYTE_RATE;
    /// // a 100 Mbit/s link rate
    /// const LINK_RATE: Rate = Rate::per_sec(octets::from_bits_u64(100_000_000));
    /// # let _ = LINK_RATE;
    /// ```
    #[must_use]
    pub const fn per_sec(units: u64) -> Self {
        Self::new(units, Duration::from_secs(1))
    }

    /// The number of units per [`Rate::per`] period.
    #[must_use]
    pub const fn units(&self) -> u64 {
        self.units
    }

    /// The period over which [`Rate::units`] units are allowed.
    #[must_use]
    pub const fn per(&self) -> Duration {
        self.per
    }

    pub(crate) const fn per_nanos(&self) -> u64 {
        // validated by the constructors to fit
        self.per.as_nanos() as u64
    }
}

/// The result of [`TokenBucket::try_acquire`] (and
/// [`RateLimiter::try_acquire`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquire {
    /// The requested units were spent; the caller may proceed.
    Granted,
    /// Not enough budget: the earliest monotonic instant (in the caller's
    /// clock, nanoseconds) at which the requested units can be granted.
    RetryAt(u64),
    /// The request exceeds the burst capacity and can never be granted
    /// as a single acquisition. Split it up (e.g. in burst-sized chunks,
    /// as [`RateLimiter::acquire`] does) or reject it.
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_valid() {
        let rate = Rate::per_sec(10);
        assert_eq!(rate.units(), 10);
        assert_eq!(rate.per(), Duration::from_secs(1));
        assert_eq!(rate.per_nanos(), 1_000_000_000);
    }

    #[test]
    fn rate_try_new_invalid() {
        assert!(Rate::try_new(0, Duration::from_secs(1)).is_none());
        assert!(Rate::try_new(1, Duration::ZERO).is_none());
        assert!(Rate::try_new(1, Duration::MAX).is_none());
        assert!(Rate::try_new(1, Duration::from_nanos(1)).is_some());
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn rate_new_zero_units_panics() {
        assert_eq!(Rate::new(0, Duration::from_secs(1)).units(), 0);
    }
}
