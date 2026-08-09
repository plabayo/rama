//! Byte-rate throttling (traffic shaping) for IO streams.
//!
//! [`ThrottledIo`] wraps any [`Io`] and paces its reads and/or writes
//! against a token bucket: per-client bandwidth caps, egress shaping
//! toward fragile upstreams, QoS tiers. Read-side throttling
//! back-pressures the peer through TCP flow control; write-side
//! throttling paces egress into the kernel.
//!
//! Apply it in a transport stack with [`ThrottleLayer`] (incoming
//! connections) or [`OutgoingThrottleLayer`] (client connectors),
//! or wrap an IO by hand with [`ThrottledIo`].
//!
//! [`Io`]: rama_core::io::Io

use rama_utils::octets::kib_u64;
use rama_utils::rate::{Rate, RateLimiter};

mod io;
#[doc(inline)]
pub use io::ThrottledIo;

mod incoming;
#[doc(inline)]
pub use incoming::{ThrottleLayer, ThrottleService};

mod outgoing;
#[doc(inline)]
pub use outgoing::{OutgoingThrottleLayer, OutgoingThrottleService};

/// How one direction of a [`ThrottledIo`] is budgeted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ThrottleMode {
    /// Each connection gets its own token bucket.
    PerConn {
        /// the byte rate each connection is allowed
        rate: Rate,
        /// burst capacity in bytes (maximum spendable at once)
        burst: u64,
    },
    /// An aggregate cap: every connection holding a clone of the
    /// [`RateLimiter`] handle spends from the same budget.
    Shared(RateLimiter),
}

impl ThrottleMode {
    /// Per-connection throttling at the given byte [`Rate`],
    /// with a burst capacity of one period worth of bytes.
    #[must_use]
    pub const fn per_conn(rate: Rate) -> Self {
        Self::PerConn {
            rate,
            burst: rate.units(),
        }
    }

    /// Per-connection throttling at the given byte [`Rate`] and
    /// burst capacity.
    ///
    /// # Panics
    ///
    /// A zero `burst` panics when the throttled IO is constructed.
    #[must_use]
    pub const fn per_conn_with_burst(rate: Rate, burst: u64) -> Self {
        Self::PerConn { rate, burst }
    }

    /// Shared (aggregate) throttling: all IOs throttled with a clone of
    /// the same [`RateLimiter`] spend from one budget.
    #[must_use]
    pub const fn shared(limiter: RateLimiter) -> Self {
        Self::Shared(limiter)
    }
}

/// Default grant quantum for a rate: a tenth of a period worth of
/// bytes, at most 16 KiB. Keeps pacing smooth and prevents one big IO
/// op from monopolizing a shared limiter.
fn default_quantum(rate: Rate) -> u64 {
    (rate.units() / 10).clamp(1, kib_u64(16))
}

/// Per-direction throttle configuration shared by the
/// incoming and outgoing layers.
#[derive(Debug, Clone, Default)]
struct ThrottleConfig {
    read: Option<ThrottleMode>,
    write: Option<ThrottleMode>,
    quantum: Option<u64>,
}

impl ThrottleConfig {
    fn wrap<S>(&self, stream: S) -> ThrottledIo<S> {
        ThrottledIo::new(stream)
            .maybe_with_read_mode(self.read.clone())
            .maybe_with_write_mode(self.write.clone())
            .maybe_with_quantum(self.quantum)
    }
}
