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
//! or wrap an IO by hand with [`ThrottledIo`]. Both layers also take
//! multiplexed connections, such as QUIC ones, whose streams spend from
//! one budget per connection through [`ThrottleGates`] (see [`Throttleable`]).
//!
//! [`Io`]: rama_core::io::Io

use rama_core::io::Io;
use rama_utils::{
    octets::kib_u64,
    rate::{Rate, RateLimiter},
};

mod budget;
#[doc(inline)]
pub use budget::ThrottleBudget;

mod gates;
#[doc(inline)]
pub use gates::ThrottleGates;

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

    /// The limiter one connection spends from across all the streams it carries:
    /// a fresh one for [`ThrottleMode::PerConn`], the shared one otherwise.
    fn connection_limiter(&self) -> RateLimiter {
        match self {
            Self::PerConn { rate, burst } => RateLimiter::new(*rate, *burst),
            Self::Shared(limiter) => limiter.clone(),
        }
    }
}

/// Default grant quantum for a rate: a tenth of a period worth of
/// bytes, at most 16 KiB. Keeps pacing smooth and prevents one big IO
/// op from monopolizing a shared limiter.
fn default_quantum(rate: Rate) -> u64 {
    (rate.units() / 10).clamp(1, kib_u64(16))
}

/// How [`ThrottleLayer`] and [`OutgoingThrottleLayer`] throttle a
/// connection: a [`ThrottleMode`] per direction and the grant quantum.
#[derive(Debug, Clone, Default)]
pub struct ThrottleConfig {
    read: Option<ThrottleMode>,
    write: Option<ThrottleMode>,
    quantum: Option<u64>,
}

impl ThrottleConfig {
    /// Create a [`ThrottleConfig`] with per-direction modes.
    #[must_use]
    pub fn new(read: Option<ThrottleMode>, write: Option<ThrottleMode>) -> Self {
        Self {
            read,
            write,
            quantum: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the grant quantum in bytes: the budget reserved per
        /// IO operation (clamped to the burst capacity; defaults to a
        /// tenth of a period worth of bytes, at most 16 KiB).
        pub fn quantum(mut self, quantum: Option<u64>) -> Self {
            self.quantum = quantum;
            self
        }
    }

    /// How the read (ingress) direction is throttled, if at all.
    #[must_use]
    pub fn read(&self) -> Option<&ThrottleMode> {
        self.read.as_ref()
    }

    /// How the write (egress) direction is throttled, if at all.
    #[must_use]
    pub fn write(&self) -> Option<&ThrottleMode> {
        self.write.as_ref()
    }

    /// The grant quantum override, if any.
    #[must_use]
    pub fn quantum(&self) -> Option<u64> {
        self.quantum
    }
}

/// An input that [`ThrottleLayer`] and [`OutgoingThrottleLayer`] throttle.
///
/// Byte streams are wrapped in a [`ThrottledIo`]. Multiplexed transports,
/// such as QUIC connections, gate the streams they carry with [`ThrottleGates`].
pub trait Throttleable: Sized {
    /// The throttled input.
    type Throttled;

    /// Throttle `self` as configured.
    fn throttle(self, config: &ThrottleConfig) -> Self::Throttled;
}

impl<IO: Io> Throttleable for IO {
    type Throttled = ThrottledIo<IO>;

    fn throttle(self, config: &ThrottleConfig) -> Self::Throttled {
        ThrottledIo::new(self)
            .maybe_with_read_mode(config.read.clone())
            .maybe_with_write_mode(config.write.clone())
            .maybe_with_quantum(config.quantum)
    }
}
