use rama_utils::rate::RateLimiter;

use super::{ThrottleBudget, ThrottleConfig, ThrottleMode};
use crate::gate::{GateDirection, GatedStream, StreamGates};

/// The [`StreamGates`] of one throttled multiplexed connection, such as a QUIC one.
///
/// All its streams spend from one budget per direction, as the reads or writes of a
/// [`ThrottledIo`](super::ThrottledIo) do: [`ThrottleMode::PerConn`] caps this connection,
/// [`ThrottleMode::Shared`] every connection spending from the same limiter.
#[derive(Debug)]
pub struct ThrottleGates {
    read: Option<RateLimiter>,
    write: Option<RateLimiter>,
    quantum: Option<u64>,
}

impl ThrottleGates {
    /// The gates of one connection, throttled as `config` sets out.
    #[must_use]
    pub fn new(config: &ThrottleConfig) -> Self {
        Self {
            read: config.read().map(ThrottleMode::connection_limiter),
            write: config.write().map(ThrottleMode::connection_limiter),
            quantum: config.quantum(),
        }
    }
}

impl StreamGates for ThrottleGates {
    type Gate = ThrottleBudget;

    fn open(&self, stream: GatedStream) -> Option<ThrottleBudget> {
        let limiter = match stream.direction() {
            GateDirection::Read => self.read.as_ref(),
            GateDirection::Write => self.write.as_ref(),
        }?;
        Some(
            ThrottleBudget::new(ThrottleMode::shared(limiter.clone()))
                .maybe_with_quantum(self.quantum),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use rama_utils::rate::Rate;

    use super::*;
    use crate::gate::{Initiator, StreamGate as _};

    fn stream(id: u64, direction: GateDirection) -> GatedStream {
        GatedStream::new(id, direction, true, Initiator::Peer)
    }

    #[tokio::test(start_paused = true)]
    async fn only_throttled_directions_are_gated() {
        let mode = ThrottleMode::per_conn(Rate::per_sec(1000));
        let gates = ThrottleGates::new(&ThrottleConfig::new(Some(mode), None));
        assert!(gates.open(stream(0, GateDirection::Read)).is_some());
        assert!(gates.open(stream(0, GateDirection::Write)).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_streams_of_a_connection_share_its_budget() {
        let mode = ThrottleMode::per_conn_with_burst(Rate::per_sec(100), 100);
        let gates = ThrottleGates::new(&ThrottleConfig::new(None, Some(mode)).with_quantum(100));
        let mut first = gates.open(stream(0, GateDirection::Write)).unwrap();
        let mut second = gates.open(stream(4, GateDirection::Write)).unwrap();
        let mut cx = Context::from_waker(Waker::noop());

        assert_eq!(first.poll_admit(&mut cx, 100), Poll::Ready(100));
        first.settle(100);
        assert!(second.poll_admit(&mut cx, 1).is_pending());
    }

    #[tokio::test(start_paused = true)]
    async fn each_connection_has_its_own_budget() {
        let mode = ThrottleMode::per_conn_with_burst(Rate::per_sec(100), 100);
        let config = ThrottleConfig::new(None, Some(mode)).with_quantum(100);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..2 {
            let mut gate = ThrottleGates::new(&config)
                .open(stream(0, GateDirection::Write))
                .unwrap();
            assert_eq!(gate.poll_admit(&mut cx, 100), Poll::Ready(100));
            gate.settle(100);
        }
    }
}
