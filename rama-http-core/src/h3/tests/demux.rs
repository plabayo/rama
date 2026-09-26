//! The datagram demultiplexer's budgets, lifetimes and end-of-receive rules, driven directly.

use crate::h3::datagram::{
    AbortRequest, DatagramConfig, DatagramLimits, Demux, ReceiveEnd, Semantics, pending_lifetime,
};
use rama_core::bytes::Bytes;
use rama_http::datagram::{NativeRecvError, ViolationPolicy};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::Instant;

/// Counts aborted requests.
#[derive(Clone, Default)]
struct Aborts(Arc<AtomicUsize>);

impl AbortRequest for Aborts {
    fn abort_request(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn config(queue_len: usize, pending_len: usize, max_buffered_bytes: usize) -> DatagramConfig {
    DatagramConfig {
        limits: DatagramLimits {
            queue_len,
            pending_len,
            max_buffered_bytes,
        },
        violations: ViolationPolicy::Reject,
    }
}

const LIFETIME: Duration = Duration::from_millis(100);

fn register(
    demux: &mut Demux<Aborts>,
    config: &DatagramConfig,
    stream: u64,
    now: Instant,
) -> Aborts {
    let aborts = Aborts::default();
    demux
        .register(
            config,
            stream,
            Semantics::Claimed,
            aborts.clone(),
            Arc::new(AtomicBool::new(false)),
            now,
        )
        .run();
    aborts
}

fn poll(demux: &mut Demux<Aborts>, stream: u64) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
    demux.poll_recv(stream, &Context::from_waker(Waker::noop()))
}

fn deliver(
    demux: &mut Demux<Aborts>,
    config: &DatagramConfig,
    stream: u64,
    len: usize,
    now: Instant,
) {
    demux
        .deliver(config, stream, Bytes::from(vec![0; len]), now, LIFETIME)
        .run();
}

#[test]
fn payloads_that_exactly_fit_the_budget_are_kept() {
    let config = config(4, 4, 8);
    let now = Instant::now();
    let mut demux = Demux::default();
    // Held for a future stream, filling the budget exactly, then adopted.
    deliver(&mut demux, &config, 4, 8, now);
    register(&mut demux, &config, 4, now);
    assert!(matches!(poll(&mut demux, 4), Poll::Ready(Ok(Some(payload))) if payload.len() == 8));
    // Queued: a sum that fits where a product would not, then one over the budget.
    register(&mut demux, &config, 8, now);
    deliver(&mut demux, &config, 8, 2, now);
    deliver(&mut demux, &config, 8, 5, now);
    deliver(&mut demux, &config, 8, 2, now);
    assert!(matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 2));
    assert!(matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 5));
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
}

#[test]
fn held_datagrams_expire_after_their_lifetime() {
    let config = config(4, 4, 64);
    let now = Instant::now();
    let mut demux = Demux::default();
    deliver(&mut demux, &config, 4, 3, now);
    register(&mut demux, &config, 4, now + LIFETIME * 2);
    assert!(poll(&mut demux, 4).is_pending());
    assert_eq!(demux.drops().expired, 1);
}

#[test]
fn pending_datagrams_wait_a_few_round_trips_with_a_floor() {
    assert_eq!(
        pending_lifetime(Duration::from_millis(200)),
        Duration::from_millis(600)
    );
    assert_eq!(
        pending_lifetime(Duration::from_millis(1)),
        Duration::from_millis(100)
    );
}

#[test]
fn an_adopted_violation_aborts_its_request() {
    let config = config(4, 4, 64);
    let now = Instant::now();
    let mut demux: Demux<Aborts> = Demux::default();
    deliver(&mut demux, &config, 4, 3, now);
    deliver(&mut demux, &config, 4, 3, now);
    let aborts = Aborts::default();
    demux
        .register(
            &config,
            4,
            Semantics::None,
            aborts.clone(),
            Arc::new(AtomicBool::new(false)),
            now,
        )
        .run();
    // Both held datagrams are violations; the request is aborted once.
    assert_eq!(aborts.0.load(Ordering::Acquire), 1);
    assert_eq!(demux.drops().no_semantics, 2);
}

#[test]
fn the_first_remote_end_stays_and_local_ends_override_it() {
    let config = config(4, 4, 64);
    let now = Instant::now();
    let cases = [
        // A reset after the peer's FIN keeps the clean end.
        ([ReceiveEnd::Finished, ReceiveEnd::Reset(9)], Ok(None)),
        // A released consumer ends a reset stream cleanly for itself.
        ([ReceiveEnd::Reset(9), ReceiveEnd::Released], Ok(None)),
        // A local abort is final.
        (
            [ReceiveEnd::Aborted(5), ReceiveEnd::Released],
            Err(NativeRecvError::Aborted(5)),
        ),
        (
            [ReceiveEnd::Reset(9), ReceiveEnd::Finished],
            Err(NativeRecvError::Reset(9)),
        ),
    ];
    for (ends, expected) in cases {
        let mut demux = Demux::default();
        register(&mut demux, &config, 0, now);
        for end in ends {
            _ = demux.receive_ended(0, end);
        }
        assert_eq!(poll(&mut demux, 0), Poll::Ready(expected), "{ends:?}");
    }
}
