//! The datagram demultiplexer's budgets, lifetimes and end-of-receive rules, driven directly.

use crate::h3::datagram::{
    AbortRequest, DatagramConfig, DatagramLimits, Demux, ReceiveEnd, Semantics,
    invalid_prefix_error, pending_lifetime,
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
    // Queued: a sum that fits where a product would not, then one over the budget, for
    // which the oldest makes room.
    register(&mut demux, &config, 8, now);
    deliver(&mut demux, &config, 8, 2, now);
    deliver(&mut demux, &config, 8, 5, now);
    deliver(&mut demux, &config, 8, 2, now);
    assert!(matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 5));
    assert!(matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 2));
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    // The request's own count, reported through its native channel.
    assert_eq!(demux.slot_dropped(8), 1);
}

#[test]
fn held_datagrams_crowding_the_budget_drop_the_payload_not_the_queues() {
    let config = config(4, 4, 10);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 4, now);
    // Held for a stream not open yet, it leaves no room that evicting queues could make.
    deliver(&mut demux, &config, 8, 6, now);
    deliver(&mut demux, &config, 0, 5, now);
    assert!(matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.len() == 4));
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    assert_eq!(demux.slot_dropped(0), 1);
}

#[test]
fn a_payload_that_can_never_fit_leaves_a_full_queue_alone() {
    let config = config(4, 4, 64);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 8, now);
    for _ in 0..4 {
        deliver(&mut demux, &config, 8, 8, now);
    }
    deliver(&mut demux, &config, 8, 65, now);
    for _ in 0..4 {
        assert!(
            matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 8)
        );
    }
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    assert_eq!(demux.drops().queue_full, 0);
    assert_eq!(demux.slot_dropped(8), 1);
}

#[test]
fn making_room_keeps_empty_datagrams() {
    let config = config(4, 4, 4);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 0, now);
    deliver(&mut demux, &config, 0, 3, now);
    deliver(&mut demux, &config, 0, 3, now);
    assert!(matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.is_empty()));
    assert!(matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.len() == 3));
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
}

#[test]
fn a_request_without_queue_room_counts_its_drops() {
    let config = config(0, 4, 64);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 3, now);
    deliver(&mut demux, &config, 0, 3, now);
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().queue_full, 2);
    assert_eq!(demux.slot_dropped(0), 2);
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

#[test]
fn bursts_and_churn_leave_bounded_storage() {
    // Budget for the whole burst, so every queue and the pending area fill.
    let config = config(32, 16, 4 * 1024 * 1024);
    let now = Instant::now();
    let mut demux = Demux::default();
    // Fill 64 request queues and the pending area for streams not yet opened.
    for stream in (0..64).map(|index| index * 4) {
        register(&mut demux, &config, stream, now);
        for _ in 0..32 {
            deliver(&mut demux, &config, stream, 1024, now);
        }
    }
    for stream in (64..80).map(|index| index * 4) {
        deliver(&mut demux, &config, stream, 1024, now);
    }
    let burst = demux.capacities();
    for stream in (0..80).map(|index| index * 4) {
        if stream >= 256 {
            register(&mut demux, &config, stream, now);
        }
        while let Poll::Ready(Ok(Some(_))) = poll(&mut demux, stream) {}
        _ = demux.unregister(stream);
    }
    let drained = demux.capacities();
    // One request at a time, many times over.
    for stream in (80..10_080).map(|index| index * 4) {
        register(&mut demux, &config, stream, now);
        deliver(&mut demux, &config, stream, 1024, now);
        assert!(matches!(poll(&mut demux, stream), Poll::Ready(Ok(Some(_)))));
        _ = demux.unregister(stream);
    }
    let churned = demux.capacities();
    eprintln!(
        "(slots, pending, queues) capacity: burst {burst:?}, drained {drained:?}, after 10000 churns {churned:?}"
    );
    assert_eq!(demux.buffered(), 0);
    // Released requests free their queues; the map and pending queue never grow past the
    // burst's peak, whatever the churn.
    assert!(burst.1 >= 16 && burst.2 >= 64 * 32, "{burst:?}");
    assert_eq!(drained.2, 0);
    assert!(
        churned.0 <= burst.0 && churned.1 <= burst.1,
        "{churned:?} {burst:?}"
    );
    assert_eq!(churned.2, 0);
}

/// Stalled queues make room for a healthy one instead of starving it of the budget.
#[test]
fn stalled_queues_make_room_for_a_healthy_one() {
    let config = config(4, 4, 64);
    let now = Instant::now();
    let mut demux = Demux::default();
    for stream in [0, 4, 8] {
        register(&mut demux, &config, stream, now);
    }
    // Two consumers that never read fill the budget exactly.
    for stream in [0, 4] {
        for _ in 0..4 {
            deliver(&mut demux, &config, stream, 8, now);
        }
    }
    assert_eq!(demux.buffered(), 64);
    for _ in 0..100 {
        deliver(&mut demux, &config, 8, 8, now);
        assert!(
            matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 8)
        );
    }
    assert_eq!(demux.slot_dropped(8), 0);
    assert_eq!(demux.slot_dropped(0) + demux.slot_dropped(4), 1);
    assert_eq!(demux.drops().over_budget, 1);
    // A payload that can never fit is dropped without evicting anyone.
    deliver(&mut demux, &config, 8, 65, now);
    assert_eq!(demux.slot_dropped(8), 1);
    assert_eq!(demux.slot_dropped(0) + demux.slot_dropped(4), 1);
    assert!(demux.buffered() <= 64);
}

/// A held datagram is adopted only within its own lifetime, whatever the queue order.
#[test]
fn held_datagrams_expire_by_their_own_lifetime() {
    let config = config(4, 4, 64);
    let start = Instant::now();
    let mut demux = Demux::<Aborts>::default();
    demux
        .deliver(
            &config,
            4,
            Bytes::from_static(b"long"),
            start,
            Duration::from_millis(600),
        )
        .run();
    // Arrives later with a shorter lifetime, after the RTT fell.
    demux
        .deliver(
            &config,
            8,
            Bytes::from_static(b"short"),
            start + Duration::from_millis(10),
            Duration::from_millis(100),
        )
        .run();
    register(&mut demux, &config, 8, start + Duration::from_millis(200));
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().expired, 1);
    assert_eq!(demux.pending_len(), 1);
    register(&mut demux, &config, 4, start + Duration::from_millis(300));
    assert!(
        matches!(poll(&mut demux, 4), Poll::Ready(Ok(Some(payload))) if payload == b"long"[..])
    );
    assert_eq!(demux.buffered(), 0);
}

/// An invalid datagram prefix is the peer's failure, like every received-input violation.
#[test]
fn invalid_prefixes_are_remote_failures() {
    for beyond_limit in [false, true] {
        assert!(
            invalid_prefix_error(beyond_limit).is_remote_failure(),
            "{beyond_limit}"
        );
    }
}
