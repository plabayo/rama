//! The datagram demultiplexer's budgets, lifetimes and end-of-receive rules, driven directly.

use crate::h3::datagram::{
    AbortRequest, DatagramConfig, DatagramLimits, Demux, MIN_DATAGRAM_CHARGE as C, ReceiveEnd,
    Semantics, invalid_prefix_error, pending_lifetime,
};
use rama_core::bytes::Bytes;
use rama_http::datagram::{NativeRecvError, ViolationPolicy};
use std::assert_matches;
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
    let config = config(4, 4, 8 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    // Held for a future stream, filling the budget exactly, then adopted.
    deliver(&mut demux, &config, 4, 8 * C, now);
    register(&mut demux, &config, 4, now);
    assert!(
        matches!(poll(&mut demux, 4), Poll::Ready(Ok(Some(payload))) if payload.len() == 8 * C)
    );
    // Queued: a sum that fits where a product would not, then one over the budget, for
    // which the oldest makes room.
    register(&mut demux, &config, 8, now);
    deliver(&mut demux, &config, 8, 2 * C, now);
    deliver(&mut demux, &config, 8, 5 * C, now);
    deliver(&mut demux, &config, 8, 2 * C, now);
    assert!(
        matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 5 * C)
    );
    assert!(
        matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 2 * C)
    );
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    // The request's own count, reported through its native channel.
    assert_eq!(demux.slot_dropped(8), 1);
}

/// Held datagrams and a payload that together fill the budget exactly: queued datagrams make
/// the room, the payload stays.
#[test]
fn held_datagrams_and_a_payload_that_exactly_fill_the_budget_keep_it() {
    let config = config(4, 4, 10 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 2 * C, now);
    deliver(&mut demux, &config, 8, 6 * C, now);
    deliver(&mut demux, &config, 0, 4 * C, now);
    assert_eq!(demux.slot_dropped(0), 1);
    assert!(
        matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.len() == 4 * C)
    );
    demux.assert_consistent(&config.limits);
}

/// A full hold gives way for a datagram that fits once the oldest held one has left.
#[test]
fn a_held_datagram_that_fits_in_the_oldest_place_replaces_it() {
    let config = config(4, 1, 3 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    deliver(&mut demux, &config, 4, 2 * C, now);
    deliver(&mut demux, &config, 8, 2 * C, now);
    assert_eq!(demux.drops().over_budget, 0);
    assert_eq!(demux.drops().expired, 1);
    assert_eq!((demux.pending_len(), demux.buffered()), (1, 2 * C));
    register(&mut demux, &config, 8, now);
    assert!(
        matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 2 * C)
    );
    demux.assert_consistent(&config.limits);
}

/// Adoption agrees with expiry: at exactly its lifetime a held datagram has expired.
#[test]
fn a_held_datagram_at_exactly_its_lifetime_has_expired() {
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    deliver(&mut demux, &config, 4, C, now);
    register(&mut demux, &config, 4, now + LIFETIME);
    assert!(poll(&mut demux, 4).is_pending());
    assert_eq!(demux.drops().expired, 1);
    demux.assert_consistent(&config.limits);
}

#[test]
fn held_datagrams_crowding_the_budget_drop_the_payload_not_the_queues() {
    let config = config(4, 4, 10 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 4 * C, now);
    // Held for a stream not open yet, it leaves no room that evicting queues could make.
    deliver(&mut demux, &config, 8, 6 * C, now);
    deliver(&mut demux, &config, 0, 5 * C, now);
    assert!(
        matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.len() == 4 * C)
    );
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    assert_eq!(demux.slot_dropped(0), 1);
}

#[test]
fn a_payload_that_can_never_fit_leaves_a_full_queue_alone() {
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 8, now);
    for _ in 0..4 {
        deliver(&mut demux, &config, 8, 8 * C, now);
    }
    deliver(&mut demux, &config, 8, 65 * C, now);
    for _ in 0..4 {
        assert!(
            matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 8 * C)
        );
    }
    assert!(poll(&mut demux, 8).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
    assert_eq!(demux.drops().queue_full, 0);
    assert_eq!(demux.slot_dropped(8), 1);
}

/// A datagram keeps its whole packet alive, so even an empty one costs a packet's charge.
#[test]
fn small_datagrams_are_charged_a_packet() {
    let config = config(32, 4, 3 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    for len in [0, 1, 0, 1] {
        deliver(&mut demux, &config, 0, len, now);
    }
    assert_eq!(demux.buffered(), 3 * C);
    for len in [1, 0, 1] {
        assert!(
            matches!(poll(&mut demux, 0), Poll::Ready(Ok(Some(payload))) if payload.len() == len)
        );
    }
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().over_budget, 1);
}

/// A held datagram that would not fit even in its predecessor's place costs nobody else theirs.
#[test]
fn a_held_datagram_that_cannot_fit_keeps_the_oldest() {
    let config = config(4, 2, 3 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    deliver(&mut demux, &config, 4, C, now);
    deliver(&mut demux, &config, 4, C, now);
    deliver(&mut demux, &config, 8, 3 * C, now);
    assert_eq!(demux.drops().over_budget, 1);
    assert_eq!(demux.drops().expired, 0);
    register(&mut demux, &config, 4, now);
    for _ in 0..2 {
        assert!(
            matches!(poll(&mut demux, 4), Poll::Ready(Ok(Some(payload))) if payload.len() == C)
        );
    }
}

#[test]
fn a_request_without_queue_room_counts_its_drops() {
    let config = config(0, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 0, 3 * C, now);
    deliver(&mut demux, &config, 0, 3 * C, now);
    assert!(poll(&mut demux, 0).is_pending());
    assert_eq!(demux.drops().queue_full, 2);
    assert_eq!(demux.slot_dropped(0), 2);
}

#[test]
fn held_datagrams_expire_after_their_lifetime() {
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    deliver(&mut demux, &config, 4, 3 * C, now);
    register(&mut demux, &config, 4, now + LIFETIME * 2);
    assert!(poll(&mut demux, 4).is_pending());
    assert_eq!(demux.drops().expired, 1);
}

/// Expired held datagrams leave on any later delivery, freeing their budget, also when their
/// stream never registers.
#[test]
fn expired_held_datagrams_free_their_budget() {
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    register(&mut demux, &config, 0, now);
    deliver(&mut demux, &config, 4, 3 * C, now);
    assert_eq!((demux.pending_len(), demux.buffered()), (1, 3 * C));
    deliver(&mut demux, &config, 0, C, now + LIFETIME * 2);
    assert_eq!(demux.drops().expired, 1);
    assert_eq!((demux.pending_len(), demux.buffered()), (0, C));
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
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux: Demux<Aborts> = Demux::default();
    deliver(&mut demux, &config, 4, 3 * C, now);
    deliver(&mut demux, &config, 4, 3 * C, now);
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
    let config = config(4, 4, 64 * C);
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
        assert_matches!(poll(&mut demux, stream), Poll::Ready(Ok(Some(_))));
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
    let config = config(4, 4, 64 * C);
    let now = Instant::now();
    let mut demux = Demux::default();
    for stream in [0, 4, 8] {
        register(&mut demux, &config, stream, now);
    }
    // Two consumers that never read fill the budget exactly.
    for stream in [0, 4] {
        for _ in 0..4 {
            deliver(&mut demux, &config, stream, 8 * C, now);
        }
    }
    assert_eq!(demux.buffered(), 64 * C);
    demux.assert_consistent(&config.limits);
    for _ in 0..100 {
        deliver(&mut demux, &config, 8, 8 * C, now);
        assert!(
            matches!(poll(&mut demux, 8), Poll::Ready(Ok(Some(payload))) if payload.len() == 8 * C)
        );
    }
    assert_eq!(demux.slot_dropped(8), 0);
    assert_eq!(demux.slot_dropped(0) + demux.slot_dropped(4), 1);
    assert_eq!(demux.drops().over_budget, 1);
    // The evicted queue's own accounting follows its datagram out.
    demux.assert_consistent(&config.limits);
    // A payload that can never fit is dropped without evicting anyone.
    deliver(&mut demux, &config, 8, 65 * C, now);
    assert_eq!(demux.slot_dropped(8), 1);
    assert_eq!(demux.slot_dropped(0) + demux.slot_dropped(4), 1);
    assert!(demux.buffered() <= 64 * C);
}

/// A held datagram is adopted only within its own lifetime, whatever the queue order.
#[test]
fn held_datagrams_expire_by_their_own_lifetime() {
    let config = config(4, 4, 64 * C);
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
