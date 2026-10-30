use super::*;

/// Setup flags.
const NATIVE: u8 = 1;
const BUDGET: u8 = 2;
const RATES: u8 = 4;
const QUOTA: u8 = 8;

/// An input: setup flags and shape, then operations.
fn input(flags: u8, shape: u8, operations: &[[u8; 4]]) -> Vec<u8> {
    let mut input = vec![flags, shape];
    for operation in operations {
        input.extend_from_slice(operation);
    }
    input
}

/// An operation with a little-endian length.
const fn op(kind: u8, a: u8, len: u16) -> [u8; 4] {
    let [lo, hi] = len.to_le_bytes();
    [kind, a, lo, hi]
}

const PEER_DATAGRAM: u8 = 0;
const NATIVE_DATAGRAM: u8 = 1;
const OVERSIZED_CAPSULE: u8 = 2;
const SEND: u8 = 4;
const RECEIVE: u8 = 5;
const ADVANCE: u8 = 6;
const PEER_CLOSE: u8 = 7;
const DROP_RECEIVER: u8 = 9;
const DROP_SENDER: u8 = 10;
const DRAIN_PEER: u8 = 11;
const NATIVE_MODE: u8 = 12;
const RECEIVE_THEN_SEND: u8 = 13;

#[test]
fn payloads_travel_both_ways_on_the_capsule_carrier() {
    let coverage = run(&input(
        0,
        0,
        &[
            op(PEER_DATAGRAM, 0, 4),
            op(RECEIVE, 0, 0),
            op(SEND, 0, 5),
            op(DRAIN_PEER, 0, 0),
        ],
    ));
    assert_eq!(coverage.stats.forwarded, 1, "{coverage:?}");
    assert_eq!(coverage.stats.capsule, 1);
    assert_eq!(coverage.stats.returned, 1);
    assert_eq!(coverage.peer_received, 1);
}

#[test]
fn payloads_travel_both_ways_on_the_native_carrier() {
    let coverage = run(&input(
        NATIVE,
        255,
        &[op(NATIVE_DATAGRAM, 0, 4), op(RECEIVE, 0, 0), op(SEND, 0, 5)],
    ));
    assert_eq!(coverage.stats.native, 1, "{coverage:?}");
    assert_eq!(coverage.stats.forwarded, 1);
    assert_eq!(coverage.stats.returned, 1);
    assert_eq!(coverage.peer_received, 1);
}

#[test]
fn wrong_truncated_and_non_minimal_contexts() {
    let coverage = run(&input(
        0,
        0,
        &[
            op(PEER_DATAGRAM, 1, 4),
            op(PEER_DATAGRAM, 2, 4),
            op(PEER_DATAGRAM, 3, 0),
            op(RECEIVE, 0, 0),
            op(RECEIVE, 0, 0),
        ],
    ));
    let stats = coverage.stats;
    assert_eq!(stats.forwarded, 1, "the non-minimal context 0: {stats:?}");
    assert_eq!(stats.dropped_unknown_context, 2);
    assert_eq!(stats.received_bytes, 4 + 4);
}

#[test]
fn an_oversized_capsule_counts_what_it_declared() {
    let coverage = run(&input(
        0,
        0,
        &[op(OVERSIZED_CAPSULE, 1, 0), op(RECEIVE, 0, 0)],
    ));
    let stats = coverage.stats;
    assert_eq!(stats.dropped_oversize, 1, "{stats:?}");
    assert_eq!(stats.oversize_declared_bytes, OVERSIZED as u64 - 1);
    assert_eq!(stats.received_bytes, 0);
}

#[test]
fn rates_deny_both_ways() {
    let mut operations = Vec::new();
    for _ in 0..5 {
        operations.push(op(PEER_DATAGRAM, 0, 4));
        operations.push(op(RECEIVE, 0, 0));
        operations.push(op(SEND, 0, 4));
    }
    let coverage = run(&input(BUDGET | RATES, 0, &operations));
    let stats = coverage.stats;
    assert!(stats.dropped_rate_limited > 0, "{stats:?}");
    assert!(stats.returned_dropped_rate_limited > 0, "{stats:?}");
    assert!(stats.forwarded > 0 && stats.returned > 0);
}

#[test]
fn quotas_deny_both_ways() {
    let mut operations = Vec::new();
    for _ in 0..4 {
        operations.push(op(PEER_DATAGRAM, 0, 1400));
        operations.push(op(RECEIVE, 0, 0));
        operations.push(op(SEND, 0, 1400));
    }
    let coverage = run(&input(BUDGET | QUOTA, 0, &operations));
    let stats = coverage.stats;
    assert!(stats.dropped_over_quota > 0, "{stats:?}");
    assert!(stats.returned_dropped_over_quota > 0, "{stats:?}");
    assert!(stats.forwarded > 0);
}

#[test]
fn a_cancelled_pending_send_holds_nothing_and_the_sender_is_used_again() {
    // A one-payload queue behind a full native carrier: the first send waits in the pump, the
    // second fills the queue, the third would wait and is cancelled. Then the carrier makes room
    // and the same sender sends again.
    let coverage = run(&input(
        NATIVE,
        0,
        &[
            op(NATIVE_MODE, 0, 1),
            op(SEND, 0, 4),
            op(SEND, 0, 4),
            op(SEND, 0, 4),
            op(NATIVE_MODE, 0, 0),
            op(SEND, 0, 4),
        ],
    ));
    assert_eq!(coverage.abandoned, 1, "{coverage:?}");
    assert_eq!(coverage.accepted, 3);
    assert_eq!(coverage.stats.returned, 3);
    assert_eq!(coverage.peer_received, 3);
}

#[test]
fn a_close_counts_the_pending_and_the_queued_payloads_unsent() {
    let coverage = run(&input(
        NATIVE,
        255,
        &[
            op(NATIVE_MODE, 0, 1),
            op(SEND, 0, 4),
            op(SEND, 0, 5),
            op(SEND, 0, 6),
            op(ADVANCE, 0, 1),
        ],
    ));
    assert_eq!(coverage.closed, Some(ConnectUdpClose::Idle), "{coverage:?}");
    assert_eq!(coverage.stats.returned_dropped_unsent, 3);
    assert_eq!(coverage.stats.returned_dropped_bytes, 4 + 5 + 6);
}

#[test]
fn a_refused_native_payload_is_too_large() {
    let coverage = run(&input(
        NATIVE,
        255,
        &[op(NATIVE_MODE, 255, 2), op(SEND, 0, 4)],
    ));
    assert_eq!(coverage.stats.returned_dropped_too_large, 1, "{coverage:?}");
    assert_eq!(coverage.peer_received, 0);
}

#[test]
fn every_handle_and_the_peer_may_go_first() {
    for operations in [
        &[op(SEND, 0, 4), op(DROP_RECEIVER, 0, 0), op(SEND, 0, 4)][..],
        &[
            op(SEND, 0, 4),
            op(DROP_SENDER, 0, 0),
            op(PEER_DATAGRAM, 0, 4),
        ],
        &[op(SEND, 0, 4), op(PEER_CLOSE, 0, 0), op(RECEIVE, 0, 0)],
        &[op(8, 0, 0), op(SEND, 0, 4), op(RECEIVE, 0, 0)],
    ] {
        for flags in [0, NATIVE] {
            let coverage = run(&input(flags, 0, operations));
            assert!(coverage.accepted >= 1, "{operations:?}: {coverage:?}");
        }
    }
}

#[test]
fn a_closed_peer_closes_the_tunnel_and_refuses_later_sends() {
    let coverage = run(&input(
        0,
        0,
        &[
            op(PEER_CLOSE, 0, 0),
            op(RECEIVE, 0, 0),
            op(ADVANCE, 0, 1),
            op(SEND, 0, 4),
        ],
    ));
    assert!(coverage.closed.is_some(), "{coverage:?}");
}

#[test]
fn a_send_right_after_the_closing_receive_is_refused() {
    // The peer finishes its direction; the receive that sees it closes the tunnel, and the send
    // that follows before the pump runs must not be accepted.
    let coverage = run(&input(
        0,
        0,
        &[op(PEER_CLOSE, 0, 0), op(RECEIVE_THEN_SEND, 0, 4)],
    ));
    assert_eq!(
        coverage.closed,
        Some(ConnectUdpClose::Closed),
        "{coverage:?}"
    );
    assert_eq!(coverage.accepted, 0);
}

#[test]
fn mixed_sequences_remain_bounded() {
    let mut state = 0x5eed_u64;
    for _ in 0..256 {
        let mut input = [0u8; 2 + 4 * MAX_OPS];
        for byte in &mut input {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 32) as u8;
        }
        tunnel_state(&input);
    }
}
