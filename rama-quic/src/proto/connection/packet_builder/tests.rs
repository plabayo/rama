use crate::proto::{
    MIN_INITIAL_SIZE,
    connection::{packet_builder::PacketBuilder, transmit::SentFrames},
    packet::SpaceId,
    tests::util::Pair,
};

/// A datagram's size is its own, not the buffer's.
///
/// Datagrams after the first in a GSO batch start at a nonzero offset, so a buffer that has
/// already passed 1200 bytes says nothing about the datagram being finished. A challenge in
/// that datagram is only proof of the path's minimum MTU if *it* reached 1200
/// (RFC 9000 §8.2.1).
///
/// The amplification limit makes this unreachable in an ordinary pass — a limit small enough
/// to keep a challenge undersized clamps the whole pass to the same allowance — so the
/// builder is driven directly here.
#[test]
fn a_challenge_is_sized_by_its_own_datagram_not_the_buffer_before_it() {
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    let token = 0x0102_0304_0506_0708;
    conn.set_challenge(token);

    // A buffer already past 1200 bytes, and a short datagram beginning after it.
    let mut buf = vec![0u8; usize::from(MIN_INITIAL_SIZE) + 64];
    let datagram_start = buf.len();
    let capacity = datagram_start + 200;
    let dst_cid = conn.active_rem_cid();
    let builder = PacketBuilder::new(
        now,
        SpaceId::Data,
        dst_cid,
        &mut buf,
        capacity,
        datagram_start,
        true,
        conn,
    )
    .expect("a 1-RTT packet can be built");
    let sent = SentFrames {
        challenge: Some(token),
        ..SentFrames::default()
    };
    builder
        .finish_and_track(now, conn, Some(sent), &mut buf)
        .unwrap();

    assert!(
        buf.len() > usize::from(MIN_INITIAL_SIZE),
        "the buffer as a whole is past {MIN_INITIAL_SIZE}: {}",
        buf.len()
    );
    assert!(
        !conn.challenge_proves_mtu(),
        "but the datagram that carried the token is {} bytes, so it proves no MTU",
        buf.len() - datagram_start
    );
}

/// A validation that exists to prove the minimum MTU is written only into a datagram that can
/// still reach it. The rule lives on the token; this is the sender honouring it.
#[test]
fn the_sender_withholds_an_mtu_challenge_from_a_datagram_that_cannot_expand() {
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();
    let now = pair.time;
    let conn = pair.client_conn_mut(client_ch);
    conn.set_mtu_challenge(0x1111_2222_3333_4444);
    let before = conn.stats().frame_tx.path_challenge;

    let mut buf = Vec::new();
    conn.populate_for_tests(now, &mut buf, 1200, false);
    assert_eq!(
        conn.stats().frame_tx.path_challenge,
        before,
        "a datagram that cannot reach the minimum size carries no MTU challenge"
    );

    let mut buf = Vec::new();
    conn.populate_for_tests(now, &mut buf, 1200, true);
    assert_eq!(
        conn.stats().frame_tx.path_challenge,
        before + 1,
        "and one that can, does"
    );
}
