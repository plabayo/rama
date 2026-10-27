//! Protected-packet reproductions of external peers' preferred-address behavior.

use super::*;

#[test]
fn unanswered_preferred_validation_preserves_limits_and_fallback() {
    for close in [false, true] {
        let (mut pair, preferred) = pair_preferring(true);
        let (client, server) = connect_armed(&mut pair);
        let original = pair.server.addr;
        let cid = pair.client_conn_mut(client).active_rem_cid();
        let now = pair.time;
        let packet = pair
            .client_conn_mut(client)
            .encode_peer_packet_for_test(now, cid, &[1]); // PING
        pair.server.inbound.push_back(Inbound {
            at: now,
            ecn: None,
            packet,
            from: Some(pair.client.addr),
            to: Some(preferred),
        });
        pair.server.drive(now, pair.client.addr);
        assert_eq!(pair.server_conn_mut(server).path_local(), Some(preferred));
        let stream = pair.server_streams(server).open(Dir::Uni).unwrap();
        pair.server_send(server, stream)
            .write(b"fallback remains usable")
            .unwrap();
        pair.server_send(server, stream).finish().unwrap();
        if close {
            pair.server.outbound.clear();
            pair.server_conn_mut(server)
                .close(now, 0u32.into(), Bytes::new());
            pair.server.drive(now, pair.client.addr);
            assert_eq!(pair.server_conn_mut(server).stats().frame_tx.stream, 0);
            assert_eq!(
                pair.server_conn_mut(server)
                    .stats()
                    .frame_tx
                    .connection_close,
                1
            );
            assert!(
                pair.server
                    .outbound
                    .iter()
                    .all(|(tx, _)| tx.local == Some(original))
            );
        } else {
            let mut sent_on_preferred = 0;
            for _ in 0..64 {
                sent_on_preferred += pair
                    .server
                    .outbound
                    .iter()
                    .filter(|(tx, _)| tx.local == Some(preferred))
                    .map(|(tx, _)| tx.size)
                    .sum::<usize>();
                if pair.server_conn_mut(server).path_local() == Some(original) {
                    break;
                }
                assert_eq!(pair.server_conn_mut(server).stats().frame_tx.stream, 0);
                pair.server.outbound.clear(); // Lose every validation response.
                pair.time = pair.server.next_wakeup().unwrap();
                pair.server.drive(pair.time, pair.client.addr);
            }
            assert!(
                sent_on_preferred <= 3600,
                "three times the sole received datagram: {sent_on_preferred}"
            );
            assert_eq!(pair.server_conn_mut(server).path_local(), Some(original));
            drive_settled(&mut pair);
            let mut recv = pair.client_recv(client, stream);
            let mut chunks = recv.read(true).unwrap();
            assert_eq!(
                chunks.next(usize::MAX).unwrap().unwrap().bytes,
                b"fallback remains usable"[..]
            );
            assert!(chunks.next(usize::MAX).unwrap().is_none());
            let _transmit = chunks.finalize();
        }
    }
}

#[test]
fn preferred_address_validation_survives_reused_cid_ack_traffic() {
    let (mut pair, preferred) = pair_preferring(true);
    let (client, server) = connect_armed(&mut pair);
    let original = pair.server.addr;
    let reused_cid = pair.client_conn_mut(client).active_rem_cid();
    probe_once(&mut pair, server);
    assert!(pair.client_conn_mut(client).reserved_rem_cid().is_some());

    let stream = pair.server_streams(server).open(Dir::Uni).unwrap();
    let body = vec![0x5a; 1800];
    pair.server_send(server, stream).write(&body).unwrap();
    pair.server_send(server, stream).finish().unwrap();
    let before = pair.server_conn_mut(server).stats().frame_tx.stream;
    let mut acked = rama_quic_proto::range_set::ArrayRangeSet::new();
    acked.insert_one(pair.server_conn_mut(server).packet_numbers().1 - 1);
    let mut ack = Vec::new();
    frame::Ack::encode(0, &acked, None, &mut ack);

    // The peer probes using its fresh preferred CID, but sends ACKs on both
    // destinations using the original CID before receiving the probe response.
    // This is the sequence observed from ngtcp2 in the Docker matrix.
    for local in [preferred, original, preferred, original] {
        let now = pair.time;
        let packet = pair
            .client_conn_mut(client)
            .encode_peer_packet_for_test(now, reused_cid, &ack);
        pair.server.inbound.push_back(Inbound {
            at: now,
            ecn: None,
            packet,
            from: Some(pair.client.addr),
            to: Some(local),
        });
        pair.server.drive(now, pair.client.addr);
        assert_eq!(
            pair.server_conn_mut(server).path_local(),
            Some(preferred),
            "ACK feedback must not oscillate the pending preferred path"
        );
        assert_eq!(
            pair.server_conn_mut(server).stats().frame_tx.stream,
            before,
            "RFC 9000 section 9.6.2: validate before sending data from the preferred address"
        );
        assert!(!pair.server_conn_mut(server).is_closed());
    }
    // Deliver the held responses and validation probes. Both endpoints must
    // settle on the preferred path and deliver the entire queued stream.
    drive_settled(&mut pair);
    assert_eq!(pair.client_conn_mut(client).remote_address(), preferred);
    assert_eq!(pair.server_conn_mut(server).path_local(), Some(preferred));
    assert!(pair.server_conn_mut(server).path_validated());
    let mut recv = pair.client_recv(client, stream);
    let mut chunks = recv.read(true).unwrap();
    let mut received = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX).unwrap() {
        received.extend_from_slice(&chunk.bytes);
    }
    let _transmit = chunks.finalize();
    assert_eq!(received, body);
}
