//! Absolute handshake budgets: proof grants one extension, traffic never renews it.

use std::collections::VecDeque;

use rama_quic_proto::packet::{FixedLengthConnectionIdParser, PartialDecode, SpaceId};

use super::*;

fn pair(gso: bool, version: Version, maximum: Duration) -> (Pair, ClientConfig) {
    let mut endpoint = EndpointConfig::try_with_rand_key().unwrap();
    endpoint.handshake_max_duration(maximum).unwrap();
    // Isolate the handshake deadline from the independent transport idle timer.
    let mut transport = TransportConfig::default();
    transport
        .set_enable_segmentation_offload(gso)
        .maybe_set_max_idle_timeout(None);
    let mut server = server_config();
    server.transport = Arc::new(transport.clone());
    let mut client = client_config();
    client.transport = Arc::new(transport);
    client.set_version(version).unwrap();
    (Pair::new(Arc::new(endpoint), server), client)
}

/// The client has finished TLS, but none of its Finished flight has reached the server.
fn awaiting_finished(
    pair: &mut Pair,
    config: ClientConfig,
) -> (ConnectionHandle, ConnectionHandle, VecDeque<Inbound>) {
    let client = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    let server = pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(pair.server_conn_mut(server).is_handshaking());
    assert!(!pair.server_conn_mut(server).path_validated());
    let finished = mem::take(&mut pair.server.inbound);
    assert!(!finished.is_empty());
    (client, server, finished)
}

fn prove_client_address(pair: &mut Pair, client: ConnectionHandle, server: ConnectionHandle) {
    let now = pair.time;
    let packet = pair.client_conn_mut(client).handshake_ping_for_test(now);
    pair.server
        .inbound
        .push_back(Inbound::plain(now, None, packet));
    pair.drive_server();
    assert!(pair.server_conn_mut(server).path_validated());
    assert!(pair.server_conn_mut(server).is_handshaking());
}

#[test]
fn validated_server_completes_after_the_initial_budget() {
    for gso in [false, true] {
        for version in [Version::V1, Version::V2] {
            for maximum in [10, 30] {
                let (mut pair, config) = pair(gso, version, Duration::from_secs(maximum));
                let started = pair.time;
                let (client, server, mut finished) = awaiting_finished(&mut pair, config);
                pair.time = started + Duration::from_secs(1);
                prove_client_address(&mut pair, client, server);
                pair.time = started + Duration::from_millis(11_250);
                pair.drive_server();
                if maximum == 10 {
                    assert_matches!(
                        pair.server_conn_mut(server).ended_because(),
                        Some(ConnectionError::TimedOut)
                    );
                    continue;
                }
                assert!(!pair.server_conn_mut(server).is_closed());
                for datagram in &mut finished {
                    datagram.at = pair.time;
                }
                pair.server.inbound.extend(finished);
                pair.drive();
                assert!(pair.server_conn_mut(server).handshake_confirmed());
                assert!(pair.client_conn_mut(client).handshake_confirmed());
            }
        }
    }
}

#[test]
fn silence_and_repeated_proof_both_expire_at_the_original_ceiling() {
    for active in [false, true] {
        let (mut pair, config) = pair(false, Version::V1, Duration::from_secs(30));
        let started = pair.time;
        let (client, server, _) = awaiting_finished(&mut pair, config);
        pair.time = started + Duration::from_secs(1);
        prove_client_address(&mut pair, client, server);
        for seconds in [9, 19, 29] {
            pair.time = started + Duration::from_secs(seconds);
            if active {
                prove_client_address(&mut pair, client, server);
            } else {
                pair.drive_server();
            }
            assert!(!pair.server_conn_mut(server).is_closed());
        }
        pair.time = started + Duration::from_secs(30);
        pair.drive_server();
        assert_matches!(
            pair.server_conn_mut(server).ended_because(),
            Some(ConnectionError::TimedOut)
        );
    }
}

#[test]
fn corrupted_handshake_and_buffered_one_rtt_do_not_grant_an_extension() {
    for corrupt in [false, true] {
        let (mut pair, config) = pair(false, Version::V1, Duration::from_secs(30));
        let started = pair.time;
        let (client, server, _) = awaiting_finished(&mut pair, config);
        let authenticated = pair.server_conn_mut(server).authenticated_packets();
        pair.time = started + Duration::from_secs(9);
        let now = pair.time;
        let connection = pair.client_conn_mut(client);
        let packet = if corrupt {
            let mut packet = connection.handshake_ping_for_test(now);
            let last = packet.len() - 1;
            packet[last] ^= 0xff;
            packet
        } else {
            connection.encode_peer_packet_for_test(now, connection.active_rem_cid(), &[1])
        };
        // Include duplicates: none of these is proof, however often it arrives.
        for _ in 0..3 {
            pair.server
                .inbound
                .push_back(Inbound::plain(now, None, packet.clone()));
        }
        pair.drive_server();
        assert_eq!(
            pair.server_conn_mut(server).authenticated_packets(),
            authenticated
        );
        assert!(!pair.server_conn_mut(server).path_validated());
        if !corrupt {
            assert!(pair.server_conn_mut(server).held_early_packets() > 0);
        }
        pair.time = started + Duration::from_secs(10);
        pair.drive_server();
        assert_matches!(
            pair.server_conn_mut(server).ended_because(),
            Some(ConnectionError::TimedOut)
        );
        assert_eq!(pair.server_conn_mut(server).held_early_packets(), 0);
    }
}

/// Deliver the server Initials, retaining its Handshake flight. Splitting coalesced packets
/// lets the client derive Handshake keys without completing TLS.
fn initial_only(pair: &mut Pair) -> VecDeque<Inbound> {
    let mut held = VecDeque::new();
    for datagram in mem::take(&mut pair.client.inbound) {
        let mut rest = Some(datagram.packet.clone());
        while let Some(bytes) = rest {
            let (packet, next) = PartialDecode::new(
                bytes,
                &FixedLengthConnectionIdParser::new(8),
                DEFAULT_SUPPORTED_VERSIONS,
                true,
            )
            .unwrap();
            let initial = packet.space() == Some(SpaceId::Initial);
            let incoming = Inbound {
                packet: BytesMut::from(packet.data()),
                ..datagram.clone()
            };
            if initial {
                pair.client.inbound.push_back(incoming);
            } else {
                held.push_back(incoming);
            }
            rest = next;
        }
    }
    assert!(!held.is_empty());
    pair.drive_client();
    held
}

#[test]
fn client_requires_handshake_keys_not_its_prevalidated_path_or_initial_packets() {
    for proof in [false, true] {
        for version in [Version::V1, Version::V2] {
            let (mut pair, config) = pair(false, version, Duration::from_secs(30));
            let started = pair.time;
            let client = pair.begin_connect(config);
            assert!(pair.client_conn_mut(client).path_validated());
            pair.drive_client();
            pair.drive_server();
            let server = pair.server.assert_accept();
            let mut held = initial_only(&mut pair);
            assert!(pair.client_conn_mut(client).is_handshaking());
            for seconds in [1, 5, 9] {
                pair.time = started + Duration::from_secs(seconds);
                let now = pair.time;
                let connection = pair.server_conn_mut(server);
                let packet = if proof {
                    connection.handshake_ping_for_test(now)
                } else {
                    connection.initial_ping_for_test(now)
                };
                pair.client
                    .inbound
                    .push_back(Inbound::plain(now, None, packet));
                pair.drive_client();
            }
            pair.time = started + Duration::from_secs(11);
            pair.drive_client();
            if !proof {
                assert_matches!(
                    pair.client_conn_mut(client).ended_because(),
                    Some(ConnectionError::TimedOut)
                );
                continue;
            }
            assert!(!pair.client_conn_mut(client).is_closed());
            for datagram in &mut held {
                datagram.at = pair.time;
            }
            pair.client.inbound.extend(held);
            pair.drive_client();
            assert!(!pair.client_conn_mut(client).is_handshaking());
            assert!(!pair.client_conn_mut(client).is_closed());
        }
    }
}

#[test]
fn a_valid_retry_token_extends_only_after_acceptance_and_keeps_the_arrival_origin() {
    for accept in [false, true] {
        let (mut pair, config) = pair(false, Version::V1, Duration::from_secs(30));
        pair.server.handle_incoming = Box::new(|incoming| {
            if incoming.remote_address_validated() {
                IncomingConnectionBehavior::Wait
            } else {
                IncomingConnectionBehavior::Retry
            }
        });
        let client = pair.begin_connect(config);
        pair.drive_client();
        pair.drive_server();
        pair.drive_client();
        pair.drive_server();
        let arrived = pair.time;
        let incoming = pair.server.waiting_incoming.pop().unwrap();
        assert!(incoming.remote_address_validated());
        if !accept {
            pair.time = arrived + Duration::from_secs(10);
            assert_matches!(
                pair.server.try_accept(incoming, pair.time),
                Err(ConnectionError::TimedOut)
            );
            // Receiving a Retry has not bought the client another ten seconds either.
            let now = pair.time;
            pair.client_conn_mut(client).handle_timeout(now);
            assert_matches!(
                pair.client_conn_mut(client).ended_because(),
                Some(ConnectionError::TimedOut)
            );
            continue;
        }
        pair.time = arrived + Duration::from_secs(9);
        let server = pair.server.try_accept(incoming, pair.time).unwrap();
        for seconds in [10, 29, 30] {
            pair.time = arrived + Duration::from_secs(seconds);
            pair.drive_server();
            assert_eq!(pair.server_conn_mut(server).is_closed(), seconds == 30);
        }
    }
}

#[test]
fn a_cached_new_token_grants_the_same_bounded_extension() {
    let (mut pair, config) = pair(false, Version::V1, Duration::from_secs(30));
    let (first, _) = pair.connect_with(config.clone());
    let now = pair.time;
    pair.client_conn_mut(first)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        IncomingConnectionBehavior::Wait
    });
    let _client = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    let arrived = pair.time;
    let incoming = pair.server.waiting_incoming.pop().unwrap();
    let server = pair.server.try_accept(incoming, pair.time).unwrap();
    pair.time = arrived + Duration::from_secs(11);
    pair.drive_server();
    assert!(pair.server_conn_mut(server).is_handshaking());
    pair.time = arrived + Duration::from_secs(30);
    pair.drive_server();
    assert_matches!(
        pair.server_conn_mut(server).ended_because(),
        Some(ConnectionError::TimedOut)
    );
}

#[test]
fn proof_at_the_initial_deadline_cannot_revive_the_attempt() {
    let (mut pair, config) = pair(false, Version::V1, Duration::from_secs(30));
    let started = pair.time;
    let (client, server, _) = awaiting_finished(&mut pair, config);
    let now = started + Duration::from_secs(10);
    let packet = pair.client_conn_mut(client).handshake_ping_for_test(now);
    // Hand the datagram directly to the connection before its timer is polled. The
    // production driver also enforces expiry before draining its receive queue.
    let event = pair
        .server
        .handle(now, pair.client.addr, None, None, packet, &mut Vec::new())
        .unwrap();
    let DatagramEvent::ConnectionEvent(_, event) = event else {
        panic!("an existing connection owns the packet");
    };
    pair.server_conn_mut(server).handle_event(event);
    assert_matches!(
        pair.server_conn_mut(server).ended_because(),
        Some(ConnectionError::TimedOut)
    );
}
