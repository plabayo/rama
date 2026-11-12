//! NAT rebinding between the two handshake flights.
use super::*;

#[test]
fn handshake_rebind_finishes_and_validates_new_path() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let server = pair.server.assert_accept();
    let original = pair.client.addr;
    let rebound: SocketAddr = "192.0.2.123:4567".parse().unwrap();
    pair.drive_client();
    assert!(!pair.server.inbound.is_empty());
    let packets: Vec<_> = pair.server.inbound.drain(..).collect();
    // Corrupt the encrypted flight: a new address alone must not change routing or credit.
    for incoming in &packets {
        let mut packet = incoming.packet.clone();
        for byte in packet.iter_mut().skip(30) {
            *byte ^= 0x55;
        }
        pair.server.inbound.push_back(Inbound {
            at: incoming.at,
            ecn: incoming.ecn,
            packet,
            from: Some(rebound),
            to: incoming.to,
        });
    }
    pair.drive_server();
    assert_eq!(pair.server_conn_mut(server).remote_address(), original);
    for incoming in &packets {
        pair.server.inbound.push_back(Inbound {
            at: incoming.at,
            ecn: incoming.ecn,
            packet: incoming.packet.clone(),
            from: Some(rebound),
            to: incoming.to,
        });
    }
    pair.client.addr = rebound;
    for incoming in &mut pair.server.inbound {
        incoming.from = Some(rebound);
    }
    pair.drive_server();
    assert_eq!(pair.server_conn_mut(server).remote_address(), rebound);
    assert_eq!(
        pair.server_conn_mut(server).validated_remote_address(),
        original
    );
    assert!(!pair.server_conn_mut(server).path_validated());
    let received: u64 = packets.iter().map(|p| p.packet.len() as u64).sum();
    let sent: usize = pair
        .server_sent
        .iter()
        .filter(|p| p.to == rebound)
        .map(|p| p.bytes)
        .sum();
    assert!(sent as u64 <= 3 * received);
    // Forwarding the exact accepted flight from a third address must not move again.
    for incoming in &packets {
        pair.server.inbound.push_back(Inbound {
            at: incoming.at,
            ecn: incoming.ecn,
            packet: incoming.packet.clone(),
            from: Some("192.0.2.124:4568".parse().unwrap()),
            to: incoming.to,
        });
    }
    pair.drive_server();
    assert_eq!(pair.server_conn_mut(server).remote_address(), rebound);
    pair.drive();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(!pair.server_conn_mut(server).is_handshaking());
    assert!(pair.server_conn_mut(server).path_validated());
    assert_eq!(
        pair.server_conn_mut(server).validated_remote_address(),
        rebound
    );
}

#[test]
fn handshake_rebind_initial_cannot_move_the_server() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    let initial: Vec<_> = pair
        .server
        .inbound
        .iter()
        .map(|p| p.packet.clone())
        .collect();
    pair.drive_server();
    let server = pair.server.assert_accept();
    for packet in initial {
        pair.server.inbound.push_back(Inbound {
            at: pair.time,
            ecn: None,
            packet,
            from: Some("192.0.2.123:4567".parse().unwrap()),
            to: Some(pair.server.addr),
        });
    }
    pair.drive_server();
    assert_eq!(
        pair.server_conn_mut(server).remote_address(),
        pair.client.addr
    );
    pair.drive();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(pair.server_conn_mut(server).path_validated());
    assert_eq!(
        pair.server_conn_mut(server).validated_remote_address(),
        pair.client.addr
    );
}

#[test]
fn handshake_rebind_failed_validation_does_not_validate_a_later_finished() {
    for return_to_original in [false, true] {
        let mut pair = Pair::default();
        let client = pair.begin_connect(client_config());
        pair.drive_client();
        pair.drive_server();
        pair.drive_client();
        let server = pair.server.assert_accept();
        let original = pair.client.addr;
        let rebound: SocketAddr = "192.0.2.123:4567".parse().unwrap();
        let mut finished = mem::take(&mut pair.server.inbound);
        let now = pair.time;
        let ping = pair.client_conn_mut(client).handshake_ping_for_test(now);
        let received_ping = ping.len();
        pair.server.inbound.push_back(Inbound {
            at: now,
            ecn: None,
            packet: ping,
            from: Some(rebound),
            to: Some(pair.server.addr),
        });
        pair.drive_server();
        assert_eq!(pair.server_conn_mut(server).remote_address(), rebound);
        assert!(!pair.server_conn_mut(server).path_validated());
        // No packet sent to the spoofed address is ever delivered to the client.
        // The address challenge expires before the absolute handshake deadline.
        pair.time += Duration::from_secs(4);
        pair.drive_server();
        assert!(pair.server_conn_mut(server).is_handshaking());
        assert!(!pair.server_conn_mut(server).path_validated());
        let received_finished: usize = finished.iter().map(|p| p.packet.len()).sum();
        for packet in &mut finished {
            packet.at = pair.time;
            packet.from = Some(if return_to_original {
                original
            } else {
                rebound
            });
        }
        pair.server.inbound.extend(finished);
        pair.drive_server();
        assert!(!pair.server_conn_mut(server).is_handshaking());
        assert_eq!(
            pair.server_conn_mut(server).path_validated(),
            return_to_original
        );
        assert_eq!(
            pair.server_conn_mut(server).validated_remote_address(),
            original
        );
        let sent: usize = pair
            .server_sent
            .iter()
            .filter(|p| p.to == rebound)
            .map(|p| p.bytes)
            .sum();
        assert!(sent <= 3 * (received_ping + received_finished));
    }
}

#[test]
fn handshake_rebind_is_rejected_when_migration_is_disabled() {
    let mut config = server_config();
    config.set_migration(false);
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        config,
    );
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    let server = pair.server.assert_accept();
    let original = pair.client.addr;
    let finished = mem::take(&mut pair.server.inbound);
    for incoming in &finished {
        pair.server.inbound.push_back(Inbound {
            at: incoming.at,
            ecn: incoming.ecn,
            packet: incoming.packet.clone(),
            from: Some("192.0.2.123:4567".parse().unwrap()),
            to: incoming.to,
        });
    }
    pair.drive_server();
    assert_eq!(pair.server_conn_mut(server).remote_address(), original);
    assert!(pair.server_conn_mut(server).is_handshaking());
    assert!(!pair.server_conn_mut(server).path_validated());
    pair.server.inbound.extend(finished);
    pair.drive();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(!pair.server_conn_mut(server).is_handshaking());
    assert!(pair.server_conn_mut(server).path_validated());
}
