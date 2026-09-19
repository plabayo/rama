use super::*;
use rama_quic_proto::Dir;

#[test]
fn ack_delay_limit_applies_after_handshake_confirmation() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.step();
    let server = pair.server.assert_accept();
    pair.server_conn_mut(server).hold_handshake_done(true);
    drive_settled(&mut pair);
    assert!(!pair.client_conn_mut(client).handshake_confirmed());
    let now = pair.time;
    pair.client_conn_mut(client)
        .assert_ack_delay_tracks_handshake_confirmation(now);

    pair.server_conn_mut(server).hold_handshake_done(false);
    drive_settled(&mut pair);
    assert!(pair.client_conn_mut(client).handshake_confirmed());
    let now = pair.time;
    pair.client_conn_mut(client)
        .assert_ack_delay_tracks_handshake_confirmation(now);
}

#[test]
fn application_data_pto_waits_for_handshake_confirmation() {
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    pair.step();
    let server = pair.server.assert_accept();
    pair.server_conn_mut(server).hold_handshake_done(true);
    drive_settled(&mut pair);
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(!pair.client_conn_mut(client).handshake_confirmed());

    // A peer may ACK the client's Finished separately from HANDSHAKE_DONE.
    // Rama's server discards its Handshake keys at completion, so supply that
    // valid ACK explicitly to isolate the Data timer from Handshake PTO.
    let now = pair.time;
    pair.client_conn_mut(client)
        .acknowledge_handshake_for_pto_test(now);

    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    pair.client_send(client, stream)
        .write(b"waiting for confirmation")
        .unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    assert!(!pair.client.outbound.is_empty());
    pair.client.outbound.clear();
    assert!(
        pair.client_conn_mut(client)
            .loss_detection_timer()
            .is_none()
    );

    // HANDSHAKE_DONE enables Data PTO for the same still-outstanding packet.
    pair.server_conn_mut(server).hold_handshake_done(false);
    pair.drive_server();
    pair.client.drive(pair.time, pair.server.addr);
    assert!(pair.client_conn_mut(client).handshake_confirmed());
    assert!(
        pair.client_conn_mut(client)
            .loss_detection_timer()
            .is_some()
    );
}

#[test]
fn extreme_time_threshold_preserves_packet_loss_detection_and_pto() {
    let mut config = server_config();
    let mut transport = TransportConfig::default();
    transport.try_set_time_threshold(f32::MAX).unwrap();
    transport.set_packet_threshold(1);
    transport.maybe_set_mtu_discovery_config(None);
    config.set_transport_config(Arc::new(transport));
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        config,
    );
    let (client, server) = pair.connect();
    pair.drive();

    let stream = pair.server_streams(server).open(Dir::Uni).unwrap();
    pair.server_send(server, stream)
        .write(b"recover me")
        .unwrap();
    pair.server.drive(pair.time, pair.client.addr);
    assert!(!pair.server.outbound.is_empty());
    pair.server.outbound.clear();
    let deadline = pair.server_conn_mut(server).loss_detection_timer().unwrap();
    let before = pair.server_conn_mut(server).stats().frame_tx;
    pair.time = deadline;
    pair.drive_server();
    let after = pair.server_conn_mut(server).stats().frame_tx;
    // A peer supporting ACK frequency is probed with IMMEDIATE_ACK; otherwise the
    // empty PTO probe uses PING. Both elicit the ACK needed for packet-threshold loss.
    assert!(after.immediate_ack + after.ping > before.immediate_ack + before.ping);
    pair.drive();

    assert!(pair.server_conn_mut(server).stats().path.lost_packets > 0);
    assert!(!pair.server_conn_mut(server).is_closed());
    assert!(!pair.client_conn_mut(client).is_closed());
    let mut recv = pair.client_recv(client, stream);
    let mut chunks = recv.read(true).unwrap();
    let chunk = chunks.next(usize::MAX).unwrap().unwrap();
    assert_eq!(chunk.bytes.as_ref(), b"recover me");
    let _transmit = chunks.finalize();
}

#[test]
fn old_path_ack_settles_stream_without_training_replacement_path() {
    let mut config = server_config();
    let mut transport = TransportConfig::default();
    transport.maybe_set_mtu_discovery_config(None);
    config.set_transport_config(Arc::new(transport));
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        config,
    );
    let (_, server) = pair.connect();
    pair.drive();
    let stream = pair.server_streams(server).open(Dir::Uni).unwrap();
    pair.server_send(server, stream)
        .write(b"old path delivery")
        .unwrap();
    pair.server_send(server, stream).finish().unwrap();
    pair.drive_server();
    pair.client.drive(pair.time, pair.server.addr);
    pair.time += Duration::from_millis(30);
    pair.client.drive(pair.time, pair.server.addr);
    assert!(!pair.client.outbound.is_empty());
    assert_eq!(pair.server_streams(server).send_streams(), 1);

    let now = pair.time;
    pair.server_conn_mut(server)
        .replace_recovery_path_for_test(now);
    let before_rtt = pair.server_conn_mut(server).rtt();
    let before_cwnd = pair.server_conn_mut(server).stats().path.cwnd;
    pair.drive_client();
    pair.server.drive(pair.time, pair.client.addr);
    assert_eq!(pair.server_streams(server).send_streams(), 0);
    assert_eq!(pair.server_conn_mut(server).rtt(), before_rtt);
    assert_eq!(pair.server_conn_mut(server).stats().path.cwnd, before_cwnd);
}

#[test]
fn rebinding_restarts_pending_mtu_probe() {
    let mut pair = Pair::default();
    let (_, server) = pair.connect();
    let now = pair.time;
    pair.server_conn_mut(server)
        .assert_rebinding_restarts_pending_mtu_probe(now);
}

#[test]
fn mixed_path_losses_train_only_current_path_and_retire_old_probes() {
    let mut pair = Pair::default();
    let (_, server) = pair.connect();
    pair.drive();
    let now = pair.time;
    pair.server_conn_mut(server)
        .assert_mixed_path_loss_is_scoped(now);
}

#[test]
fn old_path_ecn_advances_feedback_without_penalizing_current_path() {
    let mut pair = Pair::default();
    let (_, server) = pair.connect();
    pair.drive();
    let now = pair.time;
    pair.server_conn_mut(server)
        .assert_old_path_ecn_only_advances_feedback(now);
}
