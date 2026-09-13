use super::qlog::Capture;
use super::*;

#[test]
fn qlog_paths_follow_actual_migration_and_mtu_changes() {
    let _guard = subscribe();
    let capture = Capture::default();
    let mut server = server_config();
    server.transport = capture.transport(Instant::now());
    let transport = Arc::get_mut(&mut server.transport).unwrap();
    transport.set_initial_rtt(Duration::from_micros(123_456));
    transport.set_packet_threshold(7);
    transport.set_time_threshold(1.25);
    transport.set_persistent_congestion_threshold(4);
    transport.set_initial_mtu(1250);
    transport.try_set_initial_congestion_window(18_000).unwrap();
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    pair.mtu = 1300;
    let (client_ch, server_ch) = pair.connect();
    pair.drive();
    let recovery = capture.events("quic:recovery_parameters_set");
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0]["data"]["timer_granularity"], 1);
    assert_eq!(recovery[0]["data"]["reordering_threshold"], 7);
    assert_eq!(recovery[0]["data"]["time_threshold"], 1.25);
    assert_eq!(recovery[0]["data"]["persistent_congestion_threshold"], 4);
    assert_eq!(recovery[0]["data"]["max_datagram_size"], 1250);
    assert_eq!(recovery[0]["data"]["initial_congestion_window"], 18_000);
    // qlog uses milliseconds, retaining the fraction from the configured microseconds.
    let initial_rtt_ms = recovery[0]["data"]["initial_rtt"].as_f64().unwrap();
    assert!((initial_rtt_ms - 123.456).abs() < 1e-9, "{initial_rtt_ms}");
    let mtus = capture.events("quic:mtu_updated");
    assert!(!mtus.is_empty());
    assert!(
        mtus.iter()
            .all(|event| event["data"]["old"] != event["data"]["new"])
    );
    assert_eq!(
        mtus.last().unwrap()["data"]["new"],
        pair.server_conn_mut(server_ch).path_mtu()
    );
    assert!(capture.events("quic:migration_state_updated").is_empty());

    pair.client.addr = SocketAddr::new(
        Ipv4Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().next().unwrap(),
    );
    pair.client_conn_mut(client_ch).ping();
    pair.drive();
    assert_eq!(
        pair.server_conn_mut(server_ch).remote_address(),
        pair.client.addr
    );
    let migrations = capture.events("quic:migration_state_updated");
    let states: Vec<_> = migrations
        .iter()
        .map(|event| event["data"]["new"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["migration_started", "migration_complete"]);
    let assignments = capture.events("quic:tuple_assigned");
    for migration in migrations {
        assert_eq!(migration["tuple"], migration["data"]["tuple_id"]);
        assert!(
            assignments
                .iter()
                .any(|assigned| assigned["data"]["tuple_id"] == migration["data"]["tuple_id"])
        );
    }
    assert!(
        assignments
            .iter()
            .any(|event| event["data"]["tuple_remote"]["ip_v4"] == "127.0.0.1")
    );
}

#[test]
fn qlog_paths_cid_rotation_has_remote_and_local_perspectives() {
    let _guard = subscribe();
    let client_capture = Capture::default();
    let server_capture = Capture::default();
    let mut server = server_config();
    server.transport = server_capture.transport(Instant::now());
    let mut client = client_config();
    client.transport = client_capture.transport(Instant::now());
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    let (client_ch, _) = pair.connect_with(client);
    pair.drive();
    client_capture.clear();
    server_capture.clear();
    let now = pair.time;
    assert!(pair.client_conn_mut(client_ch).migrate_local_address(now));
    pair.drive();
    let client = client_capture.events("quic:connection_id_updated");
    assert!(
        client
            .iter()
            .any(|event| event["data"]["initiator"] == "remote"
                && event["data"]["old"] != event["data"]["new"])
    );
    let server = server_capture.events("quic:connection_id_updated");
    assert!(
        server
            .iter()
            .any(|event| event["data"]["initiator"] == "local"
                && event["data"]["old"] != event["data"]["new"])
    );
}

#[test]
fn qlog_paths_preferred_address_records_success_and_abandonment() {
    let _guard = subscribe();
    for reachable in [true, false] {
        let capture = Capture::default();
        let (mut pair, preferred) = pair_preferring(reachable);
        let mut client = client_config();
        client.transport = capture.transport(Instant::now());
        let (client_ch, _) = pair.connect_with(client);
        drive_settled(&mut pair);
        let migrations = capture.events("quic:migration_state_updated");
        let states: Vec<_> = migrations
            .iter()
            .map(|event| event["data"]["new"].as_str().unwrap())
            .collect();
        if reachable {
            assert_eq!(pair.client_conn_mut(client_ch).remote_address(), preferred);
            assert_eq!(
                states,
                [
                    "probing_started",
                    "probing_successful",
                    "migration_started",
                    "migration_complete"
                ]
            );
        } else {
            assert_ne!(pair.client_conn_mut(client_ch).remote_address(), preferred);
            assert_eq!(states, ["probing_started", "probing_abandoned"]);
        }
        let tuples = capture.events("quic:tuple_assigned");
        assert!(migrations.iter().all(|migration| {
            tuples
                .iter()
                .any(|tuple| tuple["data"]["tuple_id"] == migration["data"]["tuple_id"])
        }));
    }
}

#[test]
fn qlog_paths_mtu_black_hole_logs_reduction() {
    let _guard = subscribe();
    let capture = Capture::default();
    let mut client = client_config();
    client.transport = capture.transport(Instant::now());
    let mut pair = Pair::default();
    pair.mtu = 1500;
    let (client_ch, server_ch) = pair.connect_with(client);
    pair.drive();
    let old_mtu = pair.client_conn_mut(client_ch).path_mtu();
    assert!(old_mtu > 1200);
    capture.clear();
    pair.mtu = 1200;
    let stream = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, stream)
        .write(&[42; 1300])
        .unwrap();
    assert!(!pair.drive_bounded());
    assert_eq!(
        stream_chunks(pair.server_recv(server_ch, stream)).len(),
        1300
    );
    assert_eq!(
        pair.client_conn_mut(client_ch)
            .stats()
            .path
            .black_holes_detected,
        1
    );
    let updates = capture.events("quic:mtu_updated");
    assert!(
        updates
            .iter()
            .any(|event| event["data"]["old"] == old_mtu && event["data"]["new"] == 1200)
    );
}

#[test]
fn qlog_paths_failed_migration_restores_both_connection_ids() {
    let _guard = subscribe();
    let capture = Capture::default();
    let mut server = server_config();
    server.transport = capture.transport(Instant::now());
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    let (client_ch, server_ch) = pair.connect();
    pair.drive();
    let original_address = pair.client.addr;
    let original_remote_cid = pair.server_conn_mut(server_ch).active_rem_cid();
    capture.clear();

    // Deliver a fresh-CID packet from a different address, then lose every validation
    // challenge. The server adopts the move but must return to its validated fallback.
    let unreachable = SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 7).into(),
        CLIENT_PORTS.lock().next().unwrap(),
    );
    pair.client.addr = unreachable;
    let now = pair.time;
    assert!(pair.client_conn_mut(client_ch).migrate_local_address(now));
    pair.drive_client();
    pair.server.drive(pair.time, unreachable);
    pair.client.addr = original_address;
    assert_eq!(
        pair.server_conn_mut(server_ch).remote_address(),
        unreachable
    );
    assert_ne!(
        pair.server_conn_mut(server_ch).active_rem_cid(),
        original_remote_cid
    );

    for _ in 0..64 {
        if pair.server_conn_mut(server_ch).remote_address() != unreachable {
            break;
        }
        pair.server.outbound.clear();
        let next = pair
            .server
            .next_wakeup()
            .expect("pending validation deadline");
        pair.time = pair.time.max(next);
        pair.server.drive(pair.time, original_address);
    }
    assert_eq!(
        pair.server_conn_mut(server_ch).remote_address(),
        original_address
    );
    assert_eq!(
        pair.server_conn_mut(server_ch).active_rem_cid(),
        original_remote_cid
    );

    let updates = capture.events("quic:connection_id_updated");
    for initiator in ["local", "remote"] {
        let changes: Vec<_> = updates
            .iter()
            .filter(|event| event["data"]["initiator"] == initiator)
            .collect();
        assert_eq!(
            changes.len(),
            2,
            "{initiator} ID must change on adoption and rollback: {changes:?}"
        );
        assert_ne!(changes[0]["data"]["old"], changes[0]["data"]["new"]);
        assert_eq!(changes[1]["data"]["old"], changes[0]["data"]["new"]);
        assert_eq!(changes[1]["data"]["new"], changes[0]["data"]["old"]);
    }
    let migrations = capture.events("quic:migration_state_updated");
    let states: Vec<_> = migrations
        .iter()
        .map(|event| event["data"]["new"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["migration_started", "migration_abandoned"]);
}
