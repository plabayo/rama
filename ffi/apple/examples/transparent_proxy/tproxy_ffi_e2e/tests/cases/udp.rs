//! UDP ABI smoke coverage.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use serial_test::serial;

use crate::shared::{
    bindings,
    clients::{UdpFfiSession, udp_roundtrip, udp_roundtrip_v1},
    env::{AbortOnDrop, setup_env},
    ffi::EngineHandle,
    servers::spawn_udp_echo,
    types::localhost,
};

const MAX_UDP_DATAGRAM: usize = u16::MAX as usize;
const DEFAULT_PER_FLOW_BYTES: usize = 256 * 1024;
const DEFAULT_GLOBAL_BYTES: usize = 16 * 1024 * 1024;
const GLOBAL_FILL_FLOWS: usize = 64;
const DATAGRAMS_PER_FILL_FLOW: usize = 4;
const PER_FLOW_TAIL_BYTES: usize =
    DEFAULT_PER_FLOW_BYTES - DATAGRAMS_PER_FILL_FLOW * MAX_UDP_DATAGRAM;

fn fill_default_global_budget(
    engine: &Arc<EngineHandle>,
    remote: SocketAddr,
) -> Vec<UdpFfiSession> {
    let payload = vec![b'f'; MAX_UDP_DATAGRAM];
    let tail = vec![b't'; PER_FLOW_TAIL_BYTES];
    let mut sessions = Vec::with_capacity(GLOBAL_FILL_FLOWS);
    for _ in 0..GLOBAL_FILL_FLOWS {
        let session = UdpFfiSession::new(engine.clone(), remote);
        for _ in 0..DATAGRAMS_PER_FILL_FLOW {
            session.stage_client_datagram_before_activation(&payload, Some(remote));
        }
        session.stage_client_datagram_before_activation(&tail, Some(remote));
        sessions.push(session);
    }
    sessions
}

fn close_udp_sessions(sessions: Vec<UdpFfiSession>) {
    for session in sessions {
        session.close_from_client_and_assert(1);
    }
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_basic_echo() {
    let env = setup_env().await;
    let response = udp_roundtrip(env.engine, localhost(env.ports.udp), b"udp ffi").await;
    assert_eq!(response, b"UDP FFI");
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_v1_callback_abi_remains_compatible() {
    let env = setup_env().await;
    let response = udp_roundtrip_v1(env.engine, localhost(env.ports.udp), b"udp ffi v1").await;
    assert_eq!(response, b"UDP FFI V1");
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_ingress_owns_borrowed_payload_and_peer_after_return() {
    let env = setup_env().await;
    let remote = localhost(env.ports.udp);
    let mut session = UdpFfiSession::new(env.engine, remote);
    let expected_payload = b"caller-owned udp payload".to_vec();
    let mut caller_payload = expected_payload.clone();
    let mut caller_peer_host = remote.ip().to_string().into_bytes();

    session.stage_borrowed_client_datagram_before_activation(
        &caller_payload,
        &caller_peer_host,
        remote.port(),
        0,
    );

    // The C contract ends both borrows when the call above returns. Poison the
    // exact allocations before activation so deferred parsing/copying cannot
    // accidentally pass because allocator contents happened to remain intact.
    caller_payload.fill(b'!');
    caller_peer_host.fill(b'x');
    drop(caller_payload);
    drop(caller_peer_host);

    session.activate();
    let response = session.recv_server_datagram().await;
    assert_eq!(response.payload, b"CALLER-OWNED UDP PAYLOAD");
    assert_eq!(
        response.peer.as_ref().map(|peer| peer.socket_addr()),
        Some(remote),
        "peer host must be parsed before its caller-owned UTF-8 is poisoned"
    );
    session.close_from_client_and_assert(1);
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_v2_global_budget_probe_ack_and_cleanup() {
    let env = setup_env().await;
    let engine = env.engine.clone();
    let remote = localhost(env.ports.udp);

    let (channel_capacity, per_flow_bytes, global_bytes) = unsafe {
        (
            bindings::rama_transparent_proxy_engine_udp_channel_capacity(engine.raw),
            bindings::rama_transparent_proxy_engine_udp_ingress_per_flow_max_bytes(engine.raw),
            bindings::rama_transparent_proxy_engine_udp_ingress_global_max_bytes(engine.raw),
        )
    };
    assert_eq!(channel_capacity, 32, "test requires the production default");
    assert_eq!(
        per_flow_bytes, DEFAULT_PER_FLOW_BYTES,
        "test requires the production per-flow byte default"
    );
    assert_eq!(
        global_bytes, DEFAULT_GLOBAL_BYTES,
        "test requires the production global byte default"
    );
    assert_eq!(
        GLOBAL_FILL_FLOWS * DATAGRAMS_PER_FILL_FLOW * MAX_UDP_DATAGRAM,
        DEFAULT_GLOBAL_BYTES - 256,
        "64 flows of four maximum-sized payloads must leave only 256 bytes"
    );
    assert_eq!(PER_FLOW_TAIL_BYTES, 4);
    assert_eq!(
        GLOBAL_FILL_FLOWS * (DATAGRAMS_PER_FILL_FLOW * MAX_UDP_DATAGRAM + PER_FLOW_TAIL_BYTES),
        global_bytes,
        "four maximum payloads plus each flow's four-byte tail fill exactly 16 MiB"
    );

    // Inactive sessions retain their public-ABI ingress queues without giving
    // the service a chance to drain them. The required four maximum payloads
    // per flow leave four bytes under each per-flow cap; filling that tail too
    // charges the global 16 MiB exactly, making the later leak check sensitive
    // even to a single retained byte.
    let mut fillers = fill_default_global_budget(&engine, remote);
    let blocked_payload = vec![b'b'; MAX_UDP_DATAGRAM];
    let mut stalled = UdpFfiSession::new(engine.clone(), remote);
    stalled.stage_client_datagram_before_activation(&blocked_payload, Some(remote));
    stalled.activate();

    // The 65th payload cannot fit. Releasing one complete fill flow is the
    // only capacity edge; the first observable event on the stalled flow must
    // be a non-zero leased retry, never delivery of the rejected payload.
    fillers.remove(0).close_from_client_and_assert(1);
    let probe_id = stalled.wait_for_probe_read_demand().await;
    assert_ne!(probe_id, 0, "global-pressure demand must carry a probe ID");

    // A wrong ID must not consume this flow's lease. Then model one completed
    // Apple read: submit its datagram, ACK that exact ID, and prove the normal
    // example service returns the exact payload with its real peer.
    let stale_probe_id = probe_id.checked_add(1).unwrap_or(probe_id - 1);
    stalled.acknowledge_client_read(stale_probe_id);
    let recovery_payload = b"v2 global pressure recovered";
    let delivered_probe_id = stalled.send_client_datagram(recovery_payload, Some(remote));
    assert_eq!(delivered_probe_id, probe_id);
    stalled.acknowledge_client_read(delivered_probe_id);
    // An already-ACKed ID is stale too and must remain a harmless no-op.
    stalled.acknowledge_client_read(delivered_probe_id);

    let response = stalled.recv_server_datagram().await;
    assert_eq!(response.payload, b"V2 GLOBAL PRESSURE RECOVERED");
    assert_eq!(
        response.peer.as_ref().map(|peer| peer.socket_addr()),
        Some(remote)
    );
    stalled.close_from_client_and_assert(1);
    close_udp_sessions(fillers);

    // Behavioral leak and exact-ACK check on the same engine generation.
    // Refill the entire 64-flow boundary. If retained bytes survived the first
    // teardown, a refill flow rejected earlier becomes a FIFO waiter and is
    // observed below. Six new waiters also let four leases consume the complete
    // coordinator batch, making downstream progress an exact ACK witness.
    let mut refill = fill_default_global_budget(&engine, remote);
    let mut verifiers = (0..6)
        .map(|_| {
            let session = UdpFfiSession::new(engine.clone(), remote);
            session.stage_client_datagram_before_activation(&blocked_payload, Some(remote));
            session
        })
        .collect::<Vec<_>>();
    refill.remove(0).close_from_client_and_assert(1);

    let mut initial_probes = Vec::with_capacity(4);
    for verifier in verifiers.iter_mut().take(4) {
        initial_probes.push(verifier.wait_for_probe_read_demand_observed().await);
    }
    assert!(initial_probes.iter().all(|(probe_id, _)| *probe_id != 0));

    // All four probe slots are leased. ACKing verifier 1's live ID through
    // verifier 0 is a wrong-session ACK and must not advance verifier 4.
    verifiers[0].acknowledge_client_read(initial_probes[1].0);
    assert!(
        verifiers[4]
            .wait_for_probe_read_demand_before(Duration::from_millis(2))
            .await
            .is_none(),
        "wrong-session ACK advanced downstream global capacity"
    );

    // The exact ACK must free one slot and wake the next FIFO waiter before the
    // original 10 ms lease can expire. Callback-entry timestamps avoid making
    // this assertion depend on when the test task itself resumes.
    verifiers[0].acknowledge_client_read(initial_probes[0].0);
    let fifth_probe = tokio::time::timeout(
        Duration::from_millis(5),
        verifiers[4].wait_for_probe_read_demand_observed(),
    )
    .await
    .expect("exact ACK did not advance the next waiter before lease expiry");
    assert!(
        fifth_probe.1.duration_since(initial_probes[0].1) < Duration::from_millis(10),
        "fifth probe was released by lease expiry instead of the exact ACK"
    );

    // Verifier 0's ID is now stale. It cannot release another slot; a different
    // flow's still-live exact ACK must be what advances verifier 5.
    verifiers[0].acknowledge_client_read(initial_probes[0].0);
    assert!(
        verifiers[5]
            .wait_for_probe_read_demand_before(Duration::from_millis(2))
            .await
            .is_none(),
        "stale ACK advanced downstream global capacity"
    );
    verifiers[1].acknowledge_client_read(initial_probes[1].0);
    let sixth_probe = tokio::time::timeout(
        Duration::from_millis(5),
        verifiers[5].wait_for_probe_read_demand_observed(),
    )
    .await
    .expect("second exact ACK did not advance the next waiter before lease expiry");
    assert!(
        sixth_probe.1.duration_since(initial_probes[0].1) < Duration::from_millis(10),
        "sixth probe was released by lease expiry instead of the exact ACK"
    );

    for session in &mut refill {
        session.assert_no_callbacks_queued();
    }
    verifiers[2].acknowledge_client_read(initial_probes[2].0);
    verifiers[3].acknowledge_client_read(initial_probes[3].0);
    verifiers[4].acknowledge_client_read(fifth_probe.0);
    verifiers[5].acknowledge_client_read(sixth_probe.0);
    close_udp_sessions(verifiers);
    close_udp_sessions(refill);

    // The same engine remains usable after both complete pressure cycles.
    let response = udp_roundtrip(engine, remote, b"post pressure canary").await;
    assert_eq!(response, b"POST PRESSURE CANARY");
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_zero_length_datagram_roundtrips() {
    let env = setup_env().await;
    let response = udp_roundtrip(env.engine, localhost(env.ports.udp), b"").await;
    assert!(
        response.is_empty(),
        "zero-length UDP reply was not preserved"
    );
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_absent_client_peer_uses_initial_target() {
    let env = setup_env().await;
    let remote = localhost(env.ports.udp);
    let mut session = UdpFfiSession::new(env.engine, remote);
    session.activate();
    let probe_id = session.wait_for_read_demand().await;
    let delivered_probe_id = session.send_client_datagram(b"peer fallback", None);
    assert_eq!(delivered_probe_id, probe_id);
    session.acknowledge_client_read(delivered_probe_id);

    let response = session.recv_server_datagram().await;
    assert_eq!(response.payload, b"PEER FALLBACK");
    assert_eq!(
        response.peer.as_ref().map(|peer| peer.socket_addr()),
        Some(remote),
        "the reply callback must report the actual recv_from peer"
    );
    session.close_from_client_and_assert(1);
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_one_session_routes_multiple_ipv4_peers() {
    let env = setup_env().await;
    let peer_a = localhost(env.ports.udp);
    let (peer_b_port, peer_b_handle) = spawn_udp_echo().await;
    let _peer_b_server = AbortOnDrop(vec![peer_b_handle]);
    let peer_b = localhost(peer_b_port);
    assert_ne!(peer_a, peer_b, "test requires two distinct UDP peers");

    let mut session = UdpFfiSession::new(env.engine, peer_a);
    session.activate();

    let probe_a = session.wait_for_read_demand().await;
    assert_eq!(
        session.send_client_datagram(b"from peer a", Some(peer_a)),
        probe_a
    );
    session.acknowledge_client_read(probe_a);
    let probe_b = session.wait_for_read_demand().await;
    assert_eq!(
        session.send_client_datagram(b"from peer b", Some(peer_b)),
        probe_b
    );
    session.acknowledge_client_read(probe_b);

    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..2 {
        let response = session.recv_server_datagram().await;
        let actual_peer = response
            .peer
            .as_ref()
            .map(|peer| peer.socket_addr())
            .expect("echo reply must retain its source peer");
        match response.payload.as_slice() {
            b"FROM PEER A" => {
                assert_eq!(actual_peer, peer_a);
                assert!(!saw_a, "duplicate response from peer A");
                saw_a = true;
            }
            b"FROM PEER B" => {
                assert_eq!(actual_peer, peer_b);
                assert!(!saw_b, "duplicate response from peer B");
                saw_b = true;
            }
            other => panic!("unexpected multi-peer UDP response: {other:?}"),
        }
    }
    assert!(saw_a && saw_b, "both IPv4 peers must reply on one flow");
    session.close_from_client_and_assert(1);
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_service_close_callback_fires_exactly_once() {
    let env = setup_env().await;
    // A datagram socket without SO_BROADCAST cannot write to the limited
    // broadcast address. The example service's real `send_to` therefore fails
    // deterministically, exits its service future, and exercises the Rust-to-C
    // server-close callback path without sleeping for the production timeout.
    let invalid_peer = "255.255.255.255:54321"
        .parse()
        .expect("limited broadcast socket address");
    // Keep the flow's initial endpoint on loopback so the example policy
    // intercepts it; per-datagram attribution must still route to this peer.
    let mut session = UdpFfiSession::new(env.engine, localhost(env.ports.udp));
    session.activate();
    let probe_id = session.wait_for_read_demand().await;
    assert_eq!(
        session.send_client_datagram(b"force service close", Some(invalid_peer)),
        probe_id
    );
    session.acknowledge_client_read(probe_id);
    session.assert_server_close_and_free().await;
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_client_double_close_is_idempotent() {
    let env = setup_env().await;
    let mut session = UdpFfiSession::new(env.engine, localhost(env.ports.udp));
    session.activate();
    let probe_id = session.wait_for_read_demand().await;
    session.acknowledge_client_read(probe_id);

    // The first call disables callbacks under the engine's callback gate; the
    // second must remain a harmless no-op, and freeing immediately afterwards
    // proves no callback can touch the released context.
    session.close_from_client_and_assert(2);
}
