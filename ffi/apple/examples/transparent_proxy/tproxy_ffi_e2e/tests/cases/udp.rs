//! UDP ABI smoke coverage.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use rama::utils::octets::{kib, mib};
use serial_test::serial;

use crate::shared::{
    bindings,
    clients::{UdpFfiSession, udp_roundtrip},
    env::{AbortOnDrop, setup_env},
    ffi::{EngineHandle, engine_with_udp_ingress_probe_lease_ms},
    servers::spawn_udp_echo,
    types::localhost,
};

const MAX_UDP_DATAGRAM: usize = u16::MAX as usize;
const DEFAULT_PER_FLOW_BYTES: usize = kib(256);
const DEFAULT_GLOBAL_BYTES: usize = mib(16);
const GLOBAL_FILL_FLOWS: usize = 64;
const DATAGRAMS_PER_FILL_FLOW: usize = 4;
const PER_FLOW_TAIL_BYTES: usize =
    DEFAULT_PER_FLOW_BYTES - DATAGRAMS_PER_FILL_FLOW * MAX_UDP_DATAGRAM;
const ACK_TEST_PROBE_LEASE: Duration = Duration::from_millis(500);
const ACK_TEST_NEGATIVE_WINDOW: Duration = Duration::from_millis(50);

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
async fn ffi_contract_udp_global_budget_probe_ack_and_cleanup() {
    let env = setup_env().await;
    // A 500 ms production-path lease leaves a 10x margin around the 50 ms
    // negative observations below. The default remains 10 ms; this test uses
    // the example's public JSON override so correctness does not depend on a
    // 2/5 ms scheduler race on a loaded CI host.
    let engine =
        engine_with_udp_ingress_probe_lease_ms(Some(ACK_TEST_PROBE_LEASE.as_millis() as u64));
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
    // Apple read in production order: ACK the exact read completion before
    // submitting its owner datagram, and prove the normal example service
    // returns the exact payload with its real peer.
    let stale_probe_id = probe_id.checked_add(1).unwrap_or(probe_id - 1);
    stalled.acknowledge_client_read(stale_probe_id);
    stalled.acknowledge_client_read(probe_id);
    let recovery_payload = b"global pressure recovered";
    let delivered_probe_id = stalled.send_client_datagram(recovery_payload, Some(remote));
    assert_eq!(delivered_probe_id, probe_id);
    // An already-ACKed ID is stale too and must remain a harmless no-op.
    stalled.acknowledge_client_read(delivered_probe_id);

    let response = stalled.recv_server_datagram().await;
    assert_eq!(response.payload, b"GLOBAL PRESSURE RECOVERED");
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
            .wait_for_probe_read_demand_before(ACK_TEST_NEGATIVE_WINDOW)
            .await
            .is_none(),
        "wrong-session ACK advanced downstream global capacity"
    );

    // An exact ACK records read completion but deliberately keeps its charged
    // lease until that owner's payload arrives. ACK-only release would let a
    // client manufacture unbounded uncharged ingress between callback and
    // delivery, so prove it cannot advance verifier 4 by itself.
    verifiers[0].acknowledge_client_read(initial_probes[0].0);
    assert!(
        verifiers[4]
            .wait_for_probe_read_demand_before(ACK_TEST_NEGATIVE_WINDOW)
            .await
            .is_none(),
        "exact ACK released charged credit before the owning payload arrived"
    );

    // Activate the owner so the real example service consumes the payload and
    // releases its retained charge. This ACK -> owner payload -> service drain
    // chain is the production contract that frees a slot for the next FIFO
    // waiter. Callback-entry time, not waiter wake time, proves the fifth probe
    // was causally released before the 500 ms expiry backstop.
    verifiers[0].activate();
    let owner_payload = b"verifier zero owns this lease";
    assert_eq!(
        verifiers[0].send_client_datagram(owner_payload, Some(remote)),
        initial_probes[0].0
    );
    let owner_response = verifiers[0].recv_server_datagram().await;
    assert_eq!(owner_response.payload, b"VERIFIER ZERO OWNS THIS LEASE");
    let fifth_probe = verifiers[4].wait_for_probe_read_demand_observed().await;
    assert!(
        fifth_probe.1.duration_since(initial_probes[0].1) < ACK_TEST_PROBE_LEASE,
        "fifth probe was released by lease expiry instead of ACK + owner payload consumption"
    );

    // Verifier 0's ID is now stale. It cannot release another slot; a different
    // flow's still-live exact ACK plus owning payload must advance verifier 5.
    verifiers[0].acknowledge_client_read(initial_probes[0].0);
    assert!(
        verifiers[5]
            .wait_for_probe_read_demand_before(ACK_TEST_NEGATIVE_WINDOW)
            .await
            .is_none(),
        "stale ACK advanced downstream global capacity"
    );
    verifiers[1].acknowledge_client_read(initial_probes[1].0);
    verifiers[1].activate();
    let second_owner_payload = b"verifier one owns this lease";
    assert_eq!(
        verifiers[1].send_client_datagram(second_owner_payload, Some(remote)),
        initial_probes[1].0
    );
    let second_owner_response = verifiers[1].recv_server_datagram().await;
    assert_eq!(
        second_owner_response.payload,
        b"VERIFIER ONE OWNS THIS LEASE"
    );
    let sixth_probe = verifiers[5].wait_for_probe_read_demand_observed().await;
    assert!(
        sixth_probe.1.duration_since(initial_probes[1].1) < ACK_TEST_PROBE_LEASE,
        "sixth probe was released by lease expiry instead of the second exact ACK + payload"
    );

    for session in &mut refill {
        session.assert_no_callbacks_queued();
    }
    close_udp_sessions(verifiers);
    close_udp_sessions(refill);

    // The same engine remains usable after both complete pressure cycles.
    let response = udp_roundtrip(engine, remote, b"post pressure canary").await;
    assert_eq!(response, b"POST PRESSURE CANARY");
}

#[tokio::test]
#[serial]
async fn ffi_contract_udp_rejects_owner_payload_before_exact_ack() {
    let env = setup_env().await;
    let engine =
        engine_with_udp_ingress_probe_lease_ms(Some(ACK_TEST_PROBE_LEASE.as_millis() as u64));
    let remote = localhost(env.ports.udp);
    let mut fillers = fill_default_global_budget(&engine, remote);
    let blocked_payload = vec![b'p'; MAX_UDP_DATAGRAM];
    let mut verifiers = (0..5)
        .map(|_| {
            let session = UdpFfiSession::new(engine.clone(), remote);
            session.stage_client_datagram_before_activation(&blocked_payload, Some(remote));
            session
        })
        .collect::<Vec<_>>();

    fillers.remove(0).close_from_client_and_assert(1);
    let mut initial_probes = Vec::with_capacity(4);
    for verifier in verifiers.iter_mut().take(4) {
        initial_probes.push(verifier.wait_for_probe_read_demand().await);
    }
    assert!(initial_probes.iter().all(|probe_id| *probe_id != 0));

    verifiers[0].activate();
    assert_eq!(
        verifiers[0].send_client_datagram(b"must wait for exact ack", Some(remote)),
        initial_probes[0]
    );
    assert!(
        tokio::time::timeout(
            ACK_TEST_NEGATIVE_WINDOW,
            verifiers[0].recv_server_datagram()
        )
        .await
        .is_err(),
        "pre-ACK owner payload crossed the real UDP ABI into the service"
    );
    assert!(
        verifiers[4]
            .wait_for_probe_read_demand_before(ACK_TEST_NEGATIVE_WINDOW)
            .await
            .is_none(),
        "pre-ACK delivery consumed/released the lease and advanced downstream capacity"
    );

    close_udp_sessions(verifiers);
    close_udp_sessions(fillers);
}

/// Real C-ABI scale gate for the documented unbounded-live-flow population.
/// Every session first joins the engine's FIFO global-pressure coordinator;
/// after one fill flow is released, the coordinator must autonomously pace all
/// 8,192 sessions without test-side ACKs or manual kicks. Inactive sessions do
/// not allocate kernel sockets, keeping this a task/callback/accounting scale
/// test rather than an FD exhaustion test.
#[tokio::test]
#[serial]
async fn ffi_contract_udp_8192_sessions_admit_coordinate_and_close() {
    const SESSION_COUNT: usize = 8_192;
    const MAX_COORDINATOR_ELAPSED: Duration = Duration::from_secs(90);
    const MAX_CLOSE_ELAPSED: Duration = Duration::from_secs(30);

    let env = setup_env().await;
    let engine = env.engine.clone();
    let remote = localhost(env.ports.udp);
    let mut fillers = fill_default_global_budget(&engine, remote);
    let blocked_payload = vec![b's'; MAX_UDP_DATAGRAM];
    let mut sessions = Vec::with_capacity(SESSION_COUNT);

    for _ in 0..SESSION_COUNT {
        let session = UdpFfiSession::new(engine.clone(), remote);
        session.stage_client_datagram_before_activation(&blocked_payload, Some(remote));
        sessions.push(session);
    }

    let progress_started = Instant::now();
    fillers.remove(0).close_from_client_and_assert(1);
    let mut previous_callback_at = None;
    for (index, session) in sessions.iter_mut().enumerate() {
        let (probe_id, callback_at) = session.wait_for_probe_read_demand_observed().await;
        assert_ne!(probe_id, 0, "session {index} received an ordinary demand");
        if let Some(previous) = previous_callback_at {
            assert!(
                callback_at >= previous,
                "global-pressure callbacks violated FIFO creation order at session {index}"
            );
        }
        previous_callback_at = Some(callback_at);
    }
    assert!(
        progress_started.elapsed() < MAX_COORDINATOR_ELAPSED,
        "automatic coordinator took {:?} to visit {SESSION_COUNT} sessions",
        progress_started.elapsed()
    );

    let close_started = Instant::now();
    close_udp_sessions(sessions);
    close_udp_sessions(fillers);
    assert!(
        close_started.elapsed() < MAX_CLOSE_ELAPSED,
        "closing {SESSION_COUNT} real ABI sessions took {:?}",
        close_started.elapsed()
    );

    let response = udp_roundtrip(engine, remote, b"post 8192 canary").await;
    assert_eq!(response, b"POST 8192 CANARY");
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
