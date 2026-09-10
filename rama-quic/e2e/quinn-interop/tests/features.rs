//! What the transport offers beyond streams, exercised through the public API against the
//! upstream Quinn stack: unreliable datagrams and their limits, exported keying material, a key
//! update with traffic either side of it, and what the handshake settles.

mod common;

use std::time::Duration;

use common::*;
use rama::{
    net::tls::ApplicationProtocol,
    quic::{
        AddressTokenKey, ConnectionStats, DriverStats, Endpoint, EndpointConfig, EndpointStats,
        FrameStats, KEY_MATERIAL_SIZE, PacketQueueStats, ReceiveQueueLimits, SendDatagramError,
        ServerConfig, StatelessResetKey, ValidationTokenConfig,
    },
    udp::UdpSocketConfig,
    utils::octets,
};

/// Datagrams both ways, exactly as sent, and the limits the peers negotiated.
#[tokio::test]
async fn datagrams_cross_both_ways_within_the_negotiated_limit() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let up = payload(0x77, 512);
    let down = payload(0x88, 512);
    let (up_hash, down_hash) = (digest(&up), digest(&down));

    let peer = Peer::spawn({
        let down = down.clone();
        async move {
            let conn = step("the quinn server accepts", server.accept())
                .await
                .expect("an attempt arrives")
                .await
                .expect("the handshake completes");
            let heard = step("the quinn server reads a datagram", conn.read_datagram())
                .await
                .expect("a datagram arrives");
            assert_eq!(
                digest(&heard),
                up_hash,
                "the datagram arrived as it was sent"
            );
            conn.send_datagram(down.into()).expect("a datagram is sent");
            step("the quinn connection closes", conn.closed()).await;
            step("the quinn server goes idle", server.wait_idle()).await;
        }
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    let limit = conn
        .max_datagram_size()
        .expect("the peer accepts datagrams");
    assert!(limit >= up.len(), "and one this size fits: {limit}");
    conn.send_datagram(up.clone().into())
        .expect("the datagram is sent");

    let heard = step("the rama client reads a datagram", conn.read_datagram())
        .await
        .expect("a datagram arrives");
    assert_eq!(
        digest(&heard),
        down_hash,
        "the peer's datagram arrived as it was sent"
    );

    // A size no path could carry is refused with `TooLarge`. The limit moves with the path MTU
    // estimate, so this asks for a size beyond every path, not one byte over the limit read a
    // moment ago.
    let refused = conn.send_datagram(payload(0x99, octets::kib(64)).into());
    assert!(
        matches!(refused, Err(SendDatagramError::TooLarge)),
        "a datagram larger than any path could carry is refused: {refused:?}"
    );

    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// A peer that does not accept datagrams: no size to send within, and a send that says so.
#[tokio::test]
async fn a_peer_that_takes_no_datagrams_is_reported_as_such() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let mut config = quinn_server_config(&auth);
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    config.transport_config(std::sync::Arc::new(transport));
    let server = quinn::Endpoint::server(config, localhost()).expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let peer = Peer::spawn(async move {
        let conn = step("the quinn server accepts", server.accept())
            .await
            .expect("an attempt arrives")
            .await
            .expect("the handshake completes");
        step("the quinn connection closes", conn.closed()).await;
        step("the quinn server goes idle", server.wait_idle()).await;
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    assert_eq!(
        conn.max_datagram_size(),
        None,
        "a peer that takes no datagrams has no size to send within"
    );
    let refused = conn.send_datagram(payload(0x11, 32).into());
    assert!(
        matches!(refused, Err(SendDatagramError::UnsupportedByPeer)),
        "and a send says exactly that: {refused:?}"
    );

    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// Both ends derive the same keying material for one label and context. A different context
/// gives different bytes, as does a different label (RFC 8446 §7.5).
#[tokio::test]
async fn both_ends_export_the_same_keying_material() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let (told, heard) = tokio::sync::oneshot::channel::<[u8; 32]>();
    let peer = Peer::spawn(async move {
        let conn = step("the quinn server accepts", server.accept())
            .await
            .expect("an attempt arrives")
            .await
            .expect("the handshake completes");
        let mut theirs = [0u8; 32];
        conn.export_keying_material(&mut theirs, b"rama-interop", b"context")
            .expect("the server exports");
        let _ = told.send(theirs);
        step("the quinn connection closes", conn.closed()).await;
        step("the quinn server goes idle", server.wait_idle()).await;
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    let mut ours = [0u8; 32];
    conn.export_keying_material(&mut ours, b"rama-interop", b"context")
        .expect("the client exports");
    let mut other_context = [0u8; 32];
    conn.export_keying_material(&mut other_context, b"rama-interop", b"another context")
        .expect("the client exports again");
    assert_ne!(
        ours, other_context,
        "a different context gives different material"
    );
    let mut other_label = [0u8; 32];
    conn.export_keying_material(&mut other_label, b"rama-interop-2", b"context")
        .expect("the client exports again");
    assert_ne!(ours, other_label, "so does a different label");

    let theirs = step("the peer's material", heard)
        .await
        .expect("the peer exported");
    assert_eq!(ours, theirs, "both ends derived the same bytes");

    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// Traffic keys updated mid-connection. The first payload is confirmed by the peer before the
/// update is asked for, so what follows it really is on the other side of a key phase, and the
/// connection's own count of key updates has to move: an update that never happened fails this.
#[tokio::test]
async fn a_key_update_does_not_disturb_the_traffic_around_it() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let before = payload(0x21, octets::kib(8));
    let after = payload(0x22, octets::kib(8));
    let (before_hash, after_hash) = (digest(&before), digest(&after));

    let (report, mut seen) = tokio::sync::mpsc::channel::<()>(2);
    let peer = Peer::spawn(async move {
        let incoming = step("the quinn server takes the attempt", server.accept())
            .await
            .expect("an attempt arrives");
        let conn = step(
            "the quinn server completes the handshake",
            incoming.accept().expect("the attempt is accepted"),
        )
        .await
        .expect("the handshake completes");
        for expected in [before_hash, after_hash] {
            let mut uni = step("the quinn server takes a stream", conn.accept_uni())
                .await
                .expect("a stream arrives");
            let heard = step("the quinn server reads it", uni.read_to_end(octets::mib(1)))
                .await
                .expect("it completes");
            assert_eq!(
                digest(&heard),
                expected,
                "the payload arrived as it was sent"
            );
            let _ = report.send(()).await;
        }
        step("the quinn connection closes", conn.closed()).await;
        step("the quinn server goes idle", server.wait_idle()).await;
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    let mut first = step("a stream before the update", conn.open_uni())
        .await
        .expect("a stream");
    step("writing before the update", first.write_all(&before))
        .await
        .expect("it is written");
    first.finish().expect("it ends");
    // The peer has the first payload before the keys change, so the second one is the only
    // traffic on the far side of the update.
    step("the peer has the first payload", seen.recv())
        .await
        .expect("the peer reported it");

    let updates = conn.stats().key_updates;
    assert!(
        conn.force_key_update(),
        "an established connection with no update in flight starts one"
    );
    assert_eq!(
        conn.stats().key_updates,
        updates + 1,
        "the connection counts the update it just made"
    );

    let mut second = step("a stream after the update", conn.open_uni())
        .await
        .expect("a stream");
    step("writing after the update", second.write_all(&after))
        .await
        .expect("it is written");
    second.finish().expect("it ends");

    // The second payload is read before the connection goes; closing first would end that
    // stream and the test would be about the close.
    step("the peer has the second payload", seen.recv())
        .await
        .expect("the peer reported it");
    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// The same exchange with the roles swapped, and with Rama's waiting send: the server answers
/// through `send_datagram_wait`, which waits for buffer space instead of refusing.
#[tokio::test]
async fn datagrams_cross_both_ways_with_rama_as_the_server() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = step(
        "the rama server binds",
        Endpoint::server(rama_server_config(&auth), localhost()),
    )
    .await
    .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let up = payload(0xa1, 512);
    let down = payload(0xb2, 512);
    let (up_hash, down_hash) = (digest(&up), digest(&down));

    let served = Peer::spawn({
        let down = down.clone();
        let server = server.clone();
        async move {
            let incoming = step("the rama server takes the attempt", server.accept())
                .await
                .expect("an attempt arrives");
            let conn = step(
                "the rama server completes the handshake",
                incoming.accept().expect("the attempt is accepted"),
            )
            .await
            .expect("the handshake completes");
            let heard = step("the rama server reads a datagram", conn.read_datagram())
                .await
                .expect("a datagram arrives");
            assert_eq!(
                digest(&heard),
                up_hash,
                "the datagram arrived as it was sent"
            );
            assert!(
                conn.max_datagram_size()
                    .is_some_and(|size| size >= down.len()),
                "the peer takes a datagram this size"
            );
            step(
                "the rama server answers",
                conn.send_datagram_wait(down.into()),
            )
            .await
            .expect("the answer is sent");
            step("the rama connection closes", conn.closed()).await;
        }
    });

    let mut client = quinn::Endpoint::client(localhost()).expect("quinn binds");
    client.set_default_client_config(quinn_client_config(anchor));
    let conn = step(
        "the quinn client connects",
        client
            .connect(server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    conn.send_datagram(up.into()).expect("the datagram is sent");
    let heard = step("the quinn client reads a datagram", conn.read_datagram())
        .await
        .expect("a datagram arrives");
    assert_eq!(
        digest(&heard),
        down_hash,
        "the answer arrived as it was sent"
    );

    conn.close(0u32.into(), b"done");
    step("quinn's shutdown", client.wait_idle()).await;
    served.join("the rama peer").await;
    step("rama's shutdown", server.shutdown()).await;
}

/// A client that names an IP address sends no SNI (RFC 6066 §3), so the server sees none. The
/// protocol is still settled, which distinguishes "no name" from "no handshake data".
#[tokio::test]
async fn a_client_connecting_to_an_address_sends_no_server_name() {
    let auth = address_identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = step(
        "the rama server binds",
        Endpoint::server(rama_server_config(&auth), localhost()),
    )
    .await
    .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let (told, heard) = tokio::sync::oneshot::channel();
    let served = Peer::spawn({
        let server = server.clone();
        async move {
            let incoming = step("the rama server takes the attempt", server.accept())
                .await
                .expect("an attempt arrives");
            let conn = step(
                "the rama server completes the handshake",
                incoming.accept().expect("the attempt is accepted"),
            )
            .await
            .expect("the handshake completes");
            let settled = conn
                .handshake_data()
                .expect("the handshake settled something");
            let _ = told.send(settled);
            step("the rama connection closes", conn.closed()).await;
        }
    });

    // The identity is valid for the loopback address, so naming the address verifies.
    let mut client = quinn::Endpoint::client(localhost()).expect("quinn binds");
    client.set_default_client_config(quinn_client_config(anchor));
    let conn = step(
        "the quinn client connects to an address",
        client
            .connect(server_addr, "127.0.0.1")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    let settled = step("what the server saw", heard)
        .await
        .expect("the server reported it");
    assert_eq!(
        settled.server_name, None,
        "a client naming an address sends no server name"
    );
    assert_eq!(
        settled.protocol,
        Some(ApplicationProtocol::from(ALPN)),
        "and the protocol is settled all the same"
    );

    conn.close(0u32.into(), b"done");
    step("quinn's shutdown", client.wait_idle()).await;
    served.join("the rama peer").await;
    step("rama's shutdown", server.shutdown()).await;
}

/// The counters a connection publishes, read the way a consumer of the crate reads them: each
/// snapshot held in the public type that names it, and every field reached by name.
#[tokio::test]
async fn a_consumer_reads_the_counters_through_their_public_types() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let up = payload(0x5a, octets::kib(32));
    let up_hash = digest(&up);
    let peer = Peer::spawn(async move {
        let conn = step("the quinn server accepts", server.accept())
            .await
            .expect("an attempt arrives")
            .await
            .expect("the handshake completes");
        let mut stream = step("the stream arrives", conn.accept_uni())
            .await
            .expect("it opens");
        let received = step("the payload", stream.read_to_end(octets::mib(1)))
            .await
            .expect("it is read whole");
        assert_eq!(digest(&received), up_hash, "every byte, unchanged");
        step("the quinn connection closes", conn.closed()).await;
        step("the quinn server goes idle", server.wait_idle()).await;
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");
    let mut stream = step("the stream opens", conn.open_uni())
        .await
        .expect("it opens");
    step("the payload is written", stream.write_all(&up))
        .await
        .expect("it is written");
    stream.finish().expect("the stream is finished");
    step("the peer has it", stream.stopped())
        .await
        .expect("the peer did not reset it");

    let stats: ConnectionStats = conn.stats();
    let sent: FrameStats = stats.frame_tx;
    let received: FrameStats = stats.frame_rx;
    assert!(sent.stream > 0, "stream frames were sent for the payload");
    assert!(sent.crypto > 0, "and crypto frames for the handshake");
    assert!(received.acks > 0, "the peer acknowledged them");
    assert!(
        stats.udp_tx.datagrams > 0 && stats.udp_rx.datagrams > 0,
        "datagrams crossed in both directions"
    );

    let driver: DriverStats = conn.driver_stats();
    let queue: PacketQueueStats = driver.receive_queue;
    assert_eq!(
        queue.dropped_datagrams, 0,
        "nothing was refused for want of room"
    );
    assert!(
        queue.peak_datagrams >= queue.queued_datagrams && queue.peak_bytes >= queue.queued_bytes,
        "the peaks stand at or above what is held now: {queue:?}"
    );
    assert!(
        queue.peak_datagrams > 0 && queue.peak_bytes > 0,
        "and the queue did hold something along the way: {queue:?}"
    );
    assert!(
        driver.receive_queue_capacity > 0,
        "the queue keeps storage for entries"
    );
    assert_eq!(
        driver.send_failures, 0,
        "the socket took every datagram offered"
    );
    assert_eq!(driver.oversized_sends, 0, "and none was too large for it");

    let endpoint: EndpointStats = client.stats();
    let endpoint_queue: PacketQueueStats = endpoint.receive_queue;
    assert_eq!(
        endpoint_queue.dropped_datagrams, 0,
        "the endpoint-wide budget refused nothing either"
    );
    assert!(
        endpoint_queue.peak_bytes >= endpoint_queue.queued_bytes,
        "and its peak stands at or above what is held now: {endpoint_queue:?}"
    );
    assert_eq!(
        endpoint.outgoing_handshakes, 1,
        "one handshake left this endpoint"
    );

    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// The configuration a consumer of the crate reaches for when it runs more than one endpoint:
/// the two key types, the validation-token settings and the receive-queue bounds, all named
/// from outside and all installed through the public setters before a peer connects.
#[tokio::test]
async fn a_consumer_configures_keys_and_budgets_by_name() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let reset_key: StatelessResetKey = StatelessResetKey::from_seed(&[0x31; KEY_MATERIAL_SIZE]);
    let token_key: AddressTokenKey =
        AddressTokenKey::try_from_bytes(&[0x62; KEY_MATERIAL_SIZE * 2])
            .expect("material of two seeds is long enough");
    assert_eq!(
        format!("{reset_key:?}"),
        "StatelessResetKey",
        "the material is not in the debug output"
    );
    assert!(
        StatelessResetKey::try_from_bytes(&[0x31; KEY_MATERIAL_SIZE - 1]).is_err(),
        "material shorter than a seed is refused"
    );

    let validation: ValidationTokenConfig = ValidationTokenConfig::default()
        .with_lifetime(Duration::from_secs(600))
        .with_sent(3);
    let per_connection = ReceiveQueueLimits::new(64, octets::mib(1)).expect("both are nonzero");
    let per_endpoint = ReceiveQueueLimits::new(1024, octets::mib(8)).expect("both are nonzero");

    let endpoint_config: EndpointConfig = EndpointConfig::default()
        .with_stateless_reset_key(reset_key)
        .with_receive_queue_limits(per_connection, per_endpoint);
    let server_config: ServerConfig = rama_server_config(&auth)
        .with_address_token_key(token_key)
        .with_validation_token_config(validation)
        .with_incoming_buffer_size_total(u64::try_from(octets::mib(32)).expect("it fits"));

    let server = step(
        "the rama server binds with the configuration",
        Endpoint::bind(
            endpoint_config,
            Some(server_config),
            localhost(),
            UdpSocketConfig::default(),
        ),
    )
    .await
    .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let payload = payload(0x9c, octets::kib(8));
    let hash = digest(&payload);
    let (read_it, was_read) = tokio::sync::oneshot::channel::<()>();
    let served = Peer::spawn({
        let server = server.clone();
        async move {
            let conn = step("the rama server accepts", server.accept())
                .await
                .expect("an attempt arrives")
                .accept()
                .expect("it is accepted")
                .await
                .expect("the handshake completes");
            let mut uni = step("the stream arrives", conn.accept_uni())
                .await
                .expect("it opens");
            let received = step("the payload", uni.read_to_end(octets::mib(1)))
                .await
                .expect("it is read whole");
            assert_eq!(digest(&received), hash, "every byte, unchanged");
            let _ = read_it.send(());
            step("the connection closes", conn.closed()).await;
        }
    });

    let mut client = quinn::Endpoint::client(localhost()).expect("quinn binds");
    client.set_default_client_config(quinn_client_config(anchor));
    let conn = step(
        "the quinn client connects",
        client
            .connect(server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");
    let mut stream = step("the stream opens", conn.open_uni())
        .await
        .expect("it opens");
    step("the payload is written", stream.write_all(&payload))
        .await
        .expect("it is written");
    stream.finish().expect("the stream is finished");
    step("the peer read it", was_read)
        .await
        .expect("the peer reported");
    conn.close(0u32.into(), b"done");
    step("quinn's shutdown", client.wait_idle()).await;
    served.join("the rama peer").await;
    step("rama's shutdown", server.shutdown()).await;
}
