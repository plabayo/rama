//! DATAGRAM against quiche, in both Rama roles. quiche advertises 65536 when datagrams are
//! enabled, from draft-ietf-quic-datagram-01 rather than RFC 9221's 65535, and either value is
//! far above the path budget: here the binding limit is the path. That is the other half of
//! what the aioquic project shows, where the peer's advertised size is small enough to bind.
//!
//! The size boundary and the unsupported-peer case are covered for the Rama client role here.
//! The server-role test covers delivery and support, not the boundary.

mod common;

use common::*;
use rama::{
    quic::{Endpoint, SendDatagramError},
    utils::octets,
};

// The both-ways datagram exchange in both roles moved to `datagram_cases.rs`, where it runs
// from the shared registry. What stays here is the boundary the shared cases do not carry:
// the negotiated size itself, refused one byte over and delivered exactly at it.

/// A datagram of exactly the negotiated size crosses, and one byte more is refused before it
/// is sent. The shared cases carry fixed payloads and so do not reach this boundary.
#[tokio::test]
async fn a_datagram_at_the_negotiated_size_crosses_and_one_byte_more_is_refused() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let (server_addr, accepting) =
        Quiche::bind_server(with_datagrams(quiche_server_config(&identity)), deadline).await;

    let peer = Peer::spawn(async move {
        let mut server = accepting.await;
        server
            .drive_until("the quiche server completes the handshake", deadline, |c| {
                c.is_established()
            })
            .await;
        let arrived = server.read_datagram(octets::kib(64), deadline).await;
        server.send_datagram(&arrived, deadline).await;
        server
            .drive_until("the quiche server sees the connection end", deadline, |c| {
                c.is_closed()
            })
            .await;
    });

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = deadline
        .wait(
            "the rama client connects",
            client
                .connect_with(rama_client_config(&identity), server_addr, "localhost")
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");

    let limit = connection
        .max_datagram_size()
        .expect("the peer offered the extension");
    let refused = connection
        .send_datagram(payload(0x81, limit + 1).into())
        .expect_err("a datagram over the size must not be sent");
    assert_eq!(refused, SendDatagramError::TooLarge, "and it says why");

    let sent = payload(0x82, limit);
    connection
        .send_datagram(sent.clone().into())
        .expect("a datagram at the negotiated size is accepted");
    let back = deadline
        .wait("the echo", connection.read_datagram())
        .await
        .expect("it arrives");
    assert_eq!(back.len(), limit, "the echo is the whole datagram");
    assert_eq!(digest(&back), digest(&sent), "and the same bytes");

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}

/// A peer that never enabled datagrams gets none, and the connection is otherwise usable.
#[tokio::test]
async fn a_peer_that_did_not_negotiate_datagrams_refuses_them() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let (server_addr, accepting) =
        Quiche::bind_server(quiche_server_config(&identity), deadline).await;

    let asked = payload(0x84, octets::kib(4));
    let asked_hash = digest(&asked);
    let peer = Peer::spawn(async move {
        let mut server = accepting.await;
        server
            .drive_until("the quiche server completes the handshake", deadline, |c| {
                c.is_established()
            })
            .await;
        let received = server.read_stream(0, octets::mib(1), deadline).await;
        assert_eq!(digest(&received), asked_hash, "the payload arrived whole");
        server.write_stream(0, &received, deadline).await;
        server
            .drive_until("the quiche server sees the connection end", deadline, |c| {
                c.is_closed()
            })
            .await;
    });

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = deadline
        .wait(
            "the rama client connects",
            client
                .connect_with(rama_client_config(&identity), server_addr, "localhost")
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");

    assert!(
        connection.max_datagram_size().is_none(),
        "there is no size to send to: the peer offered none"
    );
    let refused = connection
        .send_datagram(payload(0x85, 64).into())
        .expect_err("a peer that did not offer the extension must not be sent one");
    assert_eq!(
        refused,
        SendDatagramError::UnsupportedByPeer,
        "and it says why"
    );

    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(&asked))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let heard = deadline
        .wait("the echo", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(digest(&heard), asked_hash, "the payload came back whole");

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}
