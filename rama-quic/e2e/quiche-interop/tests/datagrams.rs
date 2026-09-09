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

/// Rama's client sends a datagram at the negotiated size, quiche reads it and echoes it, and
/// one byte over that size is refused rather than truncated.
#[tokio::test]
async fn a_rama_client_sends_and_receives_datagrams() {
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

/// The same with Rama serving: quiche's client sends, Rama reads and echoes.
#[tokio::test]
async fn a_rama_server_sends_and_receives_datagrams() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let server = deadline
        .wait(
            "the rama server binds",
            Endpoint::server(rama_server_config(&identity), localhost()),
        )
        .await
        .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let served = Peer::spawn({
        let server = server.clone();
        async move {
            let connection = accept_one("the rama server", &server, deadline).await;
            assert!(
                connection.max_datagram_size().is_some(),
                "the peer offered the extension"
            );
            let arrived = deadline
                .wait("the datagram arrives", connection.read_datagram())
                .await
                .expect("it arrives");
            connection
                .send_datagram(arrived)
                .expect("the echo is accepted");
            deadline
                .wait("the connection ends", connection.closed())
                .await;
        }
    });

    let mut peer = Quiche::connect(
        server_addr,
        "localhost",
        with_datagrams(quiche_client_config(&identity)),
        deadline,
    )
    .await;
    peer.drive_until("the quiche client completes the handshake", deadline, |c| {
        c.is_established()
    })
    .await;

    let sent = payload(0x83, octets::kib(1));
    peer.send_datagram(&sent, deadline).await;
    let back = peer.read_datagram(octets::kib(64), deadline).await;
    assert_eq!(digest(&back), digest(&sent), "the echo came back whole");

    peer.close(deadline).await;
    served.join("the rama peer", deadline).await;
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
