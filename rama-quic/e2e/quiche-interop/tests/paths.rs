//! Moving a connection.
//!
//! `Endpoint::rebind` documents when an existing connection follows the endpoint to its new
//! socket: a confirmed client migrates once it holds an unused destination connection
//! identifier and the peer allows active migration, and otherwise keeps sending from the socket
//! it is on. All three of those outcomes are here, along with the other role, a peer that moves
//! itself under a Rama server.
//!
//! quiche issues connection identifiers only when the application asks it to, so each test says
//! what it offered.

mod common;

use std::net::SocketAddr;

use common::*;
use rama::{
    quic::{Connection, ConnectionError, Endpoint},
    udp::UdpSocketConfig,
    utils::octets,
};
use tokio::sync::oneshot;

/// What the peer is asked to allow, and what it is given to move to.
struct Offer {
    identifier: bool,
    migration_allowed: bool,
    moves: bool,
}

#[tokio::test]
async fn a_rebind_moves_the_connection_when_the_peer_offered_an_identifier() {
    rebinding(Offer {
        identifier: true,
        migration_allowed: true,
        moves: true,
    })
    .await;
}

#[tokio::test]
async fn a_rebind_leaves_the_connection_where_it_was_without_an_identifier() {
    rebinding(Offer {
        identifier: false,
        migration_allowed: true,
        moves: false,
    })
    .await;
}

#[tokio::test]
async fn a_rebind_leaves_the_connection_where_it_was_when_the_peer_forbids_migration() {
    rebinding(Offer {
        identifier: true,
        migration_allowed: false,
        moves: false,
    })
    .await;
}

async fn rebinding(offer: Offer) {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let config = if offer.migration_allowed {
        quiche_server_config(&identity)
    } else {
        quiche_server_config_without_migration(&identity)
    };
    let (server_addr, accepting) = Quiche::bind_server(config, deadline).await;

    let before = payload(0x91, octets::kib(1));
    let after = payload(0x92, octets::kib(1));
    let (before_hash, after_hash) = (digest(&before), digest(&after));

    let (moved, has_moved) = oneshot::channel();
    let peer = Peer::spawn(async move {
        let mut server = accepting.await;
        server
            .drive_until("the handshake", deadline, |c| c.is_established())
            .await;
        if offer.identifier {
            server.offer_another_identifier(0x77, deadline).await;
        }

        let first = server.read_stream(0, octets::mib(1), deadline).await;
        assert_eq!(
            digest(&first),
            before_hash,
            "the first payload arrived whole"
        );
        server.write_stream(0, &first, deadline).await;
        let from_before = server.last_seen_from().expect("a datagram arrived");

        let second = server.read_stream(4, octets::mib(1), deadline).await;
        assert_eq!(
            digest(&second),
            after_hash,
            "the second payload arrived whole"
        );
        server.write_stream(4, &second, deadline).await;
        let from_after = server.last_seen_from().expect("a datagram arrived");

        moved
            .send((from_before, from_after))
            .expect("the test is listening");

        server
            .drive_until("the client closes", deadline, |c| c.peer_error().is_some())
            .await;
        let ended = server
            .connection()
            .peer_error()
            .expect("the client stated why it stopped")
            .clone();
        assert!(ended.is_app, "an application close, not a transport one");
        assert_eq!(ended.error_code, 0, "with the code the client gave");
        assert_eq!(ended.reason, b"done", "and its reason");
    });

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let bound_first = client.local_addr().expect("its address");
    let connection = deadline
        .wait(
            "the rama client connects",
            client
                .connect_with(rama_client_config(&identity), server_addr, "localhost")
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");

    exchange(&connection, &before, deadline).await;

    deadline
        .wait(
            "the client rebinds",
            client.rebind(localhost(), UdpSocketConfig::new()),
        )
        .await
        .expect("it rebinds");
    let bound_after = client.local_addr().expect("its address");
    assert_ne!(bound_first, bound_after, "the endpoint is on a new socket");

    // The application carries on across the rebind either way.
    exchange(&connection, &after, deadline).await;

    connection.close(0u32.into(), b"done");
    let (from_before, from_after) = deadline
        .wait("the peer says where the datagrams came from", has_moved)
        .await
        .expect("it said");
    assert_eq!(
        from_before, bound_first,
        "the peer saw the socket the connection was made on"
    );
    if offer.moves {
        assert_eq!(
            from_after, bound_after,
            "and afterwards the one it rebound to"
        );
    } else {
        assert_eq!(
            from_after, bound_first,
            "and afterwards the same one, since it could not move"
        );
    }

    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}

/// One bidirectional exchange, checked by digest.
async fn exchange(connection: &Connection, payload: &[u8], deadline: Deadline) {
    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(payload))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let heard = deadline
        .wait("the echo", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(
        digest(&heard),
        digest(payload),
        "the payload came back whole"
    );
}

/// The other role: the peer moves and Rama serves it. quiche migrates its own source address,
/// and Rama's server follows the connection to it while the application carries on.
#[tokio::test]
async fn a_rama_server_follows_a_client_that_moves() {
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

    let before = payload(0x93, octets::kib(1));
    let after = payload(0x94, octets::kib(1));
    let (before_hash, after_hash) = (digest(&before), digest(&after));

    let (first_seen, is_first_seen) = oneshot::channel();
    let (both_seen, are_both_seen) = oneshot::channel();
    let served = Peer::spawn({
        let server = server.clone();
        async move {
            let connection = accept_one("the rama server", &server, deadline).await;
            let seen_before = read_and_echo(&connection, before_hash, deadline).await;
            first_seen.send(seen_before).expect("the test is listening");
            let seen_after = read_and_echo(&connection, after_hash, deadline).await;
            both_seen
                .send((seen_before, seen_after))
                .expect("the test is listening");

            let ended = deadline
                .wait("the connection ends", connection.closed())
                .await;
            let ConnectionError::ApplicationClosed(ref close) = ended else {
                panic!("the client closed the connection: {ended:?}");
            };
            assert_eq!(close.error_code(), 0u32.into(), "with the code it gave");
            assert_eq!(close.reason(), b"done", "and its reason");
        }
    });

    let mut peer = Quiche::connect(
        server_addr,
        "localhost",
        quiche_client_config_that_moves(&identity),
        deadline,
    )
    .await;
    peer.drive_until("the quiche client completes the handshake", deadline, |c| {
        c.is_established()
    })
    .await;
    // A move needs spare identifiers on both sides. Rama issues its own; quiche leaves this
    // side's to the application, and wants two: one to keep the current path and one for the
    // path being validated.
    peer.offer_another_identifier(0x88, deadline).await;
    peer.offer_another_identifier(0x89, deadline).await;
    let bound_first = peer.local_address();
    peer.write_stream(0, &before, deadline).await;
    let echoed = peer.read_stream(0, octets::mib(1), deadline).await;
    assert_eq!(digest(&echoed), before_hash, "the first payload came back");
    let seen_before = deadline
        .wait("the server says where it saw the client", is_first_seen)
        .await
        .expect("it said");
    assert_eq!(
        seen_before, bound_first,
        "the server saw the socket the client started on"
    );

    let bound_after = peer.move_to_a_new_socket(deadline).await;
    assert_ne!(bound_first, bound_after, "the client is on a new socket");
    peer.write_stream(4, &after, deadline).await;
    let echoed = peer.read_stream(4, octets::mib(1), deadline).await;
    assert_eq!(digest(&echoed), after_hash, "the second payload came back");

    let (seen_before, seen_after) = deadline
        .wait(
            "the server says where it saw the client both times",
            are_both_seen,
        )
        .await
        .expect("it said");
    assert_eq!(
        seen_before, bound_first,
        "the server saw the socket the client started on"
    );
    assert_eq!(
        seen_after, bound_after,
        "and afterwards the one it moved to"
    );

    peer.close(deadline).await;
    served.join("the rama peer", deadline).await;
}

/// Read one stream, echo it back, and answer where the peer is as Rama sees it.
async fn read_and_echo(
    connection: &Connection,
    expected: [u8; 32],
    deadline: Deadline,
) -> SocketAddr {
    let (mut send, mut recv) = deadline
        .wait("the stream arrives", connection.accept_bi())
        .await
        .expect("it opens");
    let received = deadline
        .wait("reading it", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(digest(&received), expected, "the payload arrived whole");
    deadline
        .wait("echoing it", send.write_all(&received))
        .await
        .expect("it is written");
    send.finish().expect("the echo ends");
    connection.remote_address()
}
