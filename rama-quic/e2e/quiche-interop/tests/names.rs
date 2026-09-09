//! What the server is asked for, and what it reports. RFC 6066 §3 has no SNI for an address
//! literal, so a client connecting to an IP sends none, and a server that received none must
//! say so rather than say the name failed to parse.

mod common;

use std::net::SocketAddr;

use common::*;
use rama::{
    net::address::Domain,
    quic::{ConnectionError, Endpoint, ReceivedServerName},
    utils::octets,
};

/// A quiche client that asks for `localhost` is reported by the Rama server as a domain.
#[tokio::test]
async fn a_name_the_client_asked_for_is_reported_as_a_domain() {
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
            let summary = connection
                .handshake_data()
                .expect("the handshake settled something");
            assert_eq!(
                summary.server_name,
                Some(ReceivedServerName::Domain(Domain::from_static("localhost"))),
                "the name the client asked for, as a domain"
            );
            assert_eq!(
                summary.protocol.as_ref().map(|p| p.as_bytes()),
                Some(ALPN),
                "and the protocol they agreed on"
            );
            deadline
                .wait("the connection ends", connection.closed())
                .await;
        }
    });

    let mut peer = Quiche::connect(
        server_addr,
        "localhost",
        quiche_client_config(&identity),
        deadline,
    )
    .await;
    peer.drive_until("the quiche client completes the handshake", deadline, |c| {
        c.is_established()
    })
    .await;
    peer.close(deadline).await;
    served.join("the rama peer", deadline).await;
}

/// A client that asks for no name at all is reported as having sent none, which is a different
/// answer from a name that could not be read.
#[tokio::test]
async fn a_client_that_asked_for_no_name_is_reported_as_absent() {
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
            let summary = connection
                .handshake_data()
                .expect("the handshake settled something");
            assert_eq!(
                summary.server_name, None,
                "no name was sent, so none is reported"
            );
            deadline
                .wait("the connection ends", connection.closed())
                .await;
        }
    });

    let mut peer =
        Quiche::connect_without_a_name(server_addr, quiche_client_config(&identity), deadline)
            .await;
    peer.drive_until("the quiche client completes the handshake", deadline, |c| {
        c.is_established()
    })
    .await;
    peer.close(deadline).await;
    served.join("the rama peer", deadline).await;
}

/// Rama's client connecting to an address literal sends no SNI, and the identity it checks is
/// the address in the certificate rather than a name. The family of the socket is a separate
/// matter from the shape of the name, so this runs over both.
#[tokio::test]
async fn a_rama_client_connecting_to_an_address_sends_no_name() {
    connecting_to_an_address("127.0.0.1", localhost()).await;
}

#[tokio::test]
async fn a_rama_client_connecting_to_an_ipv6_address_sends_no_name() {
    connecting_to_an_address("::1", localhost_v6()).await;
}

async fn connecting_to_an_address(address: &str, bind: SocketAddr) {
    let deadline = Deadline::new();
    let identity = Identity::generate(address);
    let (server_addr, accepting) =
        Quiche::bind_server_on(bind, quiche_server_config(&identity), deadline).await;

    let asked = payload(0xd1, octets::kib(1));
    let asked_hash = digest(&asked);
    let peer = Peer::spawn(async move {
        let mut server = accepting.await;
        server
            .drive_until("the quiche server completes the handshake", deadline, |c| {
                c.is_established()
            })
            .await;
        assert_eq!(
            server.connection().server_name(),
            None,
            "a client connecting to an address sends no name"
        );
        let received = server.read_stream(0, octets::mib(1), deadline).await;
        assert_eq!(
            digest(&received),
            asked_hash,
            "and the payload arrived whole"
        );
        server.write_stream(0, &received, deadline).await;
        server
            .drive_until("the connection ends", deadline, |c| {
                c.peer_error().is_some() || c.is_closed()
            })
            .await;
    });

    let client = deadline
        .wait("rama binds", Endpoint::client(bind))
        .await
        .expect("the client binds");
    let connection = deadline
        .wait(
            "the rama client connects",
            client
                .connect_with(rama_client_config(&identity), server_addr, address)
                .expect("the attempt starts"),
        )
        .await
        .expect("the address in the certificate is the identity it checks");

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

/// A certificate the client trusts, for an identity that is not the one it asked for. The
/// matching controls are the tests above; this is the same shape with the identity changed, so
/// what it shows is that the identity is checked and not the chain alone.
async fn refusing_a_mismatched_identity(certificate_for: &str, asked_for: &str, bind: SocketAddr) {
    let deadline = Deadline::new();
    let identity = Identity::generate(certificate_for);
    let (server_addr, accepting) =
        Quiche::bind_server_on(bind, quiche_server_config(&identity), deadline).await;

    let peer = Peer::spawn(async move {
        let mut server = accepting.await;
        // Answered to its end, so what stops the client is the check and not silence.
        server
            .drive_or_stop("the refused attempt ends", deadline, |c| {
                c.peer_error().is_some() || c.is_closed()
            })
            .await;
        assert!(
            !server.connection().is_established(),
            "an identity the client does not accept must not get a connection"
        );
    });

    let client = deadline
        .wait("rama binds", Endpoint::client(bind))
        .await
        .expect("the client binds");
    let refused = deadline
        .wait(
            "the attempt",
            client
                .connect_with(rama_client_config(&identity), server_addr, asked_for)
                .expect("the attempt starts"),
        )
        .await
        .expect_err("a certificate for another identity must not be accepted");
    assert!(
        matches!(refused, ConnectionError::TransportError(_)),
        "the attempt ended on a transport error: {refused:?}"
    );
    // The code and cause of a transport error are not reachable from outside the crate, so the
    // rendered error is what names the check. This becomes a typed check once accessors exist.
    let told = format!("{refused:?}");
    assert!(
        told.contains("NotValidForName"),
        "and the certificate did not cover the name it asked for: {told}"
    );

    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    refusing_a_mismatched_identity("elsewhere.test", "localhost", localhost()).await;
}

#[tokio::test]
async fn a_certificate_for_another_address_is_refused() {
    refusing_a_mismatched_identity("127.0.0.2", "127.0.0.1", localhost()).await;
}
