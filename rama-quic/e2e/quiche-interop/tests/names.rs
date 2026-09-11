//! What a client connecting to an IPv6 address literal sends, and what identity it checks.
//!
//! RFC 6066 §3 has no SNI for an address literal. The shared `name-absent` case covers this
//! over IPv4; this file keeps the other socket family until that case does.

mod common;

use std::net::SocketAddr;

use common::*;
use rama::{quic::Endpoint, utils::octets};

/// Rama's client connecting to an IPv6 address literal sends no SNI, and the identity it
/// checks is the address in the certificate rather than a name. The shared `name-absent` case
/// covers the same over IPv4; this keeps the other socket family until that case does.
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
