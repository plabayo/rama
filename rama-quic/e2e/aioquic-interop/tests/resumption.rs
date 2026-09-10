//! Resumption and 0-RTT against aioquic. Resumption and early data are separate things here,
//! and the tests keep them separate: one connection resumes and carries early data that the
//! server accepts, another resumes and offers no early data at all.
//!
//! Early data is opt-in in this crate. `TlsOptions::early_data` is `false` by default, so a
//! client built without asking for it resumes and offers nothing, which is the second test.

mod common;

use std::net::SocketAddr;

use common::*;
use rama::{
    quic::{ClientConfig, Endpoint},
    utils::octets,
};

/// An aioquic server that keeps session tickets, ready for two connections.
async fn ticketing_server(identity: &Identity) -> (AioQuic, SocketAddr, Deadline) {
    let deadline = Deadline::of(LIMIT);
    let mut peer = AioQuic::spawn(
        "server",
        &[
            "--cert",
            identity.certificate(),
            "--key",
            identity.key(),
            "--tickets",
            "--connections",
            "2",
        ],
    )
    .await;
    let addr = peer.listening(deadline).await;
    (peer, addr, deadline)
}

/// A first connection that takes a ticket: an exchange after the handshake, which is when the
/// session ticket follows. Whether it arrived is not asserted here; the second connection
/// resuming is what says so.
async fn warmed(
    client: &Endpoint,
    config: ClientConfig,
    addr: SocketAddr,
    peer: &mut AioQuic,
    deadline: Deadline,
) {
    let connection = deadline
        .wait(
            "the first attempt",
            client
                .connect_with(config, addr, "localhost")
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");
    let first = peer.expect("handshake", deadline).await;
    assert!(!first.resumed(), "the first connection is not a resumption");
    assert!(!first.early(), "and carries no early data");

    let asked = payload(0xa1, octets::kib(1));
    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(&asked))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let echoed = deadline
        .wait("the echo", recv.read_to_end(STREAM_LIMIT))
        .await
        .expect("it completes");
    assert_eq!(digest(&echoed), digest(&asked), "the exchange completed");
    peer.expect("stream", deadline).await;

    connection.close(0u32.into(), b"done");
    peer.expect("ended", deadline).await;
}

/// A client that asked for early data offers it on the second connection, the server accepts
/// it, and the bytes arrive.
#[tokio::test]
async fn early_data_is_offered_and_accepted() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = ticketing_server(&identity).await;

    // One configuration for both attempts: the ticket lives in its resumption cache.
    let config = rama_client_config_with_early_data(&identity);
    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    warmed(&client, config.clone(), server_addr, &mut peer, deadline).await;

    let attempt = client
        .connect_with(config.clone(), server_addr, "localhost")
        .expect("the attempt starts");
    let (connection, accepted) = attempt
        .into_0rtt()
        .unwrap_or_else(|_| panic!("the client had a ticket and early keys to offer"));

    let early = payload(0xa2, octets::kib(1));
    let mut uni = deadline
        .wait("an early uni stream", connection.open_uni())
        .await
        .expect("it opens");
    deadline
        .wait("writing early", uni.write_all(&early))
        .await
        .expect("it is written");
    uni.finish().expect("the early stream ends");

    assert!(
        deadline
            .wait("the 0-RTT verdict", accepted)
            .await
            .expect("the handshake completes"),
        "the client was told its early data was accepted"
    );
    let second = peer.expect("handshake", deadline).await;
    assert!(second.resumed(), "the server resumed the session");
    assert!(second.early(), "and accepted the early data");

    let reported = peer.expect("stream", deadline).await;
    assert_eq!(
        reported.len(),
        early.len(),
        "the early payload arrived whole"
    );
    assert_eq!(
        reported.sha256(),
        hex(&digest(&early)),
        "and the same bytes"
    );

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// A client that did not ask for early data still resumes, and offers nothing early. Resuming
/// and sending early data are separate, and only one of them is on by default.
#[tokio::test]
async fn a_client_that_did_not_ask_for_early_data_resumes_without_it() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = ticketing_server(&identity).await;

    let config = rama_client_config(&identity);
    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    warmed(&client, config.clone(), server_addr, &mut peer, deadline).await;

    let attempt = client
        .connect_with(config.clone(), server_addr, "localhost")
        .expect("the attempt starts");
    let connecting = attempt
        .into_0rtt()
        .err()
        .unwrap_or_else(|| panic!("a client that did not ask for early data must offer none"));
    let connection = deadline
        .wait("the second attempt", connecting)
        .await
        .expect("the handshake completes");

    let second = peer.expect("handshake", deadline).await;
    assert!(second.resumed(), "the server resumed the session anyway");
    assert!(!second.early(), "with no early data to accept");

    // And it is an ordinary connection: a full exchange, checked by digest.
    let asked = payload(0xa3, octets::kib(1));
    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(&asked))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let echoed = deadline
        .wait("the echo", recv.read_to_end(STREAM_LIMIT))
        .await
        .expect("it completes");
    assert_eq!(
        digest(&echoed),
        digest(&asked),
        "the payload came back whole"
    );
    peer.expect("stream", deadline).await;

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}
