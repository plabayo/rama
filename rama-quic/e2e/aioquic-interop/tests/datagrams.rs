//! DATAGRAM against aioquic, in both Rama roles: the negotiated limit, delivery and echo, a
//! peer that never offered the extension, and the local send buffer filling when the transport
//! cannot make progress.

mod common;

use std::{net::SocketAddr, time::Duration};

use common::*;
use rama::{
    quic::{ClientConfig, Connection, Endpoint, SendDatagramError},
    utils::octets,
};

/// The frame size the peer advertises. Small enough that it, and not the path, is what limits a
/// datagram, so the test is about the negotiated value.
const PEER_FRAME: usize = 256;
/// How much of Rama's outgoing datagram buffer these tests allow, so filling it is deliberate.
const SEND_BUFFER: usize = octets::kib(8);

/// An aioquic server advertising `frame` as its datagram frame size, zero meaning it does not
/// offer the extension at all. The deadline starts here, after the environment is ready.
async fn aioquic_server(
    identity: &Identity,
    frame: usize,
    orders: bool,
) -> (AioQuic, SocketAddr, Deadline) {
    let mut arguments = vec![
        "--cert".to_owned(),
        identity.certificate().to_owned(),
        "--key".to_owned(),
        identity.key().to_owned(),
        "--datagram-frame".to_owned(),
        frame.to_string(),
    ];
    if orders {
        arguments.push("--orders".to_owned());
    }
    let deadline = Deadline::new();
    let mut peer = AioQuic::spawn(
        "server",
        &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .await;
    let addr = peer.listening(deadline).await;
    (peer, addr, deadline)
}

/// Connect and take the handshake line the peer writes for it.
async fn connected(
    client: &Endpoint,
    config: ClientConfig,
    addr: SocketAddr,
    peer: &mut AioQuic,
    deadline: Deadline,
) -> Connection {
    let connection = deadline
        .wait(
            "the rama client connects",
            client
                .connect_with(config, addr, "localhost")
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");
    peer.expect("handshake", deadline).await;
    connection
}

/// A datagram at the negotiated size goes out, the peer reports the bytes it read, and the echo
/// comes back with the same length and digest.
#[tokio::test]
async fn a_rama_client_sends_and_receives_datagrams() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = aioquic_server(&identity, PEER_FRAME, false).await;

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = connected(
        &client,
        rama_client_config(&identity),
        server_addr,
        &mut peer,
        deadline,
    )
    .await;

    let limit = connection
        .max_datagram_size()
        .expect("the peer offered the extension");
    assert!(
        limit <= PEER_FRAME,
        "the negotiated size fits in the frame the peer advertised: {limit} against {PEER_FRAME}"
    );

    let sent = payload(0x71, limit);
    connection
        .send_datagram(sent.clone().into())
        .expect("a datagram at the negotiated size is accepted");

    let seen = peer.expect("datagram", deadline).await;
    assert_eq!(seen.len(), limit, "the peer read the whole datagram");
    assert_eq!(seen.sha256(), hex(&digest(&sent)), "and the same bytes");

    let back = deadline
        .wait("the echo", connection.read_datagram())
        .await
        .expect("it arrives");
    assert_eq!(back.len(), limit, "the echo is the whole datagram");
    assert_eq!(digest(&back), digest(&sent), "and the same bytes again");

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// The same, with Rama serving: the peer's client sends, Rama reads and echoes, and the peer
/// reports the echo it received.
#[tokio::test]
async fn a_rama_server_sends_and_receives_datagrams() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let deadline = Deadline::new();
    let server = deadline
        .wait(
            "the rama server binds",
            Endpoint::server(rama_server_config(&identity), localhost()),
        )
        .await
        .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let sent = payload(0x41, PEER_FRAME / 2);
    let sent_hash = digest(&sent);

    let served = Task::spawn({
        let server = server.clone();
        async move {
            let connection = accept_one("the rama server", &server, deadline).await;
            let limit = connection
                .max_datagram_size()
                .expect("the peer offered the extension");
            assert!(
                limit <= PEER_FRAME,
                "the negotiated size fits in the frame the peer advertised: {limit}"
            );
            let arrived = deadline
                .wait("the datagram arrives", connection.read_datagram())
                .await
                .expect("it arrives");
            assert_eq!(digest(&arrived), sent_hash, "it arrived whole");
            connection
                .send_datagram(arrived)
                .expect("the echo is accepted");
            deadline
                .wait("the connection ends", connection.closed())
                .await;
        }
    });

    let mut peer = AioQuic::spawn(
        "client",
        &[
            "--port",
            &server_addr.port().to_string(),
            "--ca",
            identity.certificate(),
            "--seed",
            "65",
            "--length",
            &sent.len().to_string(),
            "--datagram-frame",
            &PEER_FRAME.to_string(),
            "--datagrams",
            "1",
            "--streams",
            "0",
        ],
    )
    .await;
    peer.expect("handshake", deadline).await;
    peer.expect("connected", deadline).await;
    let echoed = peer.expect("datagram", deadline).await;
    assert_eq!(echoed.len(), sent.len(), "the echo is the whole datagram");
    assert_eq!(echoed.sha256(), hex(&sent_hash), "and the same bytes");
    peer.expect("ended", deadline).await;
    peer.expect("done", deadline).await;
    peer.finished(deadline).await;
    served.join("the rama peer", deadline).await;
}

/// One byte over the negotiated size is refused rather than truncated, and the size itself is
/// still carried, echo and all.
#[tokio::test]
async fn a_datagram_over_the_negotiated_size_is_refused() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = aioquic_server(&identity, PEER_FRAME, false).await;

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = connected(
        &client,
        rama_client_config(&identity),
        server_addr,
        &mut peer,
        deadline,
    )
    .await;

    let limit = connection
        .max_datagram_size()
        .expect("the peer offered the extension");
    let refused = connection
        .send_datagram(payload(0x72, limit + 1).into())
        .expect_err("a datagram over the size must not be sent");
    assert_eq!(refused, SendDatagramError::TooLarge, "and it says why");

    let allowed = payload(0x73, limit);
    connection
        .send_datagram(allowed.clone().into())
        .expect("a datagram at the size is accepted");
    let seen = peer.expect("datagram", deadline).await;
    assert_eq!(seen.len(), limit, "the peer read the whole datagram");
    assert_eq!(seen.sha256(), hex(&digest(&allowed)), "and the same bytes");
    let back = deadline
        .wait("the echo", connection.read_datagram())
        .await
        .expect("it arrives");
    assert_eq!(
        digest(&back),
        digest(&allowed),
        "and the echo is those bytes"
    );

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// A peer that never advertised the extension gets no datagrams at all, and the connection is
/// otherwise entirely usable.
#[tokio::test]
async fn a_peer_that_did_not_negotiate_datagrams_refuses_them() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = aioquic_server(&identity, 0, false).await;

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = connected(
        &client,
        rama_client_config(&identity),
        server_addr,
        &mut peer,
        deadline,
    )
    .await;

    assert!(
        connection.max_datagram_size().is_none(),
        "there is no size to send to: the peer offered none"
    );
    let refused = connection
        .send_datagram(payload(0x74, 64).into())
        .expect_err("a peer that did not offer the extension must not be sent one");
    assert_eq!(
        refused,
        SendDatagramError::UnsupportedByPeer,
        "and it says why"
    );

    // A full exchange, checked by digest in both directions: what is missing is the extension
    // and not the connection.
    let asked = payload(0x75, octets::kib(4));
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
        .wait("the echo", recv.read_to_end(STREAM_LIMIT))
        .await
        .expect("it completes");
    assert_eq!(
        digest(&heard),
        digest(&asked),
        "the payload came back whole"
    );
    let reported = peer.expect("stream", deadline).await;
    assert_eq!(
        reported.len(),
        asked.len(),
        "the peer read the whole stream"
    );
    assert_eq!(
        reported.sha256(),
        hex(&digest(&asked)),
        "and the same bytes"
    );

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// Backpressure is local. A peer that stops reading its socket stops acknowledging, so the
/// transport cannot make progress and Rama's own outgoing datagram buffer fills; that is what
/// `send_datagram_wait` waits for. The buffer is set small here so filling it is deliberate
/// rather than a matter of volume, and the wait is judged by the buffer having no room, not by
/// how long a future took to resolve.
#[tokio::test]
async fn a_send_with_no_room_waits_and_can_be_cancelled() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = aioquic_server(&identity, PEER_FRAME, true).await;

    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let connection = connected(
        &client,
        rama_client_config_with_datagram_buffer(&identity, SEND_BUFFER),
        server_addr,
        &mut peer,
        deadline,
    )
    .await;
    let limit = connection
        .max_datagram_size()
        .expect("the peer offered the extension");

    // Deaf at the socket: nothing is acknowledged, so the transport stops making progress and
    // the outgoing buffer stops draining.
    peer.tell("deaf", deadline).await;

    // Every attempt carries a payload of its own, so the one that ends up waiting is
    // identifiable and the ones that were taken are not confused with it. The sequence is
    // bounded, and running out of it fails the test rather than repeating a payload.
    const ATTEMPTS: usize = 4096;
    let attempt = |number: usize| {
        assert!(
            number < ATTEMPTS,
            "the buffer took {number} datagrams without filling"
        );
        let mut bytes = payload(0x76, limit);
        bytes[0..2].copy_from_slice(&u16::try_from(number).expect("it fits").to_be_bytes());
        bytes
    };

    let mut queued = 0usize;
    let cancelled = deadline
        .wait("filling until a send has no room", async {
            loop {
                let bytes = attempt(queued);
                let mut sending = Box::pin(connection.send_datagram_wait(bytes.clone().into()));
                match tokio::time::timeout(Duration::from_millis(200), &mut sending).await {
                    Ok(Ok(())) => queued += 1,
                    Ok(Err(error)) => panic!("the connection failed while filling: {error}"),
                    Err(_) => {
                        // Still pending, and `sending` is still alive here: the buffer having no
                        // room for this datagram is why. Returning drops it, which is the
                        // cancellation.
                        assert!(
                            connection.datagram_send_buffer_space() < bytes.len(),
                            "the send is waiting for room, not for a wakeup"
                        );
                        return bytes;
                    }
                }
            }
        })
        .await;
    assert!(queued > 0, "the buffer took datagrams before it filled");
    assert!(
        connection.datagram_send_buffer_space() < cancelled.len(),
        "and there is still no room now the wait has been cancelled"
    );

    // Hearing again, the transport drains and the connection is usable in both shapes.
    peer.tell("hear", deadline).await;
    let after = attempt(queued + 1);
    deadline
        .wait(
            "a datagram after the stall",
            connection.send_datagram_wait(after.clone().into()),
        )
        .await
        .expect("it is accepted once there is room");

    // Everything the peer reports is read, so its output cannot back up behind this test, and
    // the cancelled datagram must not be among it. The one sent after the stall goes out last.
    let (cancelled_hash, after_hash) = (hex(&digest(&cancelled)), hex(&digest(&after)));
    let mut seen = 0usize;
    loop {
        let reported = peer.expect("datagram", deadline).await;
        seen += 1;
        assert_ne!(
            reported.sha256(),
            cancelled_hash,
            "the cancelled datagram was never enqueued"
        );
        if reported.sha256() == after_hash {
            break;
        }
        assert!(
            seen <= queued + 1,
            "the peer reported more datagrams than were ever queued"
        );
    }

    let asked = payload(0x79, octets::kib(4));
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
        .wait("the echo", recv.read_to_end(STREAM_LIMIT))
        .await
        .expect("it completes");
    assert_eq!(digest(&heard), digest(&asked), "a stream completes as well");
    peer.expect("stream", deadline).await;

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}
