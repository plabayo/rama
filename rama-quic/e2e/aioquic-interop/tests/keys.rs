//! Key updates against aioquic, asked for from each side in turn. Neither aioquic nor quiche
//! exposes a TLS keying-material exporter, so exporters stay covered against Quinn.

mod common;

use std::{net::SocketAddr, time::Duration};

use common::*;
use rama::{
    quic::{Connection, Endpoint},
    utils::octets,
};

async fn serving(identity: &Identity) -> (AioQuic, SocketAddr, Deadline) {
    let deadline = Deadline::of(LIMIT);
    let mut peer = AioQuic::spawn(
        "server",
        &[
            "--cert",
            identity.certificate(),
            "--key",
            identity.key(),
            "--orders",
        ],
    )
    .await;
    let addr = peer.listening(deadline).await;
    (peer, addr, deadline)
}

/// One exchange, checked by digest on both sides, to carry traffic under whatever keys are
/// current.
async fn exchange(connection: &Connection, peer: &mut AioQuic, seed: u8, deadline: Deadline) {
    let asked = payload(seed, octets::kib(4));
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
        reported.sha256(),
        hex(&digest(&asked)),
        "and the peer read it"
    );
}

/// The key phase the peer is using, which is what says the keys changed rather than only the
/// counter moving.
async fn phase(peer: &mut AioQuic, deadline: Deadline) -> u64 {
    peer.tell("key-phase", deadline).await.phase()
}

/// Rama asks for the update, and traffic continues under the new keys.
#[tokio::test]
async fn rama_can_update_its_keys() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = serving(&identity).await;

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
    peer.expect("handshake", deadline).await;
    exchange(&connection, &mut peer, 0xc1, deadline).await;

    let before = connection.stats().key_updates;
    let phase_before = phase(&mut peer, deadline).await;
    assert!(
        connection.force_key_update(),
        "a confirmed handshake with no update in flight can start one"
    );
    exchange(&connection, &mut peer, 0xc2, deadline).await;
    assert_eq!(
        connection.stats().key_updates,
        before + 1,
        "and the connection counted exactly one"
    );
    assert_ne!(
        phase(&mut peer, deadline).await,
        phase_before,
        "and the peer is using the other key phase, so the keys really changed"
    );

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// The peer asks for the update, and Rama follows it: the count rises on Rama's side too,
/// because it counts updates whichever side asked.
#[tokio::test]
async fn rama_follows_a_key_update_the_peer_asks_for() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = serving(&identity).await;

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
    peer.expect("handshake", deadline).await;
    exchange(&connection, &mut peer, 0xc3, deadline).await;

    let before = connection.stats().key_updates;
    let phase_before = phase(&mut peer, deadline).await;
    peer.tell("update-keys", deadline).await;
    exchange(&connection, &mut peer, 0xc4, deadline).await;

    let counted = deadline
        .wait("the update is counted", async {
            loop {
                let now = connection.stats().key_updates;
                if now > before {
                    return now;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    assert_eq!(counted, before + 1, "exactly one update was counted");
    assert_ne!(
        phase(&mut peer, deadline).await,
        phase_before,
        "and the keys really changed, not only the counter"
    );
    // And the connection still works after it.
    exchange(&connection, &mut peer, 0xc5, deadline).await;

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}

/// The negative control: with no update asked for on either side, the same traffic leaves the
/// counter and the key phase where they were. A test that passed on old-key traffic alone, or a
/// counter that moved without the keys moving, would show up here.
#[tokio::test]
async fn traffic_alone_does_not_update_any_keys() {
    prepare().await;
    let identity = Identity::generate("localhost");
    let (mut peer, server_addr, deadline) = serving(&identity).await;

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
    peer.expect("handshake", deadline).await;

    let before = connection.stats().key_updates;
    let phase_before = phase(&mut peer, deadline).await;
    for seed in [0xc6, 0xc7, 0xc8] {
        exchange(&connection, &mut peer, seed, deadline).await;
    }
    assert_eq!(
        connection.stats().key_updates,
        before,
        "no update was asked for, so none was counted"
    );
    assert_eq!(
        phase(&mut peer, deadline).await,
        phase_before,
        "and the key phase did not move either"
    );

    connection.close(0u32.into(), b"done");
    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.expect("ended", deadline).await;
    peer.finished(deadline).await;
}
