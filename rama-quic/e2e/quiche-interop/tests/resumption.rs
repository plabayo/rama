//! Resumption and 0-RTT against quiche. quiche can be the same resumption authority twice over
//! through `set_ticket_key`, and can accept or refuse early data independently of that, so the
//! three outcomes are told apart here rather than inferred from one another: early data
//! accepted, early data refused while the session still resumes, and the resumption itself
//! refused.

mod common;

use std::net::SocketAddr;

use common::*;
use rama::{
    quic::{ClientConfig, Endpoint, StoppedError},
    utils::octets,
};
use tokio::{net::UdpSocket, sync::oneshot};

/// The stream the refusal scenario ends its exchange on, so the connection is still running
/// while what arrived is counted.
const BARRIER: u64 = 0;

/// The application close every scenario here ends on, so an idle timeout cannot stand in for
/// the client having closed.
fn expect_the_clients_close(server: &mut Quiche) {
    let ended = server
        .connection()
        .peer_error()
        .expect("the client stated why it stopped")
        .clone();
    assert!(ended.is_app, "an application close, not a transport one");
    assert_eq!(ended.error_code, 0, "with the code the client gave");
    assert_eq!(ended.reason, b"done", "and its reason");
}

/// What one accepted connection reported about resumption and early data.
#[derive(Debug)]
struct Seen {
    resumed: bool,
    reason: u32,
    /// Whether a stream became readable before the handshake finished. It is only a firm
    /// observation when the server was kept silent until then, as
    /// [`take_one_watching_for_early_data`] does; a server that answers can finish the
    /// handshake before the application has written anything.
    early_bytes_before_the_handshake: bool,
}

/// Take one connection on an already-bound socket without answering it, so that early data can
/// be observed for what it is: a server that has sent nothing cannot have finished a handshake,
/// so a stream readable while it stays silent arrived on the early keys. Then it answers and
/// the handshake finishes.
async fn take_one_watching_for_early_data(
    socket: UdpSocket,
    config: quiche::Config,
    deadline: Deadline,
) -> (Quiche, Seen) {
    let mut server = Quiche::accept_on_silently(socket, config, deadline).await;
    server
        .receive_until("the early data arrives", deadline, |c| c.stream_readable(2))
        .await;
    let early = !server.connection().is_established();
    server
        .drive_until("the quiche server completes the handshake", deadline, |c| {
            c.is_established()
        })
        .await;
    let seen = Seen {
        resumed: server.connection().is_resumed(),
        reason: server.connection().early_data_reason(),
        early_bytes_before_the_handshake: early,
    };
    (server, seen)
}

/// Take one connection on an already-bound socket, answering it as a server normally would.
async fn take_one(socket: UdpSocket, config: quiche::Config, deadline: Deadline) -> (Quiche, Seen) {
    let mut server = Quiche::accept_on(socket, config, deadline).await;
    let mut early = false;
    server
        .drive_until("the quiche server completes the handshake", deadline, |c| {
            if !c.is_established() && c.stream_readable(2) {
                early = true;
            }
            c.is_established()
        })
        .await;
    let seen = Seen {
        resumed: server.connection().is_resumed(),
        reason: server.connection().early_data_reason(),
        early_bytes_before_the_handshake: early,
    };
    (server, seen)
}

/// A first connection that takes a ticket, then hands its socket on.
async fn warmed(mut server: Quiche, warm_hash: [u8; 32], deadline: Deadline) -> UdpSocket {
    server
        .drive_until("the first handshake", deadline, |c| c.is_established())
        .await;
    let got = server.read_stream(0, octets::mib(1), deadline).await;
    assert_eq!(digest(&got), warm_hash, "the first payload arrived whole");
    // Echoed, so the client has a round trip after the handshake, which is when the session
    // ticket follows. Whether it arrived is not asserted here; the second connection resuming
    // is what says so.
    server.write_stream(0, &got, deadline).await;
    server
        .drive_until("the first connection ends", deadline, |c| c.is_closed())
        .await;
    server.into_socket()
}

/// The client's side of that first connection.
async fn warm_up(
    client: &Endpoint,
    config: ClientConfig,
    addr: SocketAddr,
    warm: &[u8],
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
    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(warm))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let echoed = deadline
        .wait("the echo", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(digest(&echoed), digest(warm), "the first payload came back");
    connection.close(0u32.into(), b"done");
}

/// A server that kept its ticket key accepts the client's early data: the bytes are readable
/// while the server has still answered nothing, both sides then report the acceptance, and the
/// payload arrives whole.
#[tokio::test]
async fn early_data_is_accepted_when_the_server_keeps_its_ticket_key() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let first = quiche_resuming_server_config(&identity, &TICKET_KEY, true);
    let second = quiche_resuming_server_config(&identity, &TICKET_KEY, true);
    let (server_addr, accepting) = Quiche::bind_server(first, deadline).await;

    let warm = payload(0xb1, octets::kib(1));
    let early = payload(0xb2, octets::kib(1));
    let (warm_hash, early_hash) = (digest(&warm), digest(&early));

    let (ready, is_ready) = oneshot::channel();
    let peer = Peer::spawn(async move {
        let socket = warmed(accepting.await, warm_hash, deadline).await;
        // The next attempt may start: the first connection is done with this socket, so its
        // driver will not take that attempt's first flight off the wire.
        ready.send(()).expect("the test is listening");
        let (mut server, seen) = take_one_watching_for_early_data(socket, second, deadline).await;
        assert!(seen.resumed, "the second connection resumed: {seen:?}");
        assert_eq!(
            seen.reason,
            early_data::ACCEPTED,
            "and its early data was accepted: {seen:?}"
        );
        assert!(
            seen.early_bytes_before_the_handshake,
            "with the bytes on the wire before the handshake was let finish: {seen:?}"
        );
        let received = server.read_stream(2, octets::mib(1), deadline).await;
        assert_eq!(
            digest(&received),
            early_hash,
            "the early payload arrived whole"
        );
        server
            .drive_until("the client closes", deadline, |c| c.peer_error().is_some())
            .await;
        expect_the_clients_close(&mut server);
    });

    let config = rama_client_config_with_early_data(&identity);
    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    warm_up(&client, config.clone(), server_addr, &warm, deadline).await;
    deadline
        .wait("the peer is ready for another attempt", is_ready)
        .await
        .expect("the peer said so");

    let attempt = client
        .connect_with(config.clone(), server_addr, "localhost")
        .expect("the attempt starts");
    let (connection, accepted) = attempt
        .into_0rtt()
        .unwrap_or_else(|_| panic!("the client had a ticket and early keys to offer"));
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
    // `Ok(None)` is the acknowledged end of the stream; `Ok(Some(_))` would be a STOP_SENDING.
    // The peer's digest of the payload is the receipt, and it is asserted on that side.
    assert_eq!(
        deadline
            .wait("the early payload is taken", uni.stopped())
            .await
            .expect("the stream ended cleanly"),
        None,
        "the peer acknowledged the end of the early stream"
    );
    connection.close(0u32.into(), b"done");

    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}

/// A server that kept its ticket key but does not accept early data resumes the session and
/// refuses the 0-RTT. The client is told, its early streams are gone, and a retry on the 1-RTT
/// keys delivers the payload once.
#[tokio::test]
async fn early_data_is_refused_while_the_session_still_resumes() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let first = quiche_resuming_server_config(&identity, &TICKET_KEY, true);
    // The same authority over tickets, without accepting early data.
    let second = quiche_resuming_server_config(&identity, &TICKET_KEY, false);
    let (server_addr, accepting) = Quiche::bind_server(first, deadline).await;

    let warm = payload(0xb3, octets::kib(1));
    let retried = payload(0xb4, octets::kib(1));
    let (warm_hash, retried_hash) = (digest(&warm), digest(&retried));

    let (ready, is_ready) = oneshot::channel();
    let peer = Peer::spawn(async move {
        let socket = warmed(accepting.await, warm_hash, deadline).await;
        // The next attempt may start: the first connection is done with this socket, so its
        // driver will not take that attempt's first flight off the wire.
        ready.send(()).expect("the test is listening");
        let (mut server, seen) = take_one(socket, second, deadline).await;
        assert!(seen.resumed, "the session still resumed: {seen:?}");
        assert_ne!(
            seen.reason,
            early_data::ACCEPTED,
            "but the early data was not accepted: {seen:?}"
        );
        assert!(
            !seen.early_bytes_before_the_handshake,
            "and no early bytes were taken: {seen:?}"
        );
        // The retry, on the 1-RTT keys.
        let received = server.read_stream(2, octets::mib(1), deadline).await;
        assert_eq!(digest(&received), retried_hash, "the retry arrived whole");
        // Answered on a stream of the server's own, so the client can see the peer took it
        // rather than infer receipt. Server-initiated unidirectional streams start at 3.
        server.write_stream(3, &received, deadline).await;

        // A barrier the client sends afterwards. Driving to it keeps the connection running,
        // and every stream that becomes readable on the way is recorded. What this bounds is
        // this exchange: nothing arrives besides the retry and the barrier. It is not a replay
        // detector, and nothing here injects a duplicate to see one caught.
        let mut unexpected = Vec::new();
        server
            .drive_until("the barrier arrives", deadline, |c| {
                for stream in c.readable() {
                    if stream != BARRIER {
                        unexpected.push(stream);
                    }
                }
                c.stream_readable(BARRIER)
            })
            .await;
        let barrier = server.read_stream(BARRIER, octets::mib(1), deadline).await;
        assert_eq!(digest(&barrier), retried_hash, "the barrier arrived whole");
        server.write_stream(BARRIER, &barrier, deadline).await;
        assert!(
            unexpected.is_empty(),
            "only the retry and the barrier arrived, not {unexpected:?}"
        );
        server
            .drive_until("the client closes", deadline, |c| c.peer_error().is_some())
            .await;
        expect_the_clients_close(&mut server);
    });

    let config = rama_client_config_with_early_data(&identity);
    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    warm_up(&client, config.clone(), server_addr, &warm, deadline).await;
    deadline
        .wait("the peer is ready for another attempt", is_ready)
        .await
        .expect("the peer said so");

    let attempt = client
        .connect_with(config.clone(), server_addr, "localhost")
        .expect("the attempt starts");
    let (connection, accepted) = attempt
        .into_0rtt()
        .unwrap_or_else(|_| panic!("the client had a ticket and early keys to offer"));
    let mut early = deadline
        .wait("an early uni stream", connection.open_uni())
        .await
        .expect("it opens");
    deadline
        .wait("writing early", early.write_all(&retried))
        .await
        .expect("it is written");
    early.finish().expect("the early stream ends");

    assert!(
        !deadline
            .wait("the 0-RTT verdict", accepted)
            .await
            .expect("the handshake completes"),
        "the client was told its early data was refused"
    );
    // The rejected stream is gone, and it says exactly why: the API needs the caller to send
    // again and does not do it for them.
    let refused = deadline
        .wait("the rejected stream", early.stopped())
        .await
        .expect_err("the stream opened before the handshake did not survive the rejection");
    assert!(
        matches!(refused, StoppedError::ZeroRttRejected),
        "the rejection is what ended it, not something else: {refused:?}"
    );

    let mut again = deadline
        .wait("a stream after the rejection", connection.open_uni())
        .await
        .expect("it opens");
    deadline
        .wait("writing again", again.write_all(&retried))
        .await
        .expect("it is written");
    again.finish().expect("the retry ends");
    // The peer's answer is the receipt. `stopped()` answering `Ok(None)` says the peer
    // acknowledged the end of the stream; `Ok(Some(_))` would be a STOP_SENDING instead.
    let mut answer = deadline
        .wait("the peer answers", connection.accept_uni())
        .await
        .expect("it opens");
    let answered = deadline
        .wait("reading the answer", answer.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(
        digest(&answered),
        retried_hash,
        "the peer sent back what it received, which is the receipt"
    );
    assert_eq!(
        deadline
            .wait("the retry is acknowledged", again.stopped())
            .await
            .expect("the stream ended cleanly"),
        None,
        "the peer acknowledged the end of the retry rather than stopping it"
    );

    // The barrier, so the peer counts what arrived while the connection was still running.
    let (mut send, mut recv) = deadline
        .wait("the barrier stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing the barrier", send.write_all(&retried))
        .await
        .expect("it is written");
    send.finish().expect("the barrier ends");
    let echoed = deadline
        .wait("the barrier comes back", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(digest(&echoed), retried_hash, "the barrier came back whole");
    connection.close(0u32.into(), b"done");

    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}

/// A server that rotated its ticket key refuses the resumption itself, which is a different
/// outcome from refusing the early data of a session it did resume.
#[tokio::test]
async fn a_rotated_ticket_key_refuses_the_resumption() {
    let deadline = Deadline::new();
    let identity = Identity::generate("localhost");
    let first = quiche_resuming_server_config(&identity, &TICKET_KEY, true);
    let second = quiche_resuming_server_config(&identity, &OTHER_TICKET_KEY, true);
    let (server_addr, accepting) = Quiche::bind_server(first, deadline).await;

    let warm = payload(0xb5, octets::kib(1));
    let warm_hash = digest(&warm);

    let (ready, is_ready) = oneshot::channel();
    let peer = Peer::spawn(async move {
        let socket = warmed(accepting.await, warm_hash, deadline).await;
        // The next attempt may start: the first connection is done with this socket, so its
        // driver will not take that attempt's first flight off the wire.
        ready.send(()).expect("the test is listening");
        let (mut server, seen) = take_one(socket, second, deadline).await;
        assert!(!seen.resumed, "the resumption itself was refused: {seen:?}");
        assert_eq!(
            seen.reason,
            early_data::SESSION_NOT_RESUMED,
            "and the reason is the session, not the early data: {seen:?}"
        );
        // An exchange before the close. Closing the instant the handshake future resolves is a
        // separate case: the close is then coalesced into the Handshake and 1-RTT spaces, as
        // RFC 9000 §10.2.3 asks, and this peer acts on neither.
        let received = server.read_stream(0, octets::mib(1), deadline).await;
        server.write_stream(0, &received, deadline).await;
        server
            .drive_until("the client closes", deadline, |c| c.peer_error().is_some())
            .await;
        expect_the_clients_close(&mut server);
    });

    let config = rama_client_config_with_early_data(&identity);
    let client = deadline
        .wait("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    warm_up(&client, config.clone(), server_addr, &warm, deadline).await;
    deadline
        .wait("the peer is ready for another attempt", is_ready)
        .await
        .expect("the peer said so");

    let attempt = client
        .connect_with(config.clone(), server_addr, "localhost")
        .expect("the attempt starts");
    let connection = match attempt.into_0rtt() {
        Ok((connection, accepted)) => {
            assert!(
                !deadline
                    .wait("the 0-RTT verdict", accepted)
                    .await
                    .expect("the handshake completes"),
                "a server that would not resume cannot have accepted early data"
            );
            connection
        }
        Err(connecting) => deadline
            .wait("the second attempt", connecting)
            .await
            .expect("the handshake completes"),
    };
    // An ordinary exchange on the connection that would not resume, then the client's own close.
    let (mut send, mut recv) = deadline
        .wait("a bi stream", connection.open_bi())
        .await
        .expect("it opens");
    deadline
        .wait("writing", send.write_all(&warm))
        .await
        .expect("it is written");
    send.finish().expect("the stream ends");
    let echoed = deadline
        .wait("the echo", recv.read_to_end(octets::mib(1)))
        .await
        .expect("it completes");
    assert_eq!(digest(&echoed), warm_hash, "the payload came back whole");
    connection.close(0u32.into(), b"done");

    deadline.wait("rama's shutdown", client.wait_idle()).await;
    peer.join("the quiche peer", deadline).await;
}
