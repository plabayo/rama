//! An HTTP/2 client request the peer provably never processed reports
//! [`Error::is_refused`] (RFC 9113 section 8.7), a processed one never does.
//!
//! [`Error::is_refused`]: rama_http_core::Error::is_refused

#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test fixtures")]

use rama_core::{ServiceInput, bytes::Bytes, rt::Executor};
use rama_http::{Body, Request};
use rama_http_core::{
    body::Incoming,
    client::conn::http2,
    h2::{Reason, server as h2_server},
};
use rama_http_types::Response;
use std::{future::poll_fn, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

type Origin = h2_server::Connection<ServiceInput<DuplexStream>, Bytes>;
type ClientConn = JoinHandle<rama_http_core::Result<()>>;

async fn connect() -> (http2::SendRequest<Body>, Origin, ClientConn) {
    connect_with(h2_server::Builder::new()).await
}

async fn connect_with(
    origin: h2_server::Builder,
) -> (http2::SendRequest<Body>, Origin, ClientConn) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (origin_tx, origin_rx) = oneshot::channel();
    tokio::spawn(async move {
        let origin = origin
            .handshake(ServiceInput::new(server_io))
            .await
            .unwrap();
        assert!(origin_tx.send(origin).is_ok(), "test awaits the origin");
    });
    let (client, conn) = http2::handshake(Executor::new(), ServiceInput::new(client_io))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);
    (client, origin_rx.await.unwrap(), conn)
}

fn send(
    client: &http2::SendRequest<Body>,
    method: &str,
    body: &'static str,
) -> JoinHandle<rama_http_core::Result<Response<Incoming>>> {
    let mut client = client.clone();
    let req = Request::builder()
        .method(method)
        .uri("https://example.test/")
        .body(Body::from(body))
        .unwrap();
    tokio::spawn(async move { client.send_request(req).await })
}

async fn next_stream(
    origin: &mut Origin,
) -> (
    rama_http_types::Request<rama_http_core::h2::RecvStream>,
    h2_server::SendResponse<Bytes>,
) {
    origin.accept().await.unwrap().unwrap()
}

/// Close the origin with a `GOAWAY` naming the last stream it processed.
async fn go_away(mut origin: Origin, reason: Reason) {
    origin.abrupt_shutdown(reason);
    _ = poll_fn(|cx| origin.poll_closed(cx)).await;
}

async fn assert_refused(
    resp: JoinHandle<rama_http_core::Result<Response<Incoming>>>,
    refused: bool,
    what: &str,
) {
    let err = timeout(Duration::from_secs(1), resp)
        .await
        .unwrap()
        .unwrap()
        .expect_err("origin went away before responding");
    assert_eq!(err.is_refused(), refused, "{what}: {err:?}");
}

/// The origin goes away while the client already sent more streams after
/// the last one it processed. Only that stream id says what was processed,
/// whatever the `GOAWAY` error code.
#[tokio::test(start_paused = true)]
async fn streams_above_goaway_last_stream_id_are_refused() {
    for reason in [
        Reason::NO_ERROR,
        Reason::ENHANCE_YOUR_CALM,
        Reason::INTERNAL_ERROR,
    ] {
        let (client, mut origin, _conn) = connect().await;

        let processed = send(&client, "GET", "");
        let (_req, _respond) = next_stream(&mut origin).await;

        let unprocessed_get = send(&client, "GET", "");
        let unprocessed_post = send(&client, "POST", "a=1");
        // paused clock: elapses once the client wrote both, unread by the origin
        sleep(Duration::from_millis(10)).await;

        go_away(origin, reason).await;

        assert_refused(
            unprocessed_get,
            true,
            &format!("unprocessed GET, {reason:?}"),
        )
        .await;
        assert_refused(
            unprocessed_post,
            true,
            &format!("unprocessed POST, {reason:?}"),
        )
        .await;
        assert_refused(processed, false, &format!("processed, {reason:?}")).await;
    }
}

/// A stream waiting for a concurrency slot was opened but never sent, so
/// the `GOAWAY` cannot cover it: it is refused, not failed along with the
/// connection.
#[tokio::test(start_paused = true)]
async fn pending_open_stream_above_goaway_is_refused() {
    let (client, mut origin, _conn) =
        connect_with(h2_server::Builder::new().with_max_concurrent_streams(1)).await;

    let processed = send(&client, "GET", "");
    let (_req, _respond) = next_stream(&mut origin).await;
    // paused clock: the client applied the origin's stream limit by now
    sleep(Duration::from_millis(10)).await;

    let pending = send(&client, "POST", "a=1");
    sleep(Duration::from_millis(10)).await;

    go_away(origin, Reason::NO_ERROR).await;

    assert_refused(pending, true, "pending open").await;
    assert_refused(processed, false, "processed").await;
}

/// Only a `REFUSED_STREAM` reset says the stream was not processed.
#[tokio::test(start_paused = true)]
async fn only_refused_stream_reset_is_refused() {
    let (client, mut origin, _conn) = connect().await;

    for (reason, refused) in [
        (Reason::REFUSED_STREAM, true),
        (Reason::CANCEL, false),
        (Reason::INTERNAL_ERROR, false),
    ] {
        let resp = send(&client, "POST", "a=1");
        let (_req, mut respond) = next_stream(&mut origin).await;
        respond.send_reset(reason);
        let (resp, ()) = tokio::join!(resp, async {
            tokio::select! {
                accepted = origin.accept() => panic!("unexpected stream: {accepted:?}"),
                () = sleep(Duration::from_millis(50)) => (),
            }
        });
        let err = resp.unwrap().expect_err("stream was reset");
        assert_eq!(err.is_refused(), refused, "{reason:?}: {err:?}");
    }
}

/// The connection's error carries no request's stream id: even after a
/// `GOAWAY` that did cover the in-flight POST, it must never read as a
/// refusal a retry policy could act on.
#[tokio::test(start_paused = true)]
async fn connection_error_is_never_refused() {
    let (client, mut origin, conn) = connect().await;

    let processed = send(&client, "POST", "a=1");
    let (_req, _respond) = next_stream(&mut origin).await;
    go_away(origin, Reason::INTERNAL_ERROR).await;

    assert_refused(processed, false, "processed").await;
    let err = timeout(Duration::from_secs(1), conn)
        .await
        .unwrap()
        .unwrap()
        .expect_err("origin went away with an error");
    assert!(!err.is_refused(), "connection error: {err:?}");
}

/// Frame header of an empty frame on stream 0.
fn empty_frame(kind: u8) -> [u8; 9] {
    [0, 0, 0, kind, 0, 0, 0, 0, 0]
}

/// The origin has the POST, then sends a frame the client must reject: the
/// client's own `GOAWAY` says nothing about what the origin processed.
#[tokio::test]
async fn locally_detected_connection_error_is_never_refused() {
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const SETTINGS: u8 = 0x4;

    let (client_io, mut origin) = tokio::io::duplex(64 * 1024);
    let (client, conn) = http2::handshake(Executor::new(), ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let processed = send(&client, "POST", "a=1");

    let mut preface = [0; 24];
    origin.read_exact(&mut preface).await.unwrap();
    origin.write_all(&empty_frame(SETTINGS)).await.unwrap();
    loop {
        let mut head = [0; 9];
        origin.read_exact(&mut head).await.unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]);
        let mut payload = vec![0; usize::try_from(len).unwrap()];
        origin.read_exact(&mut payload).await.unwrap();
        if head[3] == HEADERS {
            break;
        }
    }
    // DATA on stream 0 is a connection error (RFC 9113 section 6.1)
    origin.write_all(&empty_frame(DATA)).await.unwrap();

    let err = timeout(Duration::from_secs(1), processed)
        .await
        .unwrap()
        .unwrap()
        .expect_err("client rejected the connection");
    let cause = std::error::Error::source(&err)
        .and_then(|cause| cause.downcast_ref::<rama_http_core::h2::Error>())
        .expect("h2 cause");
    assert!(cause.is_go_away() && cause.is_library(), "got: {err:?}");
    assert!(!err.is_refused(), "processed: {err:?}");
}
