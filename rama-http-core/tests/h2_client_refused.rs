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
    io::DuplexStream,
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

type Origin = h2_server::Connection<ServiceInput<DuplexStream>, Bytes>;

async fn connect() -> (http2::SendRequest<Body>, Origin) {
    connect_with(h2_server::Builder::new()).await
}

async fn connect_with(origin: h2_server::Builder) -> (http2::SendRequest<Body>, Origin) {
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
    tokio::spawn(conn);
    (client, origin_rx.await.unwrap())
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
        let (client, mut origin) = connect().await;

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
    let (client, mut origin) =
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
    let (client, mut origin) = connect().await;

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
