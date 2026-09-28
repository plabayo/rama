//! [`HttpServer::serve_with_graceful_shutdown`] winds down one connection
//! on its own signal without cutting the in-flight response.

#![expect(clippy::expect_used, reason = "test fixtures")]

use std::{convert::Infallible, time::Duration};

use rama_core::{bytes::Bytes, rt::Executor, service::service_fn};
use rama_http_backend::server::HttpServer;
use rama_http_core::{
    client::conn as client_conn,
    h2::{Reason, client as h2_client},
};
use rama_http_types::{Body, Request, Response, StatusCode, Version, body::util::BodyExt as _};
use rama_net::test_utils::client::MockSocket;
use rama_utils::octets::kib;
use tokio::{
    sync::{oneshot, watch},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

/// Serve `server_io`; the returned receiver flips once a request is
/// being handled, which is held until `release`.
fn serve(
    server_io: MockSocket,
    release: watch::Receiver<bool>,
    signal: oneshot::Receiver<()>,
) -> (tokio::task::JoinHandle<()>, watch::Receiver<bool>) {
    let (arrived_tx, arrived) = watch::channel(false);
    let arrived_tx = std::sync::Arc::new(arrived_tx);
    let server = tokio::spawn(async move {
        HttpServer::auto(Executor::new())
            .serve_with_graceful_shutdown(
                server_io,
                service_fn(move |_: Request| {
                    let mut release = release.clone();
                    arrived_tx.send_replace(true);
                    async move {
                        release
                            .wait_for(|released| *released)
                            .await
                            .expect("test holds the release sender");
                        Ok::<_, Infallible>(Response::new(Body::from("done")))
                    }
                }),
                async move {
                    signal.await.expect("test holds the signal sender");
                },
            )
            .await
            .expect("graceful shutdown ends without error");
    });
    (server, arrived)
}

#[tokio::test]
async fn h2_signal_sends_goaway_and_finishes_in_flight_stream() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let (signal_tx, signal) = oneshot::channel();
    let (server, mut arrived) = serve(MockSocket::new(server_io), release, signal);

    let (client, conn) = h2_client::handshake(MockSocket::new(client_io))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);

    let mut ready = client.clone().ready().await.unwrap();
    let req = rama_http_types::Request::builder()
        .uri("http://example.test/")
        .version(Version::HTTP_2)
        .body(())
        .unwrap();
    let (in_flight, _) = ready.send_request(req, true).unwrap();

    arrived.wait_for(|arrived| *arrived).await.unwrap();
    signal_tx.send(()).unwrap();
    let err = timeout(WAIT, async {
        loop {
            match client.clone().ready().await {
                Err(err) => break err,
                Ok(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("client must receive GOAWAY");
    assert!(err.is_go_away(), "got: {err:?}");
    assert_eq!(err.reason(), Some(Reason::NO_ERROR));

    release_tx.send_replace(true);
    let resp = timeout(WAIT, in_flight).await.unwrap().unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(out, b"done");

    timeout(WAIT, conn).await.unwrap().unwrap().unwrap();
    timeout(WAIT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_signal_closes_after_in_flight_response() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let (signal_tx, signal) = oneshot::channel();
    let (server, mut arrived) = serve(MockSocket::new(server_io), release, signal);

    let (mut sender, conn) = client_conn::http1::handshake(MockSocket::new(client_io))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);

    let req = Request::builder()
        .uri("/")
        .header("host", "example.test")
        .body(Body::empty())
        .unwrap();
    let in_flight = tokio::spawn(sender.send_request(req));

    arrived.wait_for(|arrived| *arrived).await.unwrap();
    signal_tx.send(()).unwrap();
    release_tx.send_replace(true);

    let resp = timeout(WAIT, in_flight).await.unwrap().unwrap().unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "done");

    timeout(WAIT, conn)
        .await
        .expect("h1 connection must close after the in-flight response")
        .unwrap()
        .unwrap();
    timeout(WAIT, server).await.unwrap().unwrap();
}
