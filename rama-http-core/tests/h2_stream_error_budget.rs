//! An HTTP/2 client whose origin breaks the protocol on more streams than the budget for
//! such errors allows closes the connection, and fails every request in flight on it.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use rama_core::{ServiceInput, bytes::Bytes, graceful::WeakScope};
use rama_http::{Body, Request, StatusCode};
use rama_http_core::{
    client::conn::http2,
    h2::{Error as H2Error, RateBudget, Reason, server as h2_server},
};
use rama_http_types::Response;
use std::{error::Error as _, time::Duration};
use tokio::{task::JoinHandle, time::timeout};

const LIMIT: Duration = Duration::from_secs(5);

type Origin = h2_server::Connection<ServiceInput<tokio::io::DuplexStream>, Bytes>;
type Pending = JoinHandle<rama_http_core::Result<StatusCode>>;

/// A client whose refused stream budget covers nothing, its connection task and its origin.
async fn connect() -> (
    http2::SendRequest<Body>,
    JoinHandle<rama_http_core::Result<()>>,
    Origin,
) {
    let (client_io, origin_io) = tokio::io::duplex(64 * 1024);
    let origin = tokio::spawn(h2_server::Builder::new().handshake(ServiceInput::new(origin_io)));
    let (client, conn) = http2::Builder::new(WeakScope::detached())
        .with_refused_stream_budget(RateBudget::lifetime(0))
        .handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    (client, tokio::spawn(conn), origin.await.unwrap().unwrap())
}

/// Send a request and hand out the origin's responder for it.
async fn send(
    client: &http2::SendRequest<Body>,
    origin: &mut Origin,
) -> (Pending, h2_server::SendResponse<Bytes>) {
    let mut client = client.clone();
    let request = Request::builder()
        .uri("http://example.test/")
        .body(Body::empty())
        .unwrap();
    let response = tokio::spawn(async move { Ok(client.send_request(request).await?.status()) });
    let (_request, respond) = origin.accept().await.unwrap().unwrap();
    (response, respond)
}

fn assert_ended_with_connection(result: rama_http_core::Result<StatusCode>) {
    let error = result.unwrap_err();
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<H2Error>())
        .unwrap();
    assert!(cause.is_go_away(), "{cause:?}");
    assert_eq!(cause.reason(), Some(Reason::ENHANCE_YOUR_CALM));
}

/// The response in error ends its stream with the same frame, for a request already sent
/// in full: the stream is closed by the time the connection learns of the error.
#[tokio::test(start_paused = true)]
async fn h2_response_ending_its_stream_in_error_fails_every_request_in_flight() {
    timeout(LIMIT, async {
        let (client, conn, mut origin) = connect().await;
        let (waiting, _respond_later) = send(&client, &mut origin).await;
        let (broken, mut respond) = send(&client, &mut origin).await;

        // announces content, yet ends the stream
        let answer = Response::builder()
            .header("content-length", "5")
            .body(())
            .unwrap();
        respond.send_response(answer, true).unwrap();
        let origin = tokio::spawn(async move { while origin.accept().await.is_some() {} });

        assert!(conn.await.unwrap().is_err());
        assert_ended_with_connection(broken.await.unwrap());
        assert_ended_with_connection(waiting.await.unwrap());
        origin.await.unwrap();
    })
    .await
    .expect("a request outlived its connection");
}
