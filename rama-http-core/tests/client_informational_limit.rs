//! HTTP/1 and HTTP/2 clients relay informational (1xx) responses up to a
//! per-request limit and fail a request whose origin sends more.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use rama_core::{ServiceInput, bytes::Bytes, graceful::WeakScope};
use rama_http::{Body, Request, StatusCode};
use rama_http_core::{
    client::conn::{http1, http2},
    h2::{Error as H2Error, RateBudget, Reason, server as h2_server},
};
use rama_http_types::Response;
use std::{error::Error as _, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};

const ALLOWED: usize = 3;
const LIMIT: Duration = Duration::from_secs(5);
const INTERIM: &[u8] = b"HTTP/1.1 103 Early Hints\r\nlink: </style.css>\r\n\r\n";
const FINAL: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
/// What a client tells the origin whose connection it closes for too many refused streams.
const CLOSED_FOR_REFUSED_STREAMS: &str = "too_many_refused_streams";

fn request() -> Request<Body> {
    Request::builder()
        .uri("http://example.test/")
        .body(Body::empty())
        .unwrap()
}

async fn h1_client(io: DuplexStream) -> http1::SendRequest<Body> {
    let (client, conn) = http1::Builder::new()
        .with_max_informational_responses(ALLOWED)
        .handshake(ServiceInput::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    client
}

/// Read one bodyless request head off the origin side.
async fn h1_read_request(origin: &mut DuplexStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(origin.read_u8().await.unwrap());
    }
}

/// Answer with `interim` informational responses and a final one, either in one
/// write or one response per read of the client.
async fn h1_respond(origin: &mut DuplexStream, interim: usize, coalesced: bool) {
    if coalesced {
        let mut bytes = INTERIM.repeat(interim);
        bytes.extend_from_slice(FINAL);
        _ = origin.write_all(&bytes).await;
        return;
    }
    for _ in 0..interim {
        // The client closes once the limit is passed.
        if origin.write_all(INTERIM).await.is_err() {
            return;
        }
        // paused clock: elapses once the client parsed what was written
        sleep(Duration::from_millis(1)).await;
    }
    _ = origin.write_all(FINAL).await;
}

#[tokio::test(start_paused = true)]
async fn h1_informational_responses_up_to_the_limit_precede_a_final_response() {
    timeout(LIMIT, async {
        for coalesced in [true, false] {
            let (client_io, mut origin) = tokio::io::duplex(64 * 1024);
            let mut client = h1_client(client_io).await;
            // Each request on the connection gets the full allowance.
            for _ in 0..2 {
                let response = client.send_request(request());
                h1_read_request(&mut origin).await;
                h1_respond(&mut origin, ALLOWED, coalesced).await;
                assert_eq!(response.await.unwrap().status(), StatusCode::OK);
                client.ready().await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn h1_informational_responses_past_the_limit_fail_the_request() {
    timeout(LIMIT, async {
        for coalesced in [true, false] {
            let (client_io, mut origin) = tokio::io::duplex(64 * 1024);
            let mut client = h1_client(client_io).await;
            let response = client.send_request(request());
            h1_read_request(&mut origin).await;
            h1_respond(&mut origin, ALLOWED + 1, coalesced).await;
            let error = response.await.unwrap_err();
            assert!(error.is_parse(), "{error:?}");
            assert!(
                error.to_string().contains("informational"),
                "coalesced={coalesced}: {error}"
            );
            // The connection is not reused.
            assert!(client.ready().await.is_err());
        }
    })
    .await
    .unwrap();
}

type H2Origin = h2_server::Connection<ServiceInput<DuplexStream>, Bytes>;

async fn h2_connect() -> (http2::SendRequest<Body>, H2Origin) {
    let (client_io, origin_io) = tokio::io::duplex(64 * 1024);
    let origin = tokio::spawn(h2_server::Builder::new().handshake(ServiceInput::new(origin_io)));
    let (client, conn) = http2::Builder::new(WeakScope::detached())
        .with_max_informational_responses(ALLOWED)
        .handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    (client, origin.await.unwrap().unwrap())
}

/// Answer one request with `interim` informational responses and a final one.
async fn h2_exchange(interim: usize) -> rama_http_core::Result<StatusCode> {
    let (mut client, mut origin) = h2_connect().await;
    let response = tokio::spawn(async move { client.send_request(request()).await });
    let (_request, mut respond) = origin.accept().await.unwrap().unwrap();
    for _ in 0..interim {
        // The client resets the stream once the limit is passed.
        if respond
            .send_informational(Response::builder().status(103).body(()).unwrap())
            .is_err()
        {
            break;
        }
    }
    _ = respond.send_response(Response::new(()), true);
    let serve = tokio::spawn(async move { while origin.accept().await.is_some() {} });
    let result = response.await.unwrap().map(|response| response.status());
    serve.abort();
    result
}

#[tokio::test(start_paused = true)]
async fn h2_informational_responses_up_to_the_limit_precede_a_final_response() {
    timeout(LIMIT, async {
        assert_eq!(h2_exchange(ALLOWED).await.unwrap(), StatusCode::OK);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn h2_informational_responses_past_the_limit_fail_the_request() {
    timeout(LIMIT, async {
        let error = h2_exchange(ALLOWED + 1).await.unwrap_err();
        let cause = error
            .source()
            .and_then(|source| source.downcast_ref::<H2Error>())
            .unwrap();
        assert_eq!(cause.reason(), Some(Reason::ENHANCE_YOUR_CALM));
        assert!(cause.is_reset() && cause.is_library(), "{cause:?}");
    })
    .await
    .unwrap();
}

type H2Respond = h2_server::SendResponse<Bytes>;

/// A client connection configured by `configure`, the responders of the requests its origin
/// accepts, and the error that ends the origin's connection, if any.
struct H2Session {
    client: http2::SendRequest<Body>,
    conn: JoinHandle<rama_http_core::Result<()>>,
    accepted: mpsc::UnboundedReceiver<H2Respond>,
    origin: JoinHandle<Option<H2Error>>,
}

impl H2Session {
    async fn new(configure: impl FnOnce(&mut http2::Builder)) -> Self {
        let (client_io, origin_io) = tokio::io::duplex(64 * 1024);
        let origin =
            tokio::spawn(h2_server::Builder::new().handshake(ServiceInput::new(origin_io)));
        let mut builder = http2::Builder::new(WeakScope::detached());
        builder.set_max_informational_responses(ALLOWED);
        configure(&mut builder);
        let (client, conn) = builder
            .handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        let conn = tokio::spawn(conn);
        let mut origin: H2Origin = origin.await.unwrap().unwrap();
        let (accept, accepted) = mpsc::unbounded_channel();
        let origin = tokio::spawn(async move {
            loop {
                match origin.accept().await? {
                    Ok((_request, respond)) => _ = accept.send(respond),
                    Err(error) => return Some(error),
                }
            }
        });
        Self {
            client,
            conn,
            accepted,
            origin,
        }
    }

    /// Send a request and hand out the origin's responder for it.
    async fn send(&mut self) -> (H2Pending, H2Respond) {
        let mut sender = self.client.clone();
        let response = tokio::spawn(async move {
            let response = sender.send_request(request()).await?;
            Ok(response.status())
        });
        (response, self.accepted.recv().await.unwrap())
    }

    /// A request answered with one interim response more than the client accepts.
    async fn refused(&mut self) -> rama_http_core::Result<StatusCode> {
        let (response, mut respond) = self.send().await;
        for _ in 0..=ALLOWED {
            // The client resets the stream once the limit is passed.
            if respond
                .send_informational(Response::builder().status(103).body(()).unwrap())
                .is_err()
            {
                break;
            }
        }
        _ = respond.send_response(Response::new(()), true);
        response.await.unwrap()
    }

    /// A request answered against the protocol: the length of its content is no number.
    async fn malformed(&mut self) -> rama_http_core::Result<StatusCode> {
        let (response, mut respond) = self.send().await;
        let answer = Response::builder()
            .header("content-length", "some")
            .body(())
            .unwrap();
        _ = respond.send_response(answer, false);
        response.await.unwrap()
    }

    /// A request answered as an origin should.
    async fn served(&mut self) -> rama_http_core::Result<StatusCode> {
        let (response, mut respond) = self.send().await;
        _ = respond.send_response(Response::new(()), true);
        response.await.unwrap()
    }

    /// The reason and text of the GOAWAY that ended the origin's connection.
    async fn closed(self) -> (Reason, String) {
        let error = self.origin.await.unwrap().unwrap();
        assert!(error.is_go_away() && error.is_remote(), "{error:?}");
        assert!(self.conn.await.unwrap().is_err());
        (error.reason().unwrap(), error.to_string())
    }
}

type H2Pending = JoinHandle<rama_http_core::Result<StatusCode>>;

fn h2_cause(error: &rama_http_core::Error) -> &H2Error {
    error
        .source()
        .and_then(|source| source.downcast_ref::<H2Error>())
        .unwrap()
}

/// Whether `result` is a request the client refused by resetting only its stream.
fn is_refusal(result: &rama_http_core::Result<StatusCode>) -> bool {
    result.as_ref().is_err_and(|error| {
        let cause = h2_cause(error);
        cause.is_reset() && cause.reason() == Some(Reason::ENHANCE_YOUR_CALM)
    })
}

/// Whether `result` is a request the client failed for its origin's protocol error by
/// resetting only its stream.
fn is_stream_error(result: &rama_http_core::Result<StatusCode>) -> bool {
    result.as_ref().is_err_and(|error| {
        let cause = h2_cause(error);
        cause.is_reset() && cause.reason() == Some(Reason::PROTOCOL_ERROR)
    })
}

/// Whether `result` is a request that ended with its whole connection.
fn is_connection_error(result: &rama_http_core::Result<StatusCode>) -> bool {
    result
        .as_ref()
        .is_err_and(|error| h2_cause(error).is_go_away())
}

/// Refusing requests for their interim responses within the budget leaves the other requests
/// on the connection alone.
#[tokio::test(start_paused = true)]
async fn h2_refusals_within_the_budget_leave_the_connection_alone() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::lifetime(3));
        })
        .await;
        let (sibling, mut answer_sibling) = session.send().await;
        for _ in 0..3 {
            assert!(is_refusal(&session.refused().await));
        }
        _ = answer_sibling.send_response(Response::new(()), true);
        assert_eq!(sibling.await.unwrap().unwrap(), StatusCode::OK);
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);
        session.client.ready().await.unwrap();
    })
    .await
    .unwrap();
}

/// A burst of protocol errors within the budget fails only the requests in error.
#[tokio::test(start_paused = true)]
async fn h2_protocol_errors_within_the_budget_leave_the_connection_alone() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::new(3, 1));
        })
        .await;
        let (sibling, mut answer_sibling) = session.send().await;
        for _ in 0..3 {
            assert!(is_stream_error(&session.malformed().await));
        }
        _ = answer_sibling.send_response(Response::new(()), true);
        assert_eq!(sibling.await.unwrap().unwrap(), StatusCode::OK);
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);
        session.client.ready().await.unwrap();
    })
    .await
    .unwrap();
}

/// A flood of refusals past the budget ends the connection and the requests in flight on
/// it, and tells the origin why.
#[tokio::test(start_paused = true)]
async fn h2_refusals_past_the_budget_close_the_connection() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::lifetime(2));
        })
        .await;
        let (sibling, _answer_sibling) = session.send().await;
        for _ in 0..2 {
            assert!(is_refusal(&session.refused().await));
        }
        assert!(is_connection_error(&session.refused().await));
        assert!(is_connection_error(&sibling.await.unwrap()));

        let (reason, text) = session.closed().await;
        assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
        assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
    })
    .await
    .unwrap();
}

/// A flood of protocol errors ends the connection the same way, and for the same reason.
#[tokio::test(start_paused = true)]
async fn h2_protocol_errors_past_the_budget_close_the_connection() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::new(2, 1));
        })
        .await;
        let (sibling, _answer_sibling) = session.send().await;
        for _ in 0..2 {
            assert!(is_stream_error(&session.malformed().await));
        }
        assert!(is_connection_error(&session.malformed().await));
        assert!(is_connection_error(&sibling.await.unwrap()));

        let (reason, text) = session.closed().await;
        assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
        assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
    })
    .await
    .unwrap();
}

/// The budget regains its tokens with time, up to its burst and no further, whichever
/// kind of refused stream spent them.
#[tokio::test(start_paused = true)]
async fn h2_refused_stream_budget_refills_over_time() {
    timeout(Duration::from_mins(5), async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::new(2, 1));
        })
        .await;
        for wait in [Duration::from_secs(2), Duration::from_mins(1)] {
            assert!(is_refusal(&session.refused().await));
            assert!(is_stream_error(&session.malformed().await));
            sleep(wait).await;
        }
        assert!(is_stream_error(&session.malformed().await));
        assert!(is_refusal(&session.refused().await));
        assert!(is_connection_error(&session.refused().await));

        let (_, text) = session.closed().await;
        assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
    })
    .await
    .unwrap();
}

/// The origin's protocol errors and the refusals for a local limit spend the same budget.
#[tokio::test(start_paused = true)]
async fn h2_protocol_errors_and_refusals_draw_on_one_budget() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::lifetime(3));
        })
        .await;
        assert!(is_stream_error(&session.malformed().await));
        assert!(is_refusal(&session.refused().await));
        assert!(is_stream_error(&session.malformed().await));
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);

        assert!(is_connection_error(&session.refused().await));
        let (reason, text) = session.closed().await;
        assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
        assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
    })
    .await
    .unwrap();
}

/// A budget without rate regains nothing, however long the connection lives: it is a
/// count over the whole life of the connection.
#[tokio::test(start_paused = true)]
async fn h2_a_lifetime_budget_counts_over_the_whole_connection() {
    timeout(Duration::from_hours(4), async {
        let mut session = H2Session::new(|builder| {
            builder.set_refused_stream_budget(RateBudget::lifetime(2));
        })
        .await;
        for _ in 0..2 {
            assert!(is_stream_error(&session.malformed().await));
            sleep(Duration::from_hours(1)).await;
        }
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);
        assert!(is_connection_error(&session.malformed().await));
        let (reason, _) = session.closed().await;
        assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
    })
    .await
    .unwrap();
}

/// How many of `drip` streams in error, each sent once the budget regained the last, the
/// connection fails one by one before it closes.
async fn h2_drip_survived(budget: RateBudget, drip: usize) -> usize {
    let mut session = H2Session::new(|builder| {
        builder.set_refused_stream_budget(budget);
    })
    .await;
    for sent in 0..drip {
        if !is_stream_error(&session.malformed().await) {
            let (reason, text) = session.closed().await;
            assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
            assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
            return sent;
        }
        sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(session.served().await.unwrap(), StatusCode::OK);
    drip
}

/// An origin erring steadily below the rate never spends the budget, so only a ceiling on
/// the lifetime total ends its connection.
#[tokio::test(start_paused = true)]
async fn h2_only_a_ceiling_ends_a_steady_drip_below_the_rate() {
    timeout(Duration::from_mins(5), async {
        let budget = RateBudget::new(2, 1);
        assert_eq!(h2_drip_survived(budget, 40).await, 40);
        assert_eq!(h2_drip_survived(budget.with_ceiling(7), 40).await, 7);
    })
    .await
    .unwrap();
}

/// Without a budget the client refuses and resets as often as the origin asks for it, well
/// past what the default budget covers at once.
#[tokio::test(start_paused = true)]
async fn h2_refused_streams_without_a_budget_never_close_the_connection() {
    timeout(LIMIT, async {
        let mut session = H2Session::new(|builder| {
            builder.unset_refused_stream_budget();
        })
        .await;
        for _ in 0..750 {
            assert!(is_refusal(&session.refused().await));
            assert!(is_stream_error(&session.malformed().await));
        }
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);
    })
    .await
    .unwrap();
}

/// The default budget takes a burst of refused streams in its stride, and a steady trickle
/// after it, yet not a flood without end.
#[tokio::test(start_paused = true)]
async fn h2_default_refused_stream_budget_tolerates_bursts_and_ends_a_flood() {
    timeout(Duration::from_hours(1), async {
        let mut session = H2Session::new(|_| ()).await;
        for _ in 0..250 {
            assert!(is_refusal(&session.refused().await));
            assert!(is_stream_error(&session.malformed().await));
        }
        // Ten a second for a minute.
        for _ in 0..600 {
            sleep(Duration::from_millis(100)).await;
            assert!(is_stream_error(&session.malformed().await));
        }
        assert_eq!(session.served().await.unwrap(), StatusCode::OK);

        let mut refused = 0;
        while is_refusal(&session.refused().await) {
            refused += 1;
            assert!(refused < 100_000, "a flood never ended the connection");
        }
        let (reason, text) = session.closed().await;
        assert_eq!(reason, Reason::ENHANCE_YOUR_CALM);
        assert!(text.contains(CLOSED_FOR_REFUSED_STREAMS), "{text}");
    })
    .await
    .unwrap();
}
