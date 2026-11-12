//! A stream error past the budget for them ends the connection, and with it every exchange
//! on that connection: the one in error included, whatever state its last frame left it in.

use h2_support::prelude::*;
use rama::{
    ServiceInput,
    graceful::WeakScope,
    http::{
        Body,
        core::{server::conn::http2, service::RamaHttpService},
    },
    service::service_fn,
};
use rama_core::futures::StreamExt;
use std::{convert::Infallible, future::pending};
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

const LIMIT: Duration = Duration::from_secs(5);

/// How the peer breaks the message on stream 1.
#[derive(Debug, Clone, Copy)]
enum Broken {
    /// The head announces content and ends the stream.
    HeadEndingStream,
    /// The head announces a content length that is no number.
    Head,
    /// More content than announced.
    DataPastLength,
    /// Less content than announced, on the frame ending the stream.
    DataShortOfLength,
    /// Trailers that do not end the stream.
    TrailersLeavingStreamOpen,
    /// Trailers ending the stream short of the announced content.
    TrailersShortOfLength,
    /// Trailers carrying a pseudo-header.
    TrailersWithPseudoHeader,
}

impl Broken {
    const HEADS: [Self; 2] = [Self::HeadEndingStream, Self::Head];
    const BODIES: [Self; 5] = [
        Self::DataPastLength,
        Self::DataShortOfLength,
        Self::TrailersLeavingStreamOpen,
        Self::TrailersShortOfLength,
        Self::TrailersWithPseudoHeader,
    ];

    /// The head of the message, as far as this breakage shapes it.
    fn head(self, head: frames::Mock<frame::Headers>) -> frames::Mock<frame::Headers> {
        match self {
            Self::HeadEndingStream => head.field("content-length", "5").eos(),
            Self::Head => head.field("content-length", "some"),
            Self::DataPastLength => head.field("content-length", "1"),
            Self::DataShortOfLength | Self::TrailersShortOfLength => {
                head.field("content-length", "9")
            }
            Self::TrailersLeavingStreamOpen | Self::TrailersWithPseudoHeader => head,
        }
    }

    /// The frame following an accepted head, if the head is not the broken part.
    fn after_head(self) -> Option<SendFrame> {
        Some(match self {
            Self::HeadEndingStream | Self::Head => return None,
            Self::DataPastLength => frames::data(1, "hello").into(),
            Self::DataShortOfLength => frames::data(1, "hello").eos().into(),
            Self::TrailersLeavingStreamOpen => frames::headers(1).field("x", "y").into(),
            Self::TrailersShortOfLength => frames::headers(1).field("x", "y").eos().into(),
            Self::TrailersWithPseudoHeader => frames::headers(1).response(200).eos().into(),
        })
    }
}

/// Read a message body to its end.
async fn drain(mut body: RecvStream) -> Result<(), h2::Error> {
    while let Some(chunk) = body.data().await {
        chunk?;
    }
    body.trailers().await.map(|_trailers| ())
}

/// Await a response and its body in a task of their own, as a caller of a client does.
fn exchange(response: client::ResponseFuture) -> JoinHandle<Result<(), h2::Error>> {
    tokio::spawn(async move { drain(response.await?.into_body()).await })
}

fn assert_ended_with_connection(result: Result<(), h2::Error>, context: impl std::fmt::Debug) {
    let error = result.expect_err("exchange outlived its connection");
    assert!(
        error.is_go_away() && error.is_library(),
        "{context:?}: {error:?}"
    );
    assert_eq!(
        error.reason(),
        Some(Reason::ENHANCE_YOUR_CALM),
        "{context:?}"
    );
}

/// The outcome of a client exchange whose response is `broken` with no budget left for it.
async fn client_exchange(broken: Broken, request_ended: bool) -> Result<(), h2::Error> {
    let (io, mut srv) = mock::new();
    let peer = async move {
        srv.assert_client_handshake().await;
        let request = frames::headers(1).request("POST", "https://example.com/");
        srv.recv_frame(if request_ended {
            request.eos()
        } else {
            request
        })
        .await;
        srv.send_frame(broken.head(frames::headers(1).response(200)))
            .await;
        if let Some(frame) = broken.after_head() {
            // paused clock: elapses once the client surfaced the response head
            idle_ms(1).await;
            srv.send_frame(frame).await;
        }
        srv.recv_frame(frames::go_away(0).calm().data("too_many_refused_streams"))
            .await;
    };
    let client = async move {
        let (mut client, conn) = client::Builder::new()
            .with_refused_stream_budget(RateBudget::lifetime(0))
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let conn = tokio::spawn(conn);
        let request = Request::post("https://example.com/").body(()).unwrap();
        let (response, _request_body) = client.send_request(request, request_ended).unwrap();
        let exchange = exchange(response);
        assert!(conn.await.unwrap().is_err());
        exchange.await.unwrap()
    };
    join(peer, client).await.1
}

#[tokio::test(start_paused = true)]
async fn client_response_breaking_the_error_budget_fails_with_the_connection() {
    timeout(LIMIT, async {
        for broken in Broken::HEADS {
            for request_ended in [true, false] {
                let result = client_exchange(broken, request_ended).await;
                assert_ended_with_connection(result, (broken, request_ended));
            }
        }
    })
    .await
    .expect("a response outlived its connection");
}

#[tokio::test(start_paused = true)]
async fn client_response_body_breaking_the_error_budget_fails_with_the_connection() {
    timeout(LIMIT, async {
        for broken in Broken::BODIES {
            for request_ended in [true, false] {
                let result = client_exchange(broken, request_ended).await;
                assert_ended_with_connection(result, (broken, request_ended));
            }
        }
    })
    .await
    .expect("a response body outlived its connection");
}

/// Once the connection ended, every exchange it carried has ended with it.
#[tokio::test(start_paused = true)]
async fn no_client_exchange_outlives_a_connection_ended_by_the_error_budget() {
    const STREAMS: [u32; 4] = [1, 3, 5, 7];

    timeout(LIMIT, async {
        let (io, mut srv) = mock::new();
        let peer = async move {
            srv.assert_client_handshake().await;
            for id in STREAMS {
                srv.recv_frame(
                    frames::headers(id)
                        .request("GET", "https://example.com/")
                        .eos(),
                )
                .await;
            }
            // one exchange awaits its head, one its body, one its end, one is in error
            srv.send_frame(frames::headers(3).response(200)).await;
            srv.send_frame(frames::headers(5).response(200)).await;
            srv.send_frame(frames::data(5, "hello")).await;
            srv.send_frame(Broken::HeadEndingStream.head(frames::headers(7).response(200)))
                .await;
            srv.recv_frame(frames::go_away(0).calm().data("too_many_refused_streams"))
                .await;
        };
        let client = async move {
            let (mut client, conn) = client::Builder::new()
                .with_refused_stream_budget(RateBudget::lifetime(0))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let conn = tokio::spawn(conn);
            let exchanges: Vec<_> = STREAMS
                .iter()
                .map(|_| {
                    let request = Request::get("https://example.com/").body(()).unwrap();
                    exchange(client.send_request(request, true).unwrap().0)
                })
                .collect();
            assert!(conn.await.unwrap().is_err());
            assert_eq!(client.num_refused_streams(), 1);
            for (id, exchange) in STREAMS.iter().zip(exchanges) {
                assert_ended_with_connection(exchange.await.unwrap(), id);
            }
        };
        join(peer, client).await;
    })
    .await
    .expect("an exchange outlived its connection");
}

/// The outcome of reading a request body `broken` with no budget left for it, by a server
/// that has or has not `responded` in full.
async fn server_exchange(broken: Broken, responded: bool) -> Result<(), h2::Error> {
    let (io, mut client) = mock::new();
    let peer = async move {
        client.assert_server_handshake().await;
        client
            .send_frame(broken.head(frames::headers(1).request("POST", "https://example.com/")))
            .await;
        if responded {
            client
                .recv_frame(frames::headers(1).response(200).eos())
                .await;
        }
        if let Some(frame) = broken.after_head() {
            // paused clock: elapses once the server accepted the request
            idle_ms(1).await;
            client.send_frame(frame).await;
        }
        client
            .recv_frame(frames::go_away(1).calm().data("too_many_refused_streams"))
            .await;
    };
    let server = async move {
        let mut conn = server::Builder::new()
            .with_refused_stream_budget(RateBudget::lifetime(0))
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (request, mut respond) = conn.next().await.unwrap().unwrap();
        if responded {
            respond.send_response(Response::new(()), true).unwrap();
        }
        let body = tokio::spawn(drain(request.into_body()));
        assert!(conn.next().await.unwrap().is_err());
        body.await.unwrap()
    };
    join(peer, server).await.1
}

#[tokio::test(start_paused = true)]
async fn server_request_body_breaking_the_error_budget_fails_with_the_connection() {
    timeout(LIMIT, async {
        for broken in Broken::BODIES {
            for responded in [false, true] {
                let result = server_exchange(broken, responded).await;
                assert_ended_with_connection(result, (broken, responded));
            }
        }
    })
    .await
    .expect("a request body outlived its connection");
}

/// A request broken from its head on is never handed to the server's service.
#[tokio::test(start_paused = true)]
async fn server_request_head_breaking_the_error_budget_is_never_accepted() {
    timeout(LIMIT, async {
        for broken in Broken::HEADS {
            let (io, mut client) = mock::new();
            let peer = async move {
                client.assert_server_handshake().await;
                let request = frames::headers(1).request("POST", "https://example.com/");
                client.send_frame(broken.head(request)).await;
                client
                    .recv_frame(frames::go_away(1).calm().data("too_many_refused_streams"))
                    .await;
            };
            let server = async move {
                let mut conn = server::Builder::new()
                    .with_refused_stream_budget(RateBudget::lifetime(0))
                    .handshake::<_, Bytes>(io)
                    .await
                    .unwrap();
                let error = conn.next().await.unwrap().expect_err("request accepted");
                assert!(error.is_go_away() && error.is_library(), "{broken:?}");
            };
            join(peer, server).await;
        }
    })
    .await
    .expect("a broken request left the server waiting");
}

const OVERFLOW: u32 = u32::MAX - 2;

/// A request the peer opens and then breaks with a window update past the largest window.
async fn broken_request(client: &mut mock::Handle, id: u32) {
    let request = frames::headers(id).request("POST", "https://example.com/");
    client.send_frame(request).await;
    client.send_frame(frames::window_update(id, OVERFLOW)).await;
}

/// A server refusing requests past its concurrency limit and resetting streams for the
/// peer's protocol errors spends one budget on both.
#[tokio::test(start_paused = true)]
async fn server_refusals_and_protocol_errors_draw_on_one_budget() {
    timeout(LIMIT, async {
        let (io, mut client) = mock::new();
        let peer = async move {
            client.assert_server_handshake().await;
            let held = frames::headers(1).request("POST", "https://example.com/");
            client.send_frame(held).await;
            let refused = frames::headers(3).request("GET", "https://example.com/");
            client.send_frame(refused.eos()).await;
            client.recv_frame(frames::reset(3).refused()).await;
            client.send_frame(frames::window_update(1, OVERFLOW)).await;
            client.recv_frame(frames::reset(1).flow_control()).await;
            broken_request(&mut client, 5).await;
            client
                .recv_frame(frames::go_away(5).calm().data("too_many_refused_streams"))
                .await;
        };
        let server = async move {
            let mut conn = server::Builder::new()
                .with_max_concurrent_streams(1)
                .with_refused_stream_budget(RateBudget::lifetime(2))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let mut held = Vec::new();
            let error = loop {
                match conn.next().await.unwrap() {
                    Ok(exchange) => held.push(exchange),
                    Err(error) => break error,
                }
            };
            assert_ended_with_connection(Err(error), "server");
            assert_eq!(conn.num_refused_streams(), 3);
        };
        join(peer, server).await;
    })
    .await
    .expect("a server outlived its budget");
}

/// How many of `sent` requests, broken one a second, a server with `budget` resets one by
/// one before it closes the connection.
async fn server_drip_survived(budget: Option<RateBudget>, sent: u32) -> u32 {
    let (io, mut client) = mock::new();
    let peer = async move {
        client.assert_server_handshake().await;
        for n in 0..sent {
            let id = 2 * n + 1;
            broken_request(&mut client, id).await;
            let reset: frame::Frame = frames::reset(id).flow_control().into();
            if client.next().await.unwrap().unwrap() != reset {
                return n;
            }
            idle_ms(1000).await;
        }
        sent
    };
    let server = async move {
        let mut conn = server::Builder::new()
            .maybe_with_refused_stream_budget(budget)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let mut held = Vec::new();
        while let Some(Ok(exchange)) = conn.next().await {
            held.push(exchange);
        }
    };
    join(peer, server).await.0
}

/// A server's budget regains its tokens with time, so a peer erring below the rate is only
/// ended by a ceiling on the lifetime total, a zero rate, or nothing at all.
#[tokio::test(start_paused = true)]
async fn server_budget_rate_ceiling_and_absence_decide_the_fate_of_a_steady_drip() {
    timeout(Duration::from_mins(5), async {
        let budget = RateBudget::new(2, 1);
        assert_eq!(server_drip_survived(Some(budget), 20).await, 20);
        assert_eq!(
            server_drip_survived(Some(budget.with_ceiling(6)), 20).await,
            6
        );
        assert_eq!(
            server_drip_survived(Some(RateBudget::lifetime(4)), 20).await,
            4
        );
        assert_eq!(server_drip_survived(None, 20).await, 20);
    })
    .await
    .expect("a drip left the server waiting");
}

/// The next frame a server sends that is no flow-control credit.
async fn next_stream_error(client: &mut mock::Handle) -> frame::Frame {
    loop {
        let frame = client.next().await.unwrap().unwrap();
        if !matches!(frame, frame::Frame::WindowUpdate(_)) {
            return frame;
        }
    }
}

/// A connection served for a service draws on the budget its builder was given.
#[tokio::test(start_paused = true)]
async fn served_connection_applies_the_refused_stream_budget_of_its_builder() {
    timeout(LIMIT, async {
        let (io, mut client) = mock::new();
        let peer = async move {
            client.assert_server_handshake().await;
            broken_request(&mut client, 1).await;
            let reset: frame::Frame = frames::reset(1).flow_control().into();
            assert_eq!(next_stream_error(&mut client).await, reset);
            broken_request(&mut client, 3).await;
            let closed = frames::go_away(3).calm().data("too_many_refused_streams");
            assert_eq!(next_stream_error(&mut client).await, closed.into());
        };
        let server = async move {
            let service = RamaHttpService::new(service_fn(|_: Request<Body>| async {
                pending::<()>().await;
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
            let served = http2::Builder::new(WeakScope::detached())
                .with_refused_stream_budget(RateBudget::lifetime(1))
                .serve_connection(ServiceInput::new(io), service)
                .await;
            assert!(served.is_err());
        };
        join(peer, server).await;
    })
    .await
    .expect("a served connection outlived its budget");
}

/// A client that forgets a stream it reset at once, with no budget for a refused stream.
async fn forgetful_client(
    io: mock::Mock,
) -> (
    client::SendRequest<Bytes>,
    JoinHandle<Result<(), h2::Error>>,
) {
    let (client, conn) = client::Builder::new()
        .with_max_concurrent_reset_streams(0)
        .with_refused_stream_budget(RateBudget::lifetime(0))
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();
    (client, tokio::spawn(conn))
}

fn get() -> Request<()> {
    Request::get("https://example.com/").body(()).unwrap()
}

/// Another response after a completed exchange is a peer error, not a raced cancellation.
#[tokio::test(start_paused = true)]
async fn client_response_after_a_completed_exchange_draws_on_the_budget() {
    timeout(LIMIT, async {
        let (io, mut srv) = mock::new();
        let (completed, completion) = oneshot::channel();
        let peer = async move {
            srv.assert_client_handshake().await;
            for id in [1, 3] {
                let request = frames::headers(id).request("GET", "https://example.com/");
                srv.recv_frame(request.eos()).await;
            }
            srv.send_frame(frames::headers(3).response(200).eos()).await;
            completion.await.unwrap();
            srv.send_frame(frames::headers(3).response(200)).await;
            srv.recv_frame(frames::go_away(0).calm().data("too_many_refused_streams"))
                .await;
        };
        let client = async move {
            let (mut client, conn) = client::Builder::new()
                .with_refused_stream_budget(RateBudget::lifetime(0))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let conn = tokio::spawn(conn);
            let sibling = exchange(client.send_request(get(), true).unwrap().0);
            exchange(client.send_request(get(), true).unwrap().0)
                .await
                .unwrap()
                .expect("completed exchange");
            // Its response handles are gone before the peer sends the extra head.
            completed.send(()).unwrap();
            assert!(conn.await.unwrap().is_err());
            assert_ended_with_connection(sibling.await.unwrap(), "sibling exchange");
            assert_eq!(client.num_refused_streams(), 1);
        };
        join(peer, client).await;
    })
    .await
    .expect("a response after a completed exchange left the client waiting");
}

/// A response racing a retained cancellation is ignored without spending the budget.
#[tokio::test(start_paused = true)]
async fn client_response_racing_its_cancellation_does_not_draw_on_the_budget() {
    timeout(LIMIT, async {
        let (io, mut srv) = mock::new();
        let peer = async move {
            srv.assert_client_handshake().await;
            for id in [1, 3] {
                let request = frames::headers(id).request("GET", "https://example.com/");
                srv.recv_frame(request.eos()).await;
            }
            srv.recv_frame(frames::reset(3).cancel()).await;
            srv.send_frame(frames::headers(3).response(200)).await;
            srv.send_frame(frames::data(3, "hello").eos()).await;
            srv.send_frame(frames::headers(1).response(200)).await;
            srv.send_frame(frames::data(1, "hello").eos()).await;
            // the client leaves once its last exchange ended, not for a spent budget
            srv.recv_frame(frames::go_away(0).no_error()).await;
            srv.recv_eof().await;
        };
        let client = async move {
            let (mut client, conn) = client::Builder::new()
                .with_refused_stream_budget(RateBudget::lifetime(0))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let conn = tokio::spawn(conn);
            let sibling = exchange(client.send_request(get(), true).unwrap().0);
            drop(client.send_request(get(), true).unwrap());
            sibling.await.unwrap().expect("sibling exchange");
            assert_eq!(client.num_refused_streams(), 0);
            drop(client);
            conn.await.unwrap().expect("connection");
        };
        join(peer, client).await;
    })
    .await
    .expect("a raced cancellation left the client waiting");
}

#[tokio::test(start_paused = true)]
async fn client_response_after_a_forgotten_cancellation_draws_on_the_budget() {
    timeout(LIMIT, async {
        let (io, mut srv) = mock::new();
        let peer = async move {
            srv.assert_client_handshake().await;
            for id in [1, 3] {
                srv.recv_frame(
                    frames::headers(id)
                        .request("GET", "https://example.com/")
                        .eos(),
                )
                .await;
            }
            srv.recv_frame(frames::reset(3).cancel()).await;
            srv.send_frame(frames::headers(3).response(200)).await;
            srv.recv_frame(frames::go_away(0).calm().data("too_many_refused_streams"))
                .await;
        };
        let client = async move {
            let (mut client, conn) = forgetful_client(io).await;
            let sibling = exchange(client.send_request(get(), true).unwrap().0);
            drop(client.send_request(get(), true).unwrap());
            assert!(conn.await.unwrap().is_err());
            assert_ended_with_connection(sibling.await.unwrap(), "sibling exchange");
            assert_eq!(client.num_refused_streams(), 1);
        };
        join(peer, client).await;
    })
    .await
    .expect("a forgotten cancellation left the client waiting");
}

/// A frame for a stream the peer opened and this side has forgotten is the peer's to
/// account for, as is one for a stream this side never cancelled.
#[tokio::test(start_paused = true)]
async fn server_frame_for_a_forgotten_request_draws_on_the_budget() {
    timeout(LIMIT, async {
        let (io, mut client) = mock::new();
        let peer = async move {
            client.assert_server_handshake().await;
            let request = frames::headers(1).request("POST", "https://example.com/");
            client.send_frame(request).await;
            client.recv_frame(frames::reset(1).cancel()).await;
            client.send_frame(frames::data(1, "hello")).await;
            client
                .recv_frame(frames::go_away(1).calm().data("too_many_refused_streams"))
                .await;
        };
        let server = async move {
            let mut conn = server::Builder::new()
                .with_max_concurrent_reset_streams(0)
                .with_refused_stream_budget(RateBudget::lifetime(0))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let (request, mut respond) = conn.next().await.unwrap().unwrap();
            respond.send_reset(Reason::CANCEL);
            // Nothing holds the stream any more, so the connection forgets it.
            drop((request, respond));
            let error = conn.next().await.unwrap().expect_err("connection kept");
            assert_ended_with_connection(Err(error), "server");
            assert_eq!(conn.num_refused_streams(), 1);
        };
        join(peer, server).await;
    })
    .await
    .expect("a frame for a forgotten request left the server waiting");
}

const HEADER_LIST_LIMIT: u32 = 256;

/// A request whose head is larger than `HEADER_LIST_LIMIT`, unlike one without the field.
fn oversized_request(id: u32) -> frames::Mock<frame::Headers> {
    frames::headers(id)
        .request("GET", "https://example.com/")
        .field("some-header", "x".repeat(HEADER_LIST_LIMIT as usize / 2))
        .eos()
}

/// A server answers a request head over its limit itself, and counts the refusal against
/// the peer: past the budget the connection ends, and the requests in flight with it.
#[tokio::test(start_paused = true)]
async fn server_oversized_request_heads_draw_on_the_budget() {
    timeout(LIMIT, async {
        let (io, mut client) = mock::new();
        let peer = async move {
            client.assert_server_handshake().await;
            let held = frames::headers(1).request("POST", "https://example.com/");
            client.send_frame(held).await;
            client.send_frame(oversized_request(3)).await;
            client
                .recv_frame(frames::headers(3).response(431).eos())
                .await;
            client.send_frame(oversized_request(5)).await;
            client
                .recv_frame(frames::go_away(5).calm().data("too_many_refused_streams"))
                .await;
        };
        let server = async move {
            let mut conn = server::Builder::new()
                .with_max_header_list_size(HEADER_LIST_LIMIT)
                .with_refused_stream_budget(RateBudget::lifetime(1))
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let (request, _respond) = conn.next().await.unwrap().unwrap();
            let body = tokio::spawn(drain(request.into_body()));
            let error = conn.next().await.unwrap().expect_err("connection kept");
            assert_ended_with_connection(Err(error), "server");
            assert_eq!(conn.num_refused_streams(), 2);
            assert_ended_with_connection(body.await.unwrap(), "request in flight");
        };
        join(peer, server).await;
    })
    .await
    .expect("an oversized request head left the server waiting");
}

/// Within the budget a request head over the limit costs only that request.
#[tokio::test(start_paused = true)]
async fn server_keeps_serving_after_an_oversized_request_head_within_the_budget() {
    timeout(LIMIT, async {
        let (io, mut client) = mock::new();
        let peer = async move {
            client.assert_server_handshake().await;
            client.send_frame(oversized_request(1)).await;
            client
                .recv_frame(frames::headers(1).response(431).eos())
                .await;
            let request = frames::headers(3).request("GET", "https://example.com/");
            client.send_frame(request.eos()).await;
            client
                .recv_frame(frames::headers(3).response(200).eos())
                .await;
        };
        let server = async move {
            let mut conn = server::Builder::new()
                .with_max_header_list_size(HEADER_LIST_LIMIT)
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let (_request, mut respond) = conn.next().await.unwrap().unwrap();
            respond.send_response(Response::new(()), true).unwrap();
            assert!(conn.next().await.is_none());
            assert_eq!(conn.num_refused_streams(), 1);
        };
        join(peer, server).await;
    })
    .await
    .expect("an oversized request head left the server waiting");
}
