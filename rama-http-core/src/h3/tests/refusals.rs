//! Streams ended for what the peer sent draw on a connection budget; a spent budget closes it.

use super::{LIMIT, Pair};
use crate::{
    h3::{
        Error, RateBudget, client,
        connection::Config,
        push::Pushes,
        qpack::{Encoder, EncoderConfig, ErrorScope},
        server,
    },
    server::conn::HeaderReadTimeout,
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    graceful::WeakScope,
    rt::spawn,
};
use rama_http_types::{
    Body, Request, Response,
    proto::h3::{Code, FrameHeader, FrameType, StreamType},
};
use rama_net::uri::Uri;
use rama_quic::{Connection as QuicConnection, ConnectionError, RecvStream};
use rama_quic_proto::{VarInt, coding::Codec as _};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Notify,
    time::{Instant, advance, timeout},
};

type Server = server::Connection<QuicConnection>;
type Responder = server::SendResponse<QuicConnection>;
type Client = client::SendRequest<Body, QuicConnection>;

fn head(fields: &[(&str, &str)]) -> Bytes {
    let fields = Encoder::before_peer_settings(EncoderConfig::default())
        .encode(0, fields.iter().copied())
        .unwrap();
    let mut bytes = BytesMut::new();
    FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
        .encode(&mut bytes)
        .unwrap();
    bytes.extend_from_slice(&fields);
    bytes.freeze()
}

const VALID_HEAD: [(&str, &str); 4] = [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "localhost"),
    (":path", "/"),
];

fn valid_head() -> Bytes {
    head(&VALID_HEAD)
}

/// A server with `budget` and a peer that speaks raw QUIC streams to it.
async fn raw_peer(budget: Option<RateBudget>, config: Config) -> (Pair, Server) {
    let pair = Pair::in_memory(None, None).await;
    let config = Config {
        refused_stream_budget: budget,
        ..config
    };
    let (server, driver) = server::handshake(pair.server.clone(), config).unwrap();
    spawn(driver.run());
    (pair, server)
}

/// The peer sends a request head without a method; the error the server ends it with.
async fn malformed_request(pair: &Pair, server: &mut Server) -> Error {
    let (mut send, _recv) = pair.client.open_bi().await.unwrap();
    send.write_chunk(head(&[(":scheme", "https"), (":path", "/")]))
        .await
        .unwrap();
    let error = server
        .accept()
        .await
        .unwrap()
        .resolve()
        .await
        .err()
        .unwrap();
    if error.scope() == ErrorScope::Stream {
        assert_eq!(
            send.stopped().await.unwrap().map(u64::from),
            Some(error.code().value())
        );
    }
    error
}

/// The peer sends a complete request that the server accepts.
async fn open_request(pair: &Pair, server: &mut Server) -> (RecvStream, Responder) {
    let (mut send, recv) = pair.client.open_bi().await.unwrap();
    send.write_chunk(valid_head()).await.unwrap();
    send.finish().unwrap();
    let (_request, responder) = server.accept().await.unwrap().resolve().await.unwrap();
    (recv, responder)
}

/// Whether the response to an accepted request reaches the peer.
async fn answered(recv: &mut RecvStream, responder: Responder) -> bool {
    let sent = spawn(responder.send_response(Response::new(Body::empty())));
    let received = recv.read_to_end(1024).await;
    sent.await.unwrap().is_ok() && received.is_ok_and(|bytes| !bytes.is_empty())
}

async fn served(pair: &Pair, server: &mut Server) -> bool {
    let (mut recv, responder) = open_request(pair, server).await;
    answered(&mut recv, responder).await
}

/// The peer of `connection` saw it closed for a spent refused stream budget.
async fn assert_closed_for_refusals(connection: &QuicConnection) {
    let reason = connection.closed().await;
    let ConnectionError::ApplicationClosed(close) = reason else {
        panic!("expected HTTP/3 application close: {reason:?}");
    };
    assert_eq!(
        close.error_code.into_inner(),
        Code::H3_EXCESSIVE_LOAD.value()
    );
    // The reason tells this close apart from one for any other connection error.
    let other = Error::connection(Code::H3_EXCESSIVE_LOAD, "another cause").close_reason();
    assert_ne!(close.reason.as_ref(), other);
    assert!(!close.reason.is_empty());
}

fn assert_spent(error: Error) {
    assert_eq!(error, Error::TOO_MANY_REFUSED_STREAMS);
    assert_eq!(error.scope(), ErrorScope::Connection);
    assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
}

#[tokio::test(start_paused = true)]
async fn refused_streams_within_the_budget_leave_a_server_connection_usable() {
    timeout(LIMIT, async {
        let (pair, mut server) = raw_peer(Some(RateBudget::lifetime(3)), Config::default()).await;
        let (mut recv, responder) = open_request(&pair, &mut server).await;
        for _ in 0..3 {
            let error = malformed_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        }
        assert!(answered(&mut recv, responder).await);
        assert!(served(&pair, &mut server).await);
        assert!(pair.client.close_reason().is_none());
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn refused_streams_past_the_budget_close_a_server_connection() {
    timeout(LIMIT, async {
        let (pair, mut server) = raw_peer(Some(RateBudget::lifetime(3)), Config::default()).await;
        let (mut recv, responder) = open_request(&pair, &mut server).await;
        for _ in 0..3 {
            let error = malformed_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        assert_spent(malformed_request(&pair, &mut server).await);
        assert_closed_for_refusals(&pair.client).await;
        assert!(!answered(&mut recv, responder).await);
        assert!(server.accept().await.is_err());
        pair.close().await;
    })
    .await
    .unwrap();
}

/// The peer sends a request head larger than the server's field-section limit.
async fn oversized_request(pair: &Pair, server: &mut Server) -> Error {
    let (mut send, _recv) = pair.client.open_bi().await.unwrap();
    let value = "v".repeat(SECTION_LIMIT);
    send.write_chunk(head(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", "/"),
        ("x-large", &value),
    ]))
    .await
    .unwrap();
    server
        .accept()
        .await
        .unwrap()
        .resolve()
        .await
        .err()
        .unwrap()
}

const SECTION_LIMIT: usize = 256;

#[tokio::test(start_paused = true)]
async fn a_stream_refused_for_a_local_limit_is_charged_once() {
    timeout(LIMIT, async {
        let mut config = Config::default();
        config.decoder.max_field_section_size = SECTION_LIMIT;
        let (pair, mut server) = raw_peer(Some(RateBudget::lifetime(4)), config).await;
        for _ in 0..4 {
            let error = oversized_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        }
        assert!(served(&pair, &mut server).await);
        assert_spent(oversized_request(&pair, &mut server).await);
        assert_closed_for_refusals(&pair.client).await;
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_spent_refused_stream_budget_is_regained_over_time() {
    timeout(LIMIT, async {
        let (pair, mut server) = raw_peer(Some(RateBudget::new(2, 1)), Config::default()).await;
        let start = Instant::now();
        for _ in 0..2 {
            let error = malformed_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        // The burst went before the clock could return any of it.
        assert!(start.elapsed() < Duration::from_secs(1));
        advance(Duration::from_secs(2)).await;
        let regained = Instant::now();
        for _ in 0..2 {
            let error = malformed_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        assert!(regained.elapsed() < Duration::from_secs(1));
        assert_spent(malformed_request(&pair, &mut server).await);
        pair.close().await;
    })
    .await
    .unwrap();
}

/// How many of `sent` malformed requests, one every other second, a server with `budget`
/// ends one by one before it closes the connection.
async fn drip_survived(budget: RateBudget, sent: u64) -> u64 {
    let config = Config {
        idle_timeout: None,
        ..Config::default()
    };
    let (pair, mut server) = raw_peer(Some(budget), config).await;
    let mut survived = 0;
    while survived < sent
        && malformed_request(&pair, &mut server).await.scope() == ErrorScope::Stream
    {
        survived += 1;
        advance(Duration::from_secs(2)).await;
    }
    assert_eq!(server.refused_streams(), sent.min(survived + 1));
    if survived == sent {
        assert!(served(&pair, &mut server).await);
    } else {
        assert_closed_for_refusals(&pair.client).await;
    }
    pair.close().await;
    survived
}

#[tokio::test(start_paused = true)]
async fn only_a_ceiling_ends_a_steady_drip_below_the_rate() {
    timeout(Duration::from_mins(5), async {
        let budget = RateBudget::new(2, 1);
        assert_eq!(drip_survived(budget, 12).await, 12);
        assert_eq!(drip_survived(budget.with_ceiling(5), 12).await, 5);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn without_a_refused_stream_budget_refused_streams_never_close_the_connection() {
    timeout(LIMIT, async {
        let (pair, mut server) = raw_peer(None, Config::default()).await;
        for _ in 0..64 {
            let error = malformed_request(&pair, &mut server).await;
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        assert!(served(&pair, &mut server).await);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn streams_a_server_ends_for_other_causes_are_not_charged() {
    timeout(LIMIT, async {
        // No refusal is covered, so any charge would close the connection.
        let config = Config {
            header_read_timeout: Some(HeaderReadTimeout {
                grace: Duration::from_millis(100),
                min_rate: u32::MAX,
                ceiling: Duration::from_secs(1),
            }),
            idle_timeout: None,
            ..Config::default()
        };
        let (pair, mut server) = raw_peer(Some(RateBudget::lifetime(0)), config).await;

        // The peer cancels its own request.
        let (mut send, _recv) = pair.client.open_bi().await.unwrap();
        send.write_chunk(Bytes::from_static(b"\x01")).await.unwrap();
        let request = server.accept().await.unwrap();
        send.reset(Code::H3_REQUEST_CANCELLED.value() as u32)
            .unwrap();
        assert_eq!(
            request.resolve().await.err().unwrap().scope(),
            ErrorScope::Stream
        );

        // The application drops a request it accepted.
        let (mut recv, responder) = open_request(&pair, &mut server).await;
        drop(responder);
        recv.read_to_end(1024).await.unwrap_err();

        // The application's own deadline for a request head passes.
        let (mut send, _recv) = pair.client.open_bi().await.unwrap();
        send.write_chunk(Bytes::from_static(b"\x01")).await.unwrap();
        let error = server
            .accept()
            .await
            .unwrap()
            .resolve()
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), Code::H3_REQUEST_REJECTED);

        assert!(served(&pair, &mut server).await);
        assert!(pair.client.close_reason().is_none());
        assert_spent(malformed_request(&pair, &mut server).await);
        pair.close().await;
    })
    .await
    .unwrap();
}

const INTERIM_ALLOWED: usize = 1;

/// A client with `budget` and an origin that answers `/flood` with more interim responses
/// than the client allows, `/hold` once `release` is notified and anything else at once.
async fn flooding_origin(budget: Option<RateBudget>) -> (Pair, Client, Arc<Notify>) {
    origin(Config {
        max_informational_responses: INTERIM_ALLOWED,
        refused_stream_budget: budget,
        ..Config::default()
    })
    .await
}

/// The origin of [`flooding_origin`], for a client with `config`.
async fn origin(config: Config) -> (Pair, Client, Arc<Notify>) {
    let pair = Pair::in_memory(None, None).await;
    let (client, client_driver) =
        client::handshake::<Body, _>(pair.client.clone(), config, WeakScope::detached()).unwrap();
    let (mut server, server_driver) =
        server::handshake(pair.server.clone(), Config::default()).unwrap();
    spawn(client_driver.run());
    spawn(server_driver.run());
    let release = Arc::new(Notify::new());
    let held = release.clone();
    spawn(async move {
        while let Ok(stream) = server.accept().await {
            let held = held.clone();
            spawn(async move {
                let Ok((request, mut responder)) = stream.resolve().await else {
                    return;
                };
                let target = request.uri().request_target();
                if target == "/flood" {
                    for _ in 0..=INTERIM_ALLOWED {
                        let interim = Response::builder().status(103).body(()).unwrap();
                        if responder.send_informational(interim).await.is_err() {
                            return;
                        }
                    }
                } else if target == "/hold" {
                    held.notified().await;
                }
                _ = responder.send_response(Response::new(Body::empty())).await;
            });
        }
    });
    (pair, client, release)
}

async fn get(client: &mut Client, path: &'static str) -> Result<(), Error> {
    let uri = Uri::parse(format!("https://localhost{path}")).unwrap();
    let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    client.send_request(request).await.map(drop)
}

#[tokio::test(start_paused = true)]
async fn refused_responses_within_the_budget_leave_a_client_connection_usable() {
    timeout(LIMIT, async {
        let (pair, mut client, release) = flooding_origin(Some(RateBudget::lifetime(2))).await;
        let mut sibling = client.clone();
        let held = spawn(async move { get(&mut sibling, "/hold").await });
        for _ in 0..2 {
            let error = get(&mut client, "/flood").await.unwrap_err();
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        }
        release.notify_one();
        held.await.unwrap().unwrap();
        get(&mut client, "/").await.unwrap();
        assert!(pair.server.close_reason().is_none());
        assert_eq!(client.refused_streams(), 2);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn refused_responses_past_the_budget_close_a_client_connection() {
    timeout(LIMIT, async {
        let (pair, mut client, _release) = flooding_origin(Some(RateBudget::lifetime(2))).await;
        let mut sibling = client.clone();
        let held = spawn(async move { get(&mut sibling, "/hold").await });
        for _ in 0..2 {
            let error = get(&mut client, "/flood").await.unwrap_err();
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        assert_spent(get(&mut client, "/flood").await.unwrap_err());
        assert_closed_for_refusals(&pair.server).await;
        held.await.unwrap().unwrap_err();
        get(&mut client, "/").await.unwrap_err();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn requests_a_client_cancels_itself_are_not_charged() {
    timeout(LIMIT, async {
        // No refusal is covered, so any charge would close the connection.
        let (pair, mut client, _release) = flooding_origin(Some(RateBudget::lifetime(0))).await;
        for _ in 0..4 {
            let mut sibling = client.clone();
            let held = spawn(async move { get(&mut sibling, "/hold").await });
            get(&mut client, "/").await.unwrap();
            held.abort();
            assert!(held.await.unwrap_err().is_cancelled());
        }
        get(&mut client, "/").await.unwrap();
        assert!(pair.server.close_reason().is_none());
        assert_spent(get(&mut client, "/flood").await.unwrap_err());
        pair.close().await;
    })
    .await
    .unwrap();
}

/// A client with `budget` that takes pushes, its push consumer, and its origin.
async fn pushed_to(budget: Option<RateBudget>) -> (Pair, Client, Pushes, Arc<Notify>) {
    let (pair, mut client, release) = origin(Config {
        max_pushes: 1,
        refused_stream_budget: budget,
        ..Config::default()
    })
    .await;
    let pushes = client.take_pushes().unwrap();
    // A round trip leaves the client's driver the time to grant its push quota.
    get(&mut client, "/").await.unwrap();
    (pair, client, pushes, release)
}

/// The origin pushes a response head without a status; the error the client ends it with.
async fn malformed_push(pair: &Pair, client: &Client, pushes: &mut Pushes) -> Error {
    const ID: u32 = 0;
    let promised = Encoder::before_peer_settings(EncoderConfig::default())
        .encode(0, VALID_HEAD)
        .unwrap();
    let origin = Uri::parse("https://localhost/").unwrap();
    client
        .shared()
        .promise(0, u64::from(ID), promised, Some(origin))
        .await
        .unwrap();
    let mut stream = BytesMut::new();
    VarInt::from_u32(StreamType::PUSH.value() as u32).encode(&mut stream);
    VarInt::from_u32(ID).encode(&mut stream);
    stream.extend_from_slice(&head(&[("content-type", "text/plain")]));
    let mut send = pair.server.open_uni().await.unwrap();
    send.write_chunk(stream.freeze()).await.unwrap();
    let error = pushes.next().await.unwrap().response().await.err().unwrap();
    if error.scope() == ErrorScope::Stream {
        assert_eq!(
            send.stopped().await.unwrap().map(u64::from),
            Some(error.code().value())
        );
    }
    error
}

#[tokio::test(start_paused = true)]
async fn a_malformed_pushed_response_is_refused_and_charged_once() {
    timeout(LIMIT, async {
        let (pair, mut client, mut pushes, release) =
            pushed_to(Some(RateBudget::lifetime(1))).await;
        let mut sibling = client.clone();
        let held = spawn(async move { get(&mut sibling, "/hold").await });
        let before = client.refused_streams();
        let error = malformed_push(&pair, &client, &mut pushes).await;
        assert_eq!(error.scope(), ErrorScope::Stream);
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        assert_eq!(client.refused_streams(), before + 1);
        release.notify_one();
        held.await.unwrap().unwrap();
        get(&mut client, "/").await.unwrap();
        assert!(pair.server.close_reason().is_none());
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_malformed_pushed_response_past_the_budget_closes_a_client_connection() {
    timeout(LIMIT, async {
        let (pair, mut client, mut pushes, _release) =
            pushed_to(Some(RateBudget::lifetime(0))).await;
        let mut sibling = client.clone();
        let held = spawn(async move { get(&mut sibling, "/hold").await });
        assert_spent(malformed_push(&pair, &client, &mut pushes).await);
        assert_closed_for_refusals(&pair.server).await;
        held.await.unwrap().unwrap_err();
        get(&mut client, "/").await.unwrap_err();
        pair.close().await;
    })
    .await
    .unwrap();
}
