use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::{
    Layer as _, Service, ServiceInput, error::BoxError, extensions::ExtensionsRef as _,
    futures::stream, graceful::Shutdown, service::service_fn,
};
use rama_http::layer::follow_redirect::FollowRedirect;
use rama_http_types::{
    HeaderValue, Request, Response, Version,
    body::{OnIncompleteBody, util::BodyExt as _},
    conn::TargetHttpVersion,
    proto::h1::ext::ConnectionClose,
};
use rama_net::{
    client::{
        ConnectRequest, ConnectorService, EstablishedClientConnection, pool::SaturationPolicy,
    },
    test_utils::client::{MockConnectorService, MockSocket},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Notify, oneshot},
    time::timeout,
};

use super::*;
use crate::client::{
    BindBodyToConnLayer, HttpConnectRequestAdapter, HttpConnectorLayer, HttpPooledConnectorConfig,
    http_connect,
};
use crate::server::HttpServer;

const LIMIT: Duration = Duration::from_secs(10);

fn drains_started() -> usize {
    DRAINS_STARTED.with(std::cell::Cell::get)
}

/// What a scripted origin does to answer one request.
#[derive(Clone)]
enum Step {
    Write(Bytes),
    /// Wait until the test lets the response continue.
    Wait(Arc<Notify>),
    Sleep(Duration),
    /// Write this until the client goes away: an endless body.
    Repeat(Bytes),
    /// Close the connection.
    Close,
}

type Script = Arc<dyn Fn(&str, usize) -> Vec<Step> + Send + Sync>;

/// A raw HTTP/1 origin: answers each request on connection `conn` (counted
/// from 0) with `script(path, conn)`, byte for byte.
async fn serve_scripted(mut socket: MockSocket, conn: usize, script: Script) {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 1024];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        buf.drain(..head_end);
        let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
        for step in script(&path, conn) {
            match step {
                Step::Write(bytes) => {
                    if socket.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                Step::Wait(notify) => notify.notified().await,
                Step::Sleep(duration) => tokio::time::sleep(duration).await,
                Step::Repeat(bytes) => {
                    while socket.write_all(&bytes).await.is_ok() {}
                    return;
                }
                Step::Close => return,
            }
        }
    }
}

fn head(conn: usize, status: &str, headers: &str) -> String {
    format!("{status}\r\nx-conn-id: {conn}\r\n{headers}\r\n")
}

/// A complete `200 OK` with a content-length body.
fn sized(conn: usize, body: &[u8]) -> Vec<Step> {
    let mut bytes = head(
        conn,
        "HTTP/1.1 200 OK",
        &format!("content-length: {}\r\n", body.len()),
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    vec![Step::Write(bytes.into())]
}

fn chunk(data: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{:x}\r\n", data.len()).into_bytes();
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(b"\r\n");
    bytes
}

/// A complete chunked `200 OK`, ending in `trailers` (raw header lines).
fn chunked(conn: usize, chunks: &[&[u8]], trailers: &str) -> Vec<Step> {
    let mut bytes = head(conn, "HTTP/1.1 200 OK", "transfer-encoding: chunked\r\n").into_bytes();
    for data in chunks {
        bytes.extend(chunk(data));
    }
    bytes.extend_from_slice(format!("0\r\n{trailers}\r\n").as_bytes());
    vec![Step::Write(bytes.into())]
}

struct Harness<C> {
    client: C,
    drain: Option<Arc<Http1BodyDrain>>,
    accepted: Arc<AtomicUsize>,
}

fn harness(
    config: HttpPooledConnectorConfig,
    exec: Executor,
    script: impl Fn(&str, usize) -> Vec<Step> + Send + Sync + 'static,
) -> Harness<
    impl ConnectorService<Request, Connection: Service<Request, Output = Response, Error = BoxError>>,
> {
    let (mock, accepted) = scripted_origin(script);
    let connector = config.build_connector(HttpConnectorLayer::<Body>::new(exec).into_layer(mock));
    let drain = connector.drain.clone();
    Harness {
        client: HttpConnectRequestAdapter::new(connector),
        drain,
        accepted,
    }
}

/// A connector to a [`serve_scripted`] origin, counting its connections.
fn scripted_origin(
    script: impl Fn(&str, usize) -> Vec<Step> + Send + Sync + 'static,
) -> (
    impl ConnectorService<ConnectRequest, Connection = MockSocket> + Clone,
    Arc<AtomicUsize>,
) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let script: Script = Arc::new(script);
    let mock = MockConnectorService::new({
        let accepted = accepted.clone();
        move || {
            let conn = accepted.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            service_fn(move |socket: MockSocket| {
                let script = script.clone();
                async move {
                    serve_scripted(socket, conn, script).await;
                    Ok::<_, Infallible>(())
                }
            })
        }
    });
    (mock, accepted)
}

/// At most one connection: a request waits for it, so it shows whether a
/// dropped body's connection came back healthy without timing assumptions.
fn one_connection(drain: Option<Http1BodyDrainConfig>) -> HttpPooledConnectorConfig {
    HttpPooledConnectorConfig {
        max_connections_total: NonZeroUsize::new(1),
        saturation_policy: SaturationPolicy::Wait,
        http1_body_drain: drain,
        ..Default::default()
    }
}

fn uncapped(drain: Option<Http1BodyDrainConfig>) -> HttpPooledConnectorConfig {
    HttpPooledConnectorConfig {
        http1_body_drain: drain,
        ..Default::default()
    }
}

fn get(path: &str) -> Request {
    Request::builder()
        .uri(format!("http://origin.example{path}"))
        .body(Body::empty())
        .unwrap()
}

async fn send<C>(client: &C, request: Request) -> Response
where
    C: ConnectorService<Request, Connection: Service<Request, Output = Response, Error = BoxError>>,
{
    timeout(LIMIT, async {
        let EstablishedClientConnection { conn, input } = client.connect(request).await.unwrap();
        conn.serve(input).await.unwrap()
    })
    .await
    .expect("request deadline")
}

fn conn_id(response: &Response) -> usize {
    response.headers()["x-conn-id"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Until no drain of the connector runs: its body (and lease) was released.
async fn settled(drain: &Http1BodyDrain) {
    timeout(LIMIT, async {
        while drain.active.load(Ordering::Acquire) > 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("drain settles");
}

/// Request `path`, drop the response unread, then report the connection that
/// serves the next request on a one-connection pool.
async fn next_conn_after_dropping(
    drain: Option<Http1BodyDrainConfig>,
    script: impl Fn(&str, usize) -> Vec<Step> + Send + Sync + 'static,
    request: Request,
) -> usize {
    let harness = harness(
        one_connection(drain),
        Executor::default(),
        move |path, conn| {
            if path == "/next" {
                sized(conn, b"next")
            } else {
                script(path, conn)
            }
        },
    );
    let response = send(&harness.client, request).await;
    assert_eq!(conn_id(&response), 0);
    drop(response);
    let next = send(&harness.client, get("/next")).await;
    assert_eq!(next.into_body().collect().await.unwrap().to_bytes(), "next");
    harness.accepted.load(Ordering::SeqCst) - 1
}

// ---- successful recovery ---------------------------------------------------

#[tokio::test]
async fn unread_content_length_body_is_drained_and_reused() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| sized(conn, b"ok"),
        get("/"),
    )
    .await;
    assert_eq!(next, 0);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn disabled_draining_closes_the_connection_of_an_unread_body() {
    let next = next_conn_after_dropping(None, |_, conn| sized(conn, b"ok"), get("/")).await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn partially_read_body_is_drained_and_reused() {
    let rest = Arc::new(Notify::new());
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::default(),
        {
            let rest = rest.clone();
            move |path, conn| {
                if path == "/next" {
                    return sized(conn, b"next");
                }
                let mut first =
                    head(conn, "HTTP/1.1 200 OK", "content-length: 8192\r\n").into_bytes();
                first.extend_from_slice(&[b'a'; 1024]);
                vec![
                    Step::Write(first.into()),
                    Step::Wait(rest.clone()),
                    Step::Write(vec![b'b'; 8192 - 1024].into()),
                ]
            }
        },
    );
    let mut body = send(&harness.client, get("/")).await.into_body();
    let frame = body.frame().await.unwrap().unwrap();
    assert!(!frame.into_data().unwrap().is_empty());
    assert!(!body.is_end_stream(), "most of the body is still unread");
    rest.notify_one();
    drop(body);
    let next = send(&harness.client, get("/next")).await;
    assert_eq!(conn_id(&next), 0);
    assert_eq!(harness.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn unread_chunked_body_is_drained_and_reused() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| chunked(conn, &[b"hello", &[b'x'; 4096], b"world"], ""),
        get("/"),
    )
    .await;
    assert_eq!(next, 0);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn unread_chunked_body_with_trailers_is_drained_and_reused() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| chunked(conn, &[b"hello"], "x-checksum: 1\r\n"),
        get("/"),
    )
    .await;
    assert_eq!(next, 0);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn body_dropped_after_its_final_content_length_frame_is_not_drained() {
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::default(),
        |_, conn| sized(conn, b"complete"),
    );
    let mut body = send(&harness.client, get("/")).await.into_body();
    while !body.is_end_stream() {
        body.frame().await.unwrap().unwrap();
    }
    // no trailing `None` poll
    drop(body);
    assert_eq!(drains_started(), 0);
    let next = send(&harness.client, get("/")).await;
    assert_eq!(conn_id(&next), 0);
    next.into_body().collect().await.unwrap();
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn body_dropped_after_its_trailers_is_not_drained() {
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::default(),
        |_, conn| chunked(conn, &[b"hello"], "x-checksum: 1\r\n"),
    );
    let mut body = send(&harness.client, get("/")).await.into_body();
    loop {
        let frame = body.frame().await.unwrap().unwrap();
        if frame.is_trailers() {
            break;
        }
    }
    drop(body);
    assert_eq!(drains_started(), 0);
    assert_eq!(conn_id(&send(&harness.client, get("/")).await), 0);
}

#[tokio::test]
async fn empty_body_dropped_unpolled_is_not_drained() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| sized(conn, b""),
        get("/"),
    )
    .await;
    assert_eq!(next, 0);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn same_origin_redirect_reuses_the_connection_of_its_unread_body() {
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::default(),
        |path, conn| {
            if path == "/start" {
                let body = "moved to /final";
                let bytes = head(
                    conn,
                    "HTTP/1.1 302 Found",
                    &format!(
                        "location: http://origin.example/final\r\ncontent-length: {}\r\n",
                        body.len()
                    ),
                ) + body;
                vec![Step::Write(bytes.into_bytes().into())]
            } else {
                sized(conn, b"final")
            }
        },
    );
    let client = Arc::new(harness.client);
    let follow = FollowRedirect::new(service_fn(move |request: Request| {
        let client = client.clone();
        async move {
            let EstablishedClientConnection { conn, input } = client.connect(request).await?;
            conn.serve(input).await
        }
    }));
    let response = timeout(LIMIT, follow.serve(get("/start")))
        .await
        .expect("redirect deadline")
        .unwrap();
    assert_eq!(conn_id(&response), 0);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "final"
    );
    assert_eq!(harness.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(drains_started(), 1);
}

// ---- failure and limits ----------------------------------------------------

fn budget(max_bytes: usize) -> Option<Http1BodyDrainConfig> {
    Some(Http1BodyDrainConfig::default().with_max_bytes(max_bytes))
}

#[tokio::test]
async fn body_over_the_byte_budget_closes_the_connection() {
    let next =
        next_conn_after_dropping(budget(1000), |_, conn| sized(conn, &[0; 5000]), get("/")).await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn body_ending_exactly_at_the_byte_budget_is_reused() {
    let next =
        next_conn_after_dropping(budget(1000), |_, conn| sized(conn, &[0; 1000]), get("/")).await;
    assert_eq!(next, 0);
    // a chunked body needs a poll past the budget to see its end
    let next = next_conn_after_dropping(
        budget(1000),
        |_, conn| chunked(conn, &[&[0; 600], &[0; 400]], ""),
        get("/"),
    )
    .await;
    assert_eq!(next, 0);
}

#[tokio::test]
async fn final_frame_crossing_the_byte_budget_completes_the_drain() {
    // Only the frame with the last byte can cross the budget: the body is
    // complete once read, and so is the connection.
    let next =
        next_conn_after_dropping(budget(1000), |_, conn| sized(conn, &[0; 1001]), get("/")).await;
    assert_eq!(next, 0);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn frame_crossing_the_byte_budget_with_body_left_closes_the_connection() {
    // The chunked terminator is never read: no frame after the second chunk.
    let next = next_conn_after_dropping(
        budget(1000),
        |_, conn| chunked(conn, &[&[0; 600], &[0; 600]], ""),
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
}

#[tokio::test(start_paused = true)]
async fn trickling_body_past_the_deadline_closes_the_connection() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| {
            let mut steps = vec![Step::Write(
                head(conn, "HTTP/1.1 200 OK", "content-length: 100\r\n")
                    .into_bytes()
                    .into(),
            )];
            for _ in 0..100 {
                steps.push(Step::Sleep(Duration::from_millis(5)));
                steps.push(Step::Write(Bytes::from_static(b"x")));
            }
            steps
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn endless_body_closes_the_connection() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| {
            vec![
                Step::Write(
                    head(conn, "HTTP/1.1 200 OK", "transfer-encoding: chunked\r\n")
                        .into_bytes()
                        .into(),
                ),
                Step::Repeat(chunk(&[b'x'; 512]).into()),
            ]
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn truncated_body_closes_the_connection() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| {
            vec![
                Step::Write(
                    (head(conn, "HTTP/1.1 200 OK", "content-length: 100\r\n") + "short")
                        .into_bytes()
                        .into(),
                ),
                Step::Close,
            ]
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn invalid_chunk_framing_closes_the_connection() {
    let next = next_conn_after_dropping(
        Some(Http1BodyDrainConfig::default()),
        |_, conn| {
            vec![Step::Write(
                (head(conn, "HTTP/1.1 200 OK", "transfer-encoding: chunked\r\n")
                    + "5\r\nhello\r\nzz\r\n")
                    .into_bytes()
                    .into(),
            )]
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 1);
}

#[tokio::test]
async fn zero_limits_never_drain() {
    for config in [
        Http1BodyDrainConfig::default().with_timeout(Duration::ZERO),
        Http1BodyDrainConfig::default().with_max_bytes(0),
    ] {
        let next =
            next_conn_after_dropping(Some(config), |_, conn| sized(conn, b"ok"), get("/")).await;
        assert_eq!(next, 1);
    }
    assert_eq!(drains_started(), 0);
}

/// A response whose body stalls until `rest` is notified.
fn stalling(rest: &Arc<Notify>) -> impl Fn(&str, usize) -> Vec<Step> + Send + Sync + 'static {
    let rest = rest.clone();
    move |path, conn| {
        if path == "/stall" {
            vec![
                Step::Write(
                    (head(conn, "HTTP/1.1 200 OK", "content-length: 10\r\n") + "12345")
                        .into_bytes()
                        .into(),
                ),
                Step::Wait(rest.clone()),
                Step::Write(Bytes::from_static(b"67890")),
            ]
        } else {
            sized(conn, b"ok")
        }
    }
}

#[tokio::test]
async fn exhausted_drain_limit_closes_the_connection_right_away() {
    let rest = Arc::new(Notify::new());
    let config = Http1BodyDrainConfig::default().with_max_concurrent(NonZeroUsize::MIN);
    let harness = harness(uncapped(Some(config)), Executor::default(), stalling(&rest));
    let drain = harness.drain.clone().unwrap();

    let draining = send(&harness.client, get("/stall")).await;
    assert_eq!(conn_id(&draining), 0);
    drop(draining);
    assert_eq!(drains_started(), 1);

    // the limit is taken: this one is closed instead of drained
    let closed = send(&harness.client, get("/stall")).await;
    assert_eq!(conn_id(&closed), 1);
    drop(closed);
    assert_eq!(drains_started(), 1);

    rest.notify_one();
    settled(&drain).await;
    // connection 1 is gone, connection 0 drained
    assert_eq!(conn_id(&send(&harness.client, get("/")).await), 0);
    assert_eq!(harness.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn drain_permits_return_after_success_and_failure() {
    let config = Http1BodyDrainConfig::default()
        .with_max_concurrent(NonZeroUsize::MIN)
        .with_max_bytes(100);
    let harness = harness(
        one_connection(Some(config)),
        Executor::default(),
        |path, conn| {
            if path == "/large" {
                sized(conn, &[0; 1000])
            } else {
                sized(conn, b"ok")
            }
        },
    );
    let drain = harness.drain.clone().unwrap();
    for (path, next) in [("/", 0), ("/large", 1), ("/", 1)] {
        drop(send(&harness.client, get(path)).await);
        settled(&drain).await;
        let response = send(&harness.client, get("/next")).await;
        assert_eq!(conn_id(&response), next, "after {path}");
        response.into_body().collect().await.unwrap();
    }
    assert_eq!(drains_started(), 3);
    assert_eq!(drain.active.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn connector_clones_share_the_drain_limit_and_connectors_do_not() {
    let rest = Arc::new(Notify::new());
    let layer = BindBodyToConnLayer::new().with_http1_body_drain(
        Http1BodyDrainConfig::default().with_max_concurrent(NonZeroUsize::MIN),
    );
    let (origin, _) = scripted_origin(stalling(&rest));
    let connector = HttpConnectRequestAdapter::new(layer.layer(Arc::new(
        HttpConnectorLayer::<Body>::default().into_layer(origin.clone()),
    )));
    let clone = connector.clone();

    drop(send(&connector, get("/stall")).await);
    drop(send(&clone, get("/stall")).await);
    assert_eq!(drains_started(), 1, "the clone shares the taken limit");

    let other = HttpConnectRequestAdapter::new(layer.layer(Arc::new(
        HttpConnectorLayer::<Body>::default().into_layer(origin),
    )));
    drop(send(&other, get("/stall")).await);
    assert_eq!(
        drains_started(),
        2,
        "another connector of the same layer has a limit of its own"
    );
}

// ---- pool and cancellation races -------------------------------------------

#[tokio::test]
async fn draining_connection_is_not_handed_out() {
    let rest = Arc::new(Notify::new());
    let harness = harness(
        uncapped(Some(Default::default())),
        Executor::default(),
        stalling(&rest),
    );
    let drain = harness.drain.clone().unwrap();
    drop(send(&harness.client, get("/stall")).await);
    // no yield: the next checkout races the drain
    let response = send(&harness.client, get("/")).await;
    assert_eq!(conn_id(&response), 1, "connection 0 is still draining");
    response.into_body().collect().await.unwrap();

    rest.notify_one();
    settled(&drain).await;
    for _ in 0..3 {
        send(&harness.client, get("/"))
            .await
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    assert_eq!(
        harness.accepted.load(Ordering::SeqCst),
        2,
        "both connections are reused once drained"
    );
}

#[tokio::test]
async fn drain_completion_does_not_revive_a_retired_connection() {
    let rest = Arc::new(Notify::new());
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::default(),
        stalling(&rest),
    );
    let drain = harness.drain.clone().unwrap();
    let EstablishedClientConnection { conn, input } =
        harness.client.connect(get("/stall")).await.unwrap();
    let health = conn
        .extensions()
        .get_arc::<ConnectionHealthWatcher>()
        .unwrap();
    drop(conn.serve(input).await.unwrap());
    assert_eq!(drains_started(), 1);
    // retired for another reason while it drains
    health.mark_broken();
    rest.notify_one();
    settled(&drain).await;
    assert_eq!(health.health(), ConnectionHealth::Broken);
    assert_eq!(conn_id(&send(&harness.client, get("/")).await), 1);
}

#[tokio::test]
async fn executor_shutdown_cancels_drains_and_retires_their_connection() {
    let (trigger, signal) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        _ = signal.await;
    });
    let rest = Arc::new(Notify::new());
    let harness = harness(
        one_connection(Some(Default::default())),
        Executor::graceful(shutdown.guard()),
        stalling(&rest),
    );
    let drain = harness.drain.clone().unwrap();
    drop(send(&harness.client, get("/stall")).await);
    assert_eq!(drains_started(), 1);
    trigger.send(()).unwrap();
    settled(&drain).await;
    assert_eq!(conn_id(&send(&harness.client, get("/")).await), 1);
}

/// Records `event` when dropped: a stand-in for a pool lease.
struct Record(Arc<Mutex<Vec<&'static str>>>, &'static str);

impl Drop for Record {
    fn drop(&mut self) {
        self.0.lock().push(self.1);
    }
}

/// A drain body over `body`, recording its connection's invalidation and the
/// release of its lease.
fn recorded(
    body: Body,
    events: &Arc<Mutex<Vec<&'static str>>>,
    exec: &Executor,
    config: &Http1BodyDrainConfig,
) -> Http1DrainBody<Record> {
    let invalidated = events.clone();
    let body = Body::new(OnIncompleteBody::new(body, move || {
        invalidated.lock().push("invalidate");
    }));
    let conn = Extensions::new();
    conn.insert(Http1DrainRuntime::new(exec));
    Http1DrainBody::new(
        GuardedBody::new(body, Record(events.clone(), "release")),
        Arc::new(Http1BodyDrain::new(config)),
        conn,
    )
}

fn pending_body() -> Body {
    Body::from_stream(stream::pending::<Result<Bytes, Infallible>>())
}

#[tokio::test(start_paused = true)]
async fn deadline_elapsed_before_first_poll_closes_without_draining() {
    let events = Arc::default();
    drop(recorded(
        Body::from("unread"),
        &events,
        &Executor::new(),
        &Http1BodyDrainConfig::default(),
    ));
    // Advance before the spawned drain gets its first poll. Even a body
    // whose final frame is ready must not be read after the deadline.
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(*events.lock(), ["invalidate", "release"]);
}

#[tokio::test(start_paused = true)]
async fn deadline_elapsed_between_polls_stops_before_reading_more() {
    let mut body = GuardedBody::new(
        Body::from_stream(stream::iter(
            (0..=FRAMES_PER_POLL).map(|_| Ok::<_, Infallible>(Bytes::from_static(b"x"))),
        )),
        (),
    );
    let deadline = Instant::now() + Duration::from_millis(50);
    let mut discarded = 0;
    {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            poll_drain(
                &mut body,
                &mut cx,
                &mut discarded,
                usize::MAX,
                Some(deadline)
            ),
            Poll::Pending,
        );
    }
    assert_eq!(discarded, FRAMES_PER_POLL);

    tokio::time::advance(Duration::from_millis(50)).await;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert_eq!(
        poll_drain(
            &mut body,
            &mut cx,
            &mut discarded,
            usize::MAX,
            Some(deadline)
        ),
        Poll::Ready(DrainOutcome::Deadline),
    );
    assert_eq!(discarded, FRAMES_PER_POLL, "no frame read at the deadline");
}

async fn recorded_until(events: &Arc<Mutex<Vec<&'static str>>>, len: usize) {
    timeout(LIMIT, async {
        while events.lock().len() < len {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("drain finishes");
}

#[tokio::test]
async fn shutdown_invalidates_before_releasing_and_is_not_delayed() {
    let (trigger, signal) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        _ = signal.await;
    });
    let exec = Executor::graceful(shutdown.guard());
    let events = Arc::default();
    drop(recorded(
        pending_body(),
        &events,
        &exec,
        &Default::default(),
    ));
    drop(exec);
    assert_eq!(drains_started(), 1);
    tokio::task::yield_now().await;
    assert!(events.lock().is_empty(), "draining holds the lease");
    trigger.send(()).unwrap();
    timeout(LIMIT, shutdown.shutdown())
        .await
        .expect("a cancelled drain does not hold up shutdown");
    assert_eq!(*events.lock(), ["invalidate", "release"]);
}

#[test]
fn runtime_shutdown_invalidates_before_releasing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let events = Arc::default();
    runtime.block_on(async {
        drop(recorded(
            pending_body(),
            &events,
            &Executor::new(),
            &Default::default(),
        ));
    });
    assert_eq!(drains_started(), 1);
    assert!(events.lock().is_empty());
    drop(runtime);
    assert_eq!(*events.lock(), ["invalidate", "release"]);
    assert_eq!(drains_started(), 1, "a dropped drain starts no other");
}

#[test]
fn dropped_outside_a_runtime_closes_the_connection() {
    let events = Arc::default();
    drop(recorded(
        Body::from("unread"),
        &events,
        &Executor::new(),
        &Default::default(),
    ));
    assert_eq!(drains_started(), 0);
    assert_eq!(*events.lock(), ["invalidate", "release"]);
}

#[tokio::test(start_paused = true)]
async fn always_ready_bodies_yield_and_end_at_the_deadline() {
    let config = Http1BodyDrainConfig::default()
        .with_max_bytes(usize::MAX)
        .with_timeout(Duration::from_millis(20));
    for frame in [Bytes::new(), Bytes::from_static(b"x")] {
        let events = Arc::default();
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = tokio::spawn({
            let ticks = ticks.clone();
            async move {
                // Only the ticker moves the paused clock: the deadline is reached only if the drain yields.
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::time::advance(Duration::from_millis(1)).await;
                }
            }
        });
        let body = Body::from_stream(stream::repeat_with(move || {
            Ok::<_, Infallible>(frame.clone())
        }));
        drop(recorded(body, &events, &Executor::new(), &config));
        recorded_until(&events, 2).await;
        ticker.abort();
        assert_eq!(*events.lock(), ["invalidate", "release"]);
        assert!(ticks.load(Ordering::Relaxed) > 1, "the drain yields");
    }
}

// ---- protocol exclusions ---------------------------------------------------

#[tokio::test]
async fn request_close_intent_is_not_drained() {
    let mut request = get("/");
    request
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));
    // the response does not echo the close
    let next = next_conn_after_dropping(
        Some(Default::default()),
        |_, conn| sized(conn, b"ok"),
        request,
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn response_close_intent_is_not_drained() {
    let next = next_conn_after_dropping(
        Some(Default::default()),
        |_, conn| {
            vec![Step::Write(
                (head(
                    conn,
                    "HTTP/1.1 200 OK",
                    "connection: close\r\ncontent-length: 2\r\n",
                ) + "ok")
                    .into_bytes()
                    .into(),
            )]
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn http10_response_without_keep_alive_is_not_drained() {
    let next = next_conn_after_dropping(
        Some(Default::default()),
        |_, conn| {
            vec![Step::Write(
                (head(conn, "HTTP/1.0 200 OK", "content-length: 2\r\n") + "ok")
                    .into_bytes()
                    .into(),
            )]
        },
        get("/"),
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn close_delimited_responses_are_marked_and_not_drained() {
    for headers in ["", "transfer-encoding: gzip\r\n"] {
        let harness = harness(
            one_connection(Some(Default::default())),
            Executor::default(),
            move |path, conn| {
                if path == "/next" {
                    sized(conn, b"next")
                } else {
                    vec![Step::Write(
                        (head(conn, "HTTP/1.1 200 OK", headers) + "until the end")
                            .into_bytes()
                            .into(),
                    )]
                }
            },
        );
        let response = send(&harness.client, get("/")).await;
        assert!(
            response.extensions().contains::<ConnectionClose>(),
            "{headers:?}"
        );
        drop(response);
        let next = send(&harness.client, get("/next")).await;
        assert_eq!(conn_id(&next), 1);
        next.into_body().collect().await.unwrap();
    }
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn upgrades_and_connect_tunnels_are_not_drained() {
    let mut upgrade = get("/upgrade");
    upgrade
        .headers_mut()
        .insert("connection", HeaderValue::from_static("upgrade"));
    upgrade
        .headers_mut()
        .insert("upgrade", HeaderValue::from_static("test"));
    let next = next_conn_after_dropping(
        Some(Default::default()),
        |_, conn| {
            vec![Step::Write(
                head(
                    conn,
                    "HTTP/1.1 101 Switching Protocols",
                    "connection: upgrade\r\nupgrade: test\r\n",
                )
                .into_bytes()
                .into(),
            )]
        },
        upgrade,
    )
    .await;
    assert_eq!(next, 1);

    let connect = Request::builder()
        .method("CONNECT")
        .uri("http://origin.example:443")
        .body(Body::empty())
        .unwrap();
    let next = next_conn_after_dropping(
        Some(Default::default()),
        |_, conn| {
            vec![Step::Write(
                head(conn, "HTTP/1.1 200 OK", "").into_bytes().into(),
            )]
        },
        connect,
    )
    .await;
    assert_eq!(next, 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn http2_abandoned_body_keeps_its_connection_without_draining() {
    let accepted = Arc::new(AtomicUsize::new(0));
    let mock = MockConnectorService::new({
        let accepted = accepted.clone();
        move || {
            let conn = accepted.fetch_add(1, Ordering::SeqCst);
            HttpServer::auto(Executor::default()).service(service_fn(
                move |_request: Request| async move {
                    let mut response = Response::new(Body::from(vec![0u8; 256 * 1024]));
                    response
                        .headers_mut()
                        .insert("x-conn-id", HeaderValue::from(conn as u64));
                    Ok::<_, Infallible>(response)
                },
            ))
        }
    });
    let client = HttpConnectRequestAdapter::new(
        uncapped(Some(Default::default()))
            .build_connector(HttpConnectorLayer::<Body>::default().into_layer(mock)),
    );
    let h2 = || {
        Request::builder()
            .version(Version::HTTP_2)
            .uri("http://origin.example/")
            .body(Body::empty())
            .unwrap()
    };
    let response = send(&client, h2()).await;
    assert_eq!(response.version(), Version::HTTP_2);
    drop(response);
    assert_eq!(conn_id(&send(&client, h2()).await), 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(drains_started(), 0);
}

#[tokio::test]
async fn only_http1_connections_carry_the_drain_runtime() {
    for (version, expected) in [(Version::HTTP_11, true), (Version::HTTP_2, false)] {
        let (io, _peer) = tokio::io::duplex(4096);
        let input = ConnectRequest::new("origin.example:80".parse().unwrap());
        input.extensions().insert(TargetHttpVersion(version));
        let established = http_connect::<_, _, Body>(ServiceInput::new(io), input, Executor::new())
            .await
            .unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .contains::<Http1DrainRuntime>(),
            expected,
            "{version:?}"
        );
    }
}
