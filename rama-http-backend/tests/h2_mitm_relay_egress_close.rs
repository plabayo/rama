//! Regression e2e: the [`HttpMitmRelay`] must propagate the end of its
//! egress HTTP/2 connection to the ingress HTTP/2 connection.
//!
//! Browsers preconnect (e.g. while the user is typing a URL) and keep idle
//! h2 connections around. Origins close idle connections, a never used one
//! often within seconds. If the relay keeps the ingress connection open,
//! the client sends its next navigation on a connection with nothing
//! behind it and the page fails to load until the user retries.
//!
//! What the relay does instead:
//!
//! - egress gone (EOF or GOAWAY): graceful GOAWAY on ingress, in-flight
//!   ingress streams still finish;
//! - a request that raced the egress close and never reached the origin:
//!   `RST_STREAM(REFUSED_STREAM)`, safe to retry (RFC 9113 section 8.7);
//! - a failure while egress is still healthy: fail only that stream.
//!
//! Wiring (all in-memory, paused clock):
//!
//!   h2 client --duplex--> relay (ingress h2 -> egress h2) --duplex--> origin

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures"
)]

use std::{sync::Arc, time::Duration};

use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    graceful::Shutdown,
    io::BridgeIo,
    layer::{ArcLayer, ConsumeErrLayer},
    rt::Executor,
};
use rama_http::layer::follow_redirect::FollowRedirectLayer;
use rama_http_backend::proxy::mitm::{DefaultErrorResponse, HttpMitmRelay};
use rama_http_core::h2::{self, Reason, client as h2_client, server as h2_server};
use rama_http_types::{Request, Response, StatusCode, Version};
use rama_net::{http::TargetHttpVersion, test_utils::client::MockSocket};
use rama_utils::octets::kib;
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::{CancellationToken, DropGuard};

/// Relay middleware parks requests with this header until released.
const HOLD_HEADER: &str = "x-test-hold";
/// Same, for requests to this path (e.g. a redirect target).
const HOLD_PATH: &str = "/held";
/// Relay middleware fails requests with this header on its own.
const FAIL_HEADER: &str = "x-test-fail";

/// How long an origin keeps a never used connection open.
const ORIGIN_IDLE_CLOSE: Duration = Duration::from_secs(5);

type OriginConn = h2_server::Connection<MockSocket, Bytes>;
type OriginStream = (
    rama_http_types::Request<h2::RecvStream>,
    h2_server::SendResponse<Bytes>,
);

#[derive(Debug, Clone, Copy)]
enum OriginClose {
    /// Transport EOF without any h2 frame.
    Eof,
    /// Graceful `GOAWAY(NO_ERROR)`.
    GoAway,
}

/// Relay middleware wrapping the test gate.
#[derive(Debug, Clone, Copy)]
enum Middleware {
    /// Egress errors reach the relay, like production relay middleware.
    Propagate,
    /// Like the relay's default middleware: errors become a `502`.
    ConsumeErrors,
    /// Follows redirects, so one request can make several egress hops.
    FollowRedirects,
}

#[derive(Debug, Clone, Copy)]
enum EgressMode {
    /// Egress ALPN said h2: egress handshake before ingress is served.
    Eager,
    /// No hint: egress connects on the first ingress request.
    Lazy,
}

#[derive(Clone)]
struct GateLayer {
    arrived: Arc<watch::Sender<bool>>,
    release: watch::Receiver<bool>,
}

impl<S> Layer<S> for GateLayer {
    type Service = Gate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Gate {
            inner,
            gates: self.clone(),
        }
    }
}

#[derive(Clone)]
struct Gate<S> {
    inner: S,
    gates: GateLayer,
}

impl<S> Service<Request> for Gate<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        if req.headers().contains_key(FAIL_HEADER) {
            return Err(BoxError::from_static_str("middleware refused request"));
        }
        if req.headers().contains_key(HOLD_HEADER) || req.uri().to_string().ends_with(HOLD_PATH) {
            self.gates.arrived.send_replace(true);
            let mut release = self.gates.release.clone();
            release
                .wait_for(|released| *released)
                .await
                .expect("test holds the release sender");
            // paused clock: only elapses once all other tasks are idle,
            // so the egress h2 stack has fully seen the origin close
            sleep(Duration::from_millis(10)).await;
        }
        self.inner.serve(req).await.map_err(Into::into)
    }
}

struct Harness {
    client: h2_client::SendRequest<Bytes>,
    client_conn: JoinHandle<Result<(), h2::Error>>,
    relay: JoinHandle<Result<(), BoxError>>,
    origin: Option<oneshot::Receiver<OriginConn>>,
    arrived: watch::Receiver<bool>,
    release: watch::Sender<bool>,
    _shutdown: DropGuard,
}

async fn harness(mode: EgressMode) -> Harness {
    harness_with(mode, Middleware::Propagate).await
}

async fn harness_with(mode: EgressMode, middleware: Middleware) -> Harness {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(64));
    let (relay_egress_stream, origin_stream) = tokio::io::duplex(kib(64));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());

    let (origin_tx, origin_rx) = oneshot::channel();
    tokio::spawn(async move {
        let conn = h2_server::handshake(MockSocket::new(origin_stream))
            .await
            .expect("origin h2 handshake");
        assert!(origin_tx.send(conn).is_ok(), "test awaits the origin");
    });

    let (arrived_tx, arrived) = watch::channel(false);
    let (release, release_rx) = watch::channel(false);
    let gate = GateLayer {
        arrived: Arc::new(arrived_tx),
        release: release_rx,
    };

    let egress = MockSocket::new(relay_egress_stream);
    if matches!(mode, EgressMode::Eager) {
        egress
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
    }

    let relay_exec = Executor::graceful(graceful.guard());
    let relay = tokio::spawn(async move {
        let relay = HttpMitmRelay::new(relay_exec);
        let io = BridgeIo(MockSocket::new(relay_ingress_stream), egress);
        match middleware {
            Middleware::Propagate => {
                relay
                    .with_http_middleware((gate, ArcLayer::new()))
                    .serve(io)
                    .await
            }
            Middleware::ConsumeErrors => {
                relay
                    .with_http_middleware((
                        ConsumeErrLayer::trace_as_debug()
                            .with_response(DefaultErrorResponse::new()),
                        gate,
                        ArcLayer::new(),
                    ))
                    .serve(io)
                    .await
            }
            Middleware::FollowRedirects => {
                relay
                    .with_http_middleware((FollowRedirectLayer::new(), gate, ArcLayer::new()))
                    .serve(io)
                    .await
            }
        }
    });

    let (client, client_conn) = h2_client::handshake(MockSocket::new(client_stream))
        .await
        .expect("client h2 handshake with relay");
    let client_conn = tokio::spawn(client_conn);

    Harness {
        client,
        client_conn,
        relay,
        origin: Some(origin_rx),
        arrived,
        release,
        _shutdown: token.drop_guard(),
    }
}

impl Harness {
    /// Origin side of the egress connection, once handshaked. For the
    /// lazy mode this completes on the first relayed request.
    async fn origin(&mut self) -> OriginConn {
        self.origin
            .take()
            .expect("origin taken once")
            .await
            .expect("origin handshake")
    }

    async fn send(&self, req: Request<()>) -> h2_client::ResponseFuture {
        let mut client = self.client.clone().ready().await.expect("client ready");
        let (resp, _body) = client.send_request(req, true).expect("send request");
        resp
    }

    /// Ingress connection must end gracefully (GOAWAY), with no request
    /// ever failing in between.
    async fn assert_ingress_went_away(mut self) {
        let conn = timeout(Duration::from_secs(1), &mut self.client_conn)
            .await
            .expect("ingress h2 connection must be closed after the egress is gone")
            .expect("client conn task");
        conn.expect("ingress h2 connection must close gracefully");

        let err = self
            .client
            .clone()
            .ready()
            .await
            .expect_err("ingress must not accept new requests");
        assert!(err.is_go_away(), "expected GOAWAY, got: {err:?}");
        assert_eq!(err.reason(), Some(Reason::NO_ERROR));

        timeout(Duration::from_secs(1), self.relay)
            .await
            .expect("relay must finish")
            .expect("relay task")
            .expect("relay must end without error");
    }
}

fn get(path: &str, headers: &[&str]) -> Request<()> {
    let mut builder = Request::builder()
        .uri(format!("https://origin.example{path}"))
        .version(Version::HTTP_2);
    for name in headers {
        builder = builder.header(*name, "1");
    }
    builder.body(()).unwrap()
}

async fn next_stream(origin: &mut OriginConn) -> OriginStream {
    origin
        .accept()
        .await
        .expect("origin stream")
        .expect("origin accept")
}

fn respond_ok(mut respond: h2_server::SendResponse<Bytes>, body: &'static [u8]) {
    let resp = rama_http_types::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    let mut stream = respond.send_response(resp, false).expect("send response");
    stream
        .send_data(Bytes::from_static(body), true)
        .expect("send body");
}

async fn read_body(resp: h2_client::ResponseFuture) -> Result<Vec<u8>, h2::Error> {
    let resp = resp.await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release flow control capacity");
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Drive an origin connection that is going away until it is done.
async fn drain_origin(origin: &mut OriginConn) {
    let drain = async {
        // errors repeat once the peer is gone
        if let Some(Ok((req, _))) = origin.accept().await {
            panic!("no stream expected after GOAWAY: {req:?}");
        }
    };
    timeout(Duration::from_secs(30), drain)
        .await
        .expect("origin connection must close after its GOAWAY");
}

/// Close the origin side of the egress connection.
async fn close_origin(mut origin: OriginConn, how: OriginClose) {
    match how {
        OriginClose::Eof => drop(origin),
        OriginClose::GoAway => {
            origin.graceful_shutdown();
            drain_origin(&mut origin).await;
        }
    }
}

/// The reported case: a preconnected (never used) h2 connection is closed
/// by the origin after ~5s idle; the user navigates at 6.5s.
async fn idle_preconnect_egress_close(how: OriginClose) {
    let mut h = harness(EgressMode::Eager).await;
    let mut origin = h.origin().await;

    tokio::select! {
        biased;
        accepted = origin.accept() => panic!("preconnect must be idle: {accepted:?}"),
        () = sleep(ORIGIN_IDLE_CLOSE) => (),
    }
    close_origin(origin, how).await;

    // user hits enter: by now the client must know this conn is gone,
    // so a browser opens a fresh connection instead of failing the page
    sleep(Duration::from_millis(1500)).await;
    assert!(
        h.client_conn.is_finished(),
        "ingress still open {:?} after the origin closed the egress ({how:?})",
        Duration::from_millis(1500),
    );
    h.assert_ingress_went_away().await;
}

#[tokio::test(start_paused = true)]
async fn idle_preconnect_egress_eof_goes_away_on_ingress() {
    idle_preconnect_egress_close(OriginClose::Eof).await;
}

#[tokio::test(start_paused = true)]
async fn idle_preconnect_egress_goaway_goes_away_on_ingress() {
    idle_preconnect_egress_close(OriginClose::GoAway).await;
}

/// Long lived, lazily connected egress (no ALPN hint) closed after use.
async fn idle_used_egress_close(how: OriginClose) {
    let mut h = harness(EgressMode::Lazy).await;

    let resp = h.send(get("/first", &[])).await;
    let mut origin = h.origin().await;
    let (_req, respond) = next_stream(&mut origin).await;
    respond_ok(respond, b"first");
    let (body, ()) = tokio::join!(read_body(resp), async {
        tokio::select! {
            biased;
            accepted = origin.accept() => panic!("unexpected stream: {accepted:?}"),
            () = sleep(Duration::from_millis(50)) => (),
        }
    });
    assert_eq!(body.expect("first response"), b"first");

    tokio::select! {
        biased;
        accepted = origin.accept() => panic!("egress must be idle: {accepted:?}"),
        () = sleep(Duration::from_secs(150)) => (),
    }
    close_origin(origin, how).await;

    h.assert_ingress_went_away().await;
}

#[tokio::test(start_paused = true)]
async fn idle_used_lazy_egress_eof_goes_away_on_ingress() {
    idle_used_egress_close(OriginClose::Eof).await;
}

#[tokio::test(start_paused = true)]
async fn idle_used_lazy_egress_goaway_goes_away_on_ingress() {
    idle_used_egress_close(OriginClose::GoAway).await;
}

/// The request was already on the ingress connection when the origin
/// closed the egress: it never reached the origin, so it must be refused
/// (client retries on a new connection), not failed or cut off.
async fn request_racing_egress_close_is_refused(how: OriginClose, middleware: Middleware) {
    let mut h = harness_with(EgressMode::Eager, middleware).await;
    let origin = h.origin().await;

    let resp = h.send(get("/navigate", &[HOLD_HEADER])).await;
    h.arrived
        .wait_for(|arrived| *arrived)
        .await
        .expect("request reached relay middleware");

    close_origin(origin, how).await;
    h.release.send_replace(true);

    let err = timeout(Duration::from_secs(1), resp)
        .await
        .expect("request must complete")
        .expect_err("request on a dead egress cannot succeed");
    assert_eq!(
        err.reason(),
        Some(Reason::REFUSED_STREAM),
        "unsent request must be refused (retry safe), got: {err:?}"
    );

    h.assert_ingress_went_away().await;
}

#[tokio::test(start_paused = true)]
async fn request_racing_egress_eof_is_refused() {
    request_racing_egress_close_is_refused(OriginClose::Eof, Middleware::Propagate).await;
}

#[tokio::test(start_paused = true)]
async fn request_racing_egress_goaway_is_refused() {
    request_racing_egress_close_is_refused(OriginClose::GoAway, Middleware::Propagate).await;
}

/// The default relay middleware turns the egress error into a `502`
/// before the relay sees it; the request must still be refused.
#[tokio::test(start_paused = true)]
async fn request_racing_egress_eof_is_refused_with_default_middleware() {
    request_racing_egress_close_is_refused(OriginClose::Eof, Middleware::ConsumeErrors).await;
}

#[tokio::test(start_paused = true)]
async fn request_racing_egress_goaway_is_refused_with_default_middleware() {
    request_racing_egress_close_is_refused(OriginClose::GoAway, Middleware::ConsumeErrors).await;
}

/// A POST the origin processed must never be refused (a client would
/// replay it), even when a later middleware hop for it (here: the
/// redirected GET) raced the egress close and was never sent.
#[tokio::test(start_paused = true)]
async fn processed_request_is_not_refused_when_later_hop_is_unsent() {
    let mut h = harness_with(EgressMode::Eager, Middleware::FollowRedirects).await;
    let mut origin = h.origin().await;

    let post = Request::builder()
        .method("POST")
        .uri("https://origin.example/submit")
        .version(Version::HTTP_2)
        .body(())
        .unwrap();
    let resp = h.send(post).await;
    let (req, mut respond) = next_stream(&mut origin).await;
    assert_eq!(req.method(), "POST", "origin processes the POST");
    let see_other = rama_http_types::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", format!("https://origin.example{HOLD_PATH}"))
        .body(())
        .unwrap();
    respond
        .send_response(see_other, true)
        .expect("send redirect");

    // drive the origin to flush the redirect, until the redirected GET
    // is parked in the middleware; egress dies meanwhile
    tokio::select! {
        arrived = h.arrived.wait_for(|arrived| *arrived) => {
            arrived.expect("redirect hop reached relay middleware");
        }
        accepted = origin.accept() => panic!("redirect hop must be held: {accepted:?}"),
    }
    close_origin(origin, OriginClose::Eof).await;
    h.release.send_replace(true);

    let resp = timeout(Duration::from_secs(1), resp)
        .await
        .expect("request must complete")
        .expect("a processed request must get a response, not a retry safe reset");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    h.assert_ingress_went_away().await;
}

/// Origin GOAWAY while a response is still streaming: that response must
/// complete in full, a new stream racing the GOAWAY is refused.
#[tokio::test(start_paused = true)]
async fn egress_goaway_does_not_truncate_in_flight_sibling() {
    let mut h = harness(EgressMode::Eager).await;
    let mut origin = h.origin().await;

    let download = h.send(get("/download", &[])).await;
    let (_req, mut respond) = next_stream(&mut origin).await;
    let mut body_tx = respond
        .send_response(
            rama_http_types::Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap(),
            false,
        )
        .expect("send response head");
    body_tx
        .send_data(Bytes::from_static(b"part-1;"), false)
        .expect("send part 1");

    let racer = h.send(get("/racer", &[HOLD_HEADER])).await;
    let (download, racer, ()) = tokio::join!(read_body(download), racer, async {
        h.arrived
            .wait_for(|arrived| *arrived)
            .await
            .expect("racer reached relay middleware");

        origin.graceful_shutdown();
        let drive = drain_origin(&mut origin);
        let finish = async {
            h.release.send_replace(true);
            sleep(Duration::from_millis(100)).await;
            // fails when the relay dropped the stream, the client
            // side assertion below reports that
            drop(body_tx.send_data(Bytes::from_static(b"part-2"), true));
        };
        tokio::join!(drive, finish);
    });

    assert_eq!(
        download.expect("in-flight response must not be cut off"),
        b"part-1;part-2",
    );
    let err = racer.expect_err("racer cannot be served by a GOAWAY'd egress");
    assert_eq!(err.reason(), Some(Reason::REFUSED_STREAM), "got: {err:?}");

    h.assert_ingress_went_away().await;
}

/// A failure that is not the egress connection's (here: middleware) must
/// only fail that one stream.
#[tokio::test(start_paused = true)]
async fn request_failure_with_healthy_egress_keeps_ingress() {
    let mut h = harness(EgressMode::Eager).await;
    let mut origin = h.origin().await;

    let failed = h.send(get("/fail", &[FAIL_HEADER])).await;
    let resp = timeout(Duration::from_secs(1), failed)
        .await
        .expect("failed request completes")
        .expect("failed request gets a response");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let ok = h.send(get("/ok", &[])).await;
    let (_req, respond) = next_stream(&mut origin).await;
    respond_ok(respond, b"ok");
    let (body, ()) = tokio::join!(read_body(ok), async {
        tokio::select! {
            biased;
            accepted = origin.accept() => panic!("unexpected stream: {accepted:?}"),
            () = sleep(Duration::from_millis(50)) => (),
        }
    });
    assert_eq!(
        body.expect("ingress must survive a request scoped failure"),
        b"ok"
    );
    assert!(!h.client_conn.is_finished());
}
