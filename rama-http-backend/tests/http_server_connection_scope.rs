//! Every served connection runs in a child of the most recent scope in its extensions (or of
//! the server's): it drains on the graceful phase without cutting the in-flight response,
//! and is dropped at the hard phase.

#![expect(clippy::expect_used, clippy::unwrap_used, reason = "test fixtures")]

use std::{convert::Infallible, time::Duration};

use rama_core::{
    Layer as _, Service as _,
    bytes::Bytes,
    extensions::ExtensionsRef,
    graceful::{Cause, Scope, WeakScope, attach_scope, scope_context},
    layer::{ScopeLayer, scope::ScopeAborted},
    service::service_fn,
};
use rama_http_backend::server::HttpServer;
use rama_http_core::{
    client::conn as client_conn,
    h2::{Reason, client as h2_client},
};
use rama_http_types::{Body, Request, Response, StatusCode, Version, body::util::BodyExt as _};
use rama_net::{address::SocketAddress, test_utils::client::MockSocket};
use rama_tcp::{TcpStream, server::TcpListener};
use rama_utils::octets::kib;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::{Instant, timeout},
};

const WAIT: Duration = Duration::from_secs(5);

type Server = tokio::task::JoinHandle<Result<(), rama_core::error::BoxError>>;

/// Serve `server_io` on `scope`; the returned receiver holds the scope the request sees once
/// it is being handled, which is held until `release`.
fn serve(
    server_io: MockSocket,
    weak_scope: WeakScope,
    layer: Option<ScopeLayer>,
    release: watch::Receiver<bool>,
) -> (Server, watch::Receiver<Option<Scope>>) {
    let (arrived_tx, arrived) = watch::channel(None);
    let arrived_tx = std::sync::Arc::new(arrived_tx);
    let service = HttpServer::auto(weak_scope).service(service_fn(move |req: Request| {
        let mut release = release.clone();
        let scope = scope_context(req.extensions()).and_then(WeakScope::into_scope);
        arrived_tx.send_replace(Some(
            scope.expect("every request sees its connection scope"),
        ));
        async move {
            release
                .wait_for(|released| *released)
                .await
                .expect("test holds the release sender");
            Ok::<_, Infallible>(Response::new(Body::from("done")))
        }
    }));
    let server = tokio::spawn(async move {
        match layer {
            Some(layer) => layer.into_layer(service).serve(server_io).await,
            None => service.serve(server_io).await,
        }
    });
    (server, arrived)
}

async fn h2_request(client_io: tokio::io::DuplexStream) -> H2Client {
    h2_request_on(MockSocket::new(client_io)).await
}

async fn h2_request_on<IO>(io: IO) -> H2Client
where
    IO: AsyncRead + AsyncWrite + Unpin + ExtensionsRef + Send + 'static,
{
    let (client, conn) = h2_client::handshake(io).await.unwrap();
    let conn = tokio::spawn(conn);
    let mut ready = client.clone().ready().await.unwrap();
    let req = Request::builder()
        .uri("http://example.test/")
        .version(Version::HTTP_2)
        .body(())
        .unwrap();
    let (in_flight, _) = ready.send_request(req, true).unwrap();
    H2Client {
        client,
        conn,
        in_flight,
    }
}

struct H2Client {
    client: h2_client::SendRequest<Bytes>,
    conn: tokio::task::JoinHandle<Result<(), rama_http_core::h2::Error>>,
    in_flight: h2_client::ResponseFuture,
}

impl H2Client {
    async fn expect_goaway(&self, wait: Duration) {
        let err = timeout(wait, async {
            loop {
                match self.client.clone().ready().await {
                    Err(err) => break err,
                    // A sleep, not a yield: a paused clock only advances while the runtime idles.
                    Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("client must receive GOAWAY");
        assert!(err.is_go_away(), "got: {err:?}");
        assert_eq!(err.reason(), Some(Reason::NO_ERROR));
    }

    async fn expect_done(self) {
        let resp = timeout(WAIT, self.in_flight).await.unwrap().unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(out, b"done");
        timeout(WAIT, self.conn).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn h2_connection_scope_cancel_sends_goaway_and_finishes_in_flight_stream() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let server_io = MockSocket::new(server_io);
    let scope = Scope::new();
    attach_scope(server_io.extensions(), &scope);
    let (server, mut arrived) = serve(server_io, WeakScope::never(), None, release);

    let client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    scope.cancel(Cause::Reason("upstream gone"));
    client.expect_goaway(WAIT).await;

    release_tx.send_replace(true);
    client.expect_done().await;
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
    // The connection's own child of `scope` is gone with it, once the test lets go of the
    // request's view of it.
    drop(arrived);
    let weak = scope.clone_weak();
    drop(scope);
    timeout(WAIT, weak.drained()).await.unwrap();
}

#[tokio::test]
async fn executor_scope_cancel_drains_the_connection() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let root = Scope::new();
    let (server, mut arrived) = serve(MockSocket::new(server_io), root.clone_weak(), None, release);

    let client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    root.cancel(Cause::Owner);
    client.expect_goaway(WAIT).await;

    release_tx.send_replace(true);
    client.expect_done().await;
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
    // Only the root's own holder is left once the connection is done.
    drop(arrived);
    timeout(WAIT, root.join()).await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_connection_scope_cancel_closes_after_in_flight_response() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let server_io = MockSocket::new(server_io);
    let scope = Scope::new();
    attach_scope(server_io.extensions(), &scope);
    let (server, mut arrived) = serve(server_io, WeakScope::never(), None, release);

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

    arrived.wait_for(Option::is_some).await.unwrap();
    scope.cancel(Cause::Owner);
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
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn abort_drops_a_connection_with_a_stuck_request() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (_release_tx, release) = watch::channel(false);
    let server_io = MockSocket::new(server_io);
    let scope = Scope::new();
    attach_scope(server_io.extensions(), &scope);
    let (server, mut arrived) = serve(server_io, WeakScope::never(), None, release);

    let client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    scope.cancel(Cause::Owner);
    client.expect_goaway(WAIT).await;
    scope.abort(Cause::Owner);

    timeout(WAIT, server)
        .await
        .expect("an aborted connection must stop at once")
        .unwrap()
        .unwrap();
    let _err = timeout(WAIT, client.in_flight)
        .await
        .unwrap()
        .expect_err("the stuck stream is cut");
}

#[tokio::test(start_paused = true)]
async fn scope_layer_drains_at_max_age_and_aborts_after_grace() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (_release_tx, release) = watch::channel(false);
    let layer = ScopeLayer::new()
        .with_max_age(Duration::from_secs(12))
        .with_grace(Duration::from_secs(4));
    let start = Instant::now();
    let (server, mut arrived) = serve(
        MockSocket::new(server_io),
        WeakScope::never(),
        Some(layer),
        release,
    );

    let client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    client.expect_goaway(Duration::from_secs(30)).await;
    assert_eq!(start.elapsed().as_secs(), 12);

    let err = server.await.unwrap().expect_err("aborted by the layer");
    let aborted = err
        .downcast_ref::<ScopeAborted>()
        .expect("a scope abort error");
    assert!(matches!(aborted.cause(), Some(Cause::GraceElapsed)));
    assert_eq!(start.elapsed().as_secs(), 16);
}

/// The scope the handler of the request in flight sees.
fn request_scope(arrived: &watch::Receiver<Option<Scope>>) -> Scope {
    arrived.borrow().clone().expect("a request arrived")
}

#[tokio::test]
async fn default_connections_get_isolated_cancellable_scopes() {
    let (first_io, first_server_io) = tokio::io::duplex(kib(64));
    let (second_io, second_server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let (first_server, mut first_arrived) = serve(
        MockSocket::new(first_server_io),
        WeakScope::never(),
        None,
        release.clone(),
    );
    let (second_server, mut second_arrived) = serve(
        MockSocket::new(second_server_io),
        WeakScope::never(),
        None,
        release,
    );

    let first = h2_request(first_io).await;
    let second = h2_request(second_io).await;
    first_arrived.wait_for(Option::is_some).await.unwrap();
    second_arrived.wait_for(Option::is_some).await.unwrap();
    let first_scope = request_scope(&first_arrived);
    let second_scope = request_scope(&second_arrived);
    assert!(!first_scope.is_never());
    assert!(!second_scope.is_never());

    // Cancelled from state the handler sees: only its own connection drains.
    first_scope.cancel(Cause::Reason("handler"));
    first.expect_goaway(WAIT).await;
    assert!(!second_scope.is_cancelled());
    drop(
        second
            .client
            .clone()
            .ready()
            .await
            .expect("the sibling stays ready"),
    );

    release_tx.send_replace(true);
    first.expect_done().await;
    timeout(WAIT, first_server).await.unwrap().unwrap().unwrap();
    second_scope.abort(Cause::Owner);
    timeout(WAIT, second_server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn default_h1_connection_closes_on_its_request_scope() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (release_tx, release) = watch::channel(false);
    let (server, mut arrived) = serve(
        MockSocket::new(server_io),
        WeakScope::never(),
        None,
        release,
    );

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
    arrived.wait_for(Option::is_some).await.unwrap();
    request_scope(&arrived).cancel(Cause::Reason("handler"));
    release_tx.send_replace(true);

    let resp = timeout(WAIT, in_flight).await.unwrap().unwrap().unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    timeout(WAIT, conn).await.unwrap().unwrap().unwrap();
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn scope_layer_parent_keeps_the_executor_shutdown() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (_release_tx, release) = watch::channel(false);
    let root = Scope::new();
    let layer = ScopeLayer::new().with_parent(root.clone_weak());
    let (server, mut arrived) = serve(
        MockSocket::new(server_io),
        root.clone_weak(),
        Some(layer),
        release,
    );

    let client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    root.cancel(Cause::Owner);
    client.expect_goaway(WAIT).await;
    root.abort(Cause::Owner);
    let err = timeout(WAIT, server)
        .await
        .expect("the scope's abort reaches the layered connection")
        .unwrap()
        .expect_err("aborted");
    assert!(err.downcast_ref::<ScopeAborted>().is_some());
}

#[tokio::test(start_paused = true)]
async fn earlier_parent_cap_ends_a_layered_connection() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (_release_tx, release) = watch::channel(false);
    let root = Scope::new().with_hard_timeout(Duration::from_secs(3));
    let layer = ScopeLayer::new()
        .with_parent(root.clone_weak())
        .with_hard_max_age(Duration::from_secs(60));
    let start = Instant::now();
    let (server, mut arrived) = serve(
        MockSocket::new(server_io),
        root.clone_weak(),
        Some(layer),
        release,
    );

    let _client = h2_request(client_io).await;
    arrived.wait_for(Option::is_some).await.unwrap();
    let err = server
        .await
        .unwrap()
        .expect_err("aborted by the parent cap");
    assert!(err.downcast_ref::<ScopeAborted>().is_some());
    assert_eq!(start.elapsed().as_secs(), 3);
}

/// An input scope unrelated to the server's scope: the connection follows both.
#[tokio::test]
async fn an_unrelated_input_scope_and_the_layer_parent_both_apply() {
    for end_input in [true, false] {
        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let (_release_tx, release) = watch::channel(false);
        let root = Scope::new();
        let input = Scope::new();
        let server_io = MockSocket::new(server_io);
        attach_scope(server_io.extensions(), &input);
        let layer = ScopeLayer::new().with_parent(root.clone_weak());
        let (server, mut arrived) = serve(server_io, root.clone_weak(), Some(layer), release);

        let client = h2_request(client_io).await;
        arrived.wait_for(Option::is_some).await.unwrap();
        let (ended, other) = if end_input {
            (&input, &root)
        } else {
            (&root, &input)
        };
        ended.cancel(Cause::Owner);
        client.expect_goaway(WAIT).await;
        assert!(
            !other.is_cancelled(),
            "a connection never reaches its parents"
        );
        ended.abort(Cause::Owner);
        timeout(WAIT, server).await.unwrap().unwrap().unwrap_err();
    }
}

#[tokio::test]
async fn tcp_listener_hands_its_executor_scope_to_a_layer() {
    let root = Scope::new();
    let scope = root.clone_weak();
    let listener = TcpListener::build(scope.clone())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (_release_tx, release) = watch::channel(false);
    let (arrived_tx, mut arrived) = watch::channel(false);
    let http = HttpServer::auto(scope.clone()).service(service_fn(move |_: Request| {
        let mut release = release.clone();
        arrived_tx.send_replace(true);
        async move {
            _ = release.wait_for(|released| *released).await;
            Ok::<_, Infallible>(Response::new(Body::from("done")))
        }
    }));
    let serving = tokio::spawn(listener.serve(ScopeLayer::new().into_layer(http)));

    let stream = TcpStream::from(tokio::net::TcpStream::connect(addr).await.unwrap());
    let client = h2_request_on(stream).await;
    arrived.wait_for(|arrived| *arrived).await.unwrap();
    root.cancel(Cause::Owner);
    client.expect_goaway(WAIT).await;
    root.abort(Cause::Owner);
    let _err = timeout(WAIT, client.in_flight)
        .await
        .unwrap()
        .expect_err("the stuck stream is cut at the hard phase");
    timeout(WAIT, serving).await.unwrap().unwrap();
}

/// A handler keeping the request's extensions keeps only weak scope metadata: the root's
/// join completes once the connection is done.
#[tokio::test]
async fn retained_request_extensions_do_not_hold_the_join() {
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let root = Scope::new();
    let retained = std::sync::Arc::new(parking_lot::Mutex::new(None));
    let service = HttpServer::auto(root.clone_weak()).service(service_fn({
        let retained = retained.clone();
        move |req: Request| {
            *retained.lock() = Some(req.extensions().clone());
            async move { Ok::<_, Infallible>(Response::new(Body::from("done"))) }
        }
    }));
    let server = tokio::spawn(async move { service.serve(MockSocket::new(server_io)).await });

    let client = h2_request(client_io).await;
    timeout(WAIT, async {
        while retained.lock().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the handler ran");
    // Ends the connection once the response is out.
    root.cancel(Cause::Owner);
    client.expect_done().await;
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
    assert!(retained.lock().is_some());
    timeout(WAIT, root.join())
        .await
        .expect("retained extensions do not hold the drain")
        .unwrap();
}
