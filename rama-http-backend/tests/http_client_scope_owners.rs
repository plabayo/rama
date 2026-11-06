//! Client work spawned on an executor holds that executor's scope while it lives, and lets
//! its join complete once released; retained metadata never holds it.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{
    convert::Infallible,
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Layer as _, Service as _,
    bytes::Bytes,
    error::BoxError,
    extensions::ExtensionsRef as _,
    futures::{StreamExt as _, stream},
    graceful::{Cause, Scope, WeakScope},
    rt::Executor,
    service::service_fn,
};
use rama_http::io::upgrade::{Upgraded, handle_upgrade};
use rama_http_backend::{
    client::{
        BindBodyToConnLayer, HttpClientService, HttpConnId, HttpConnIdentifier,
        HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
    },
    server::HttpServer,
};
use rama_http_types::{
    Body, Method, Request, Response, Version,
    body::{StreamingBody as _, util::BodyExt as _},
};
use rama_net::{
    address::SocketAddress,
    client::{
        EstablishedClientConnection,
        pool::{MultiplexPool, PooledConnector},
    },
    uri::Uri,
};
use rama_tcp::{TcpStream, client::service::TcpConnector, server::TcpListener};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

/// How long a join must stay pending to count as held.
const HOLD: Duration = Duration::from_millis(200);
const LIMIT: Duration = Duration::from_secs(10);

/// An origin outside of any client scope: `/` answers at once, `/slow` sends one chunk and
/// never ends, `/gated` sends one chunk and the second once its gate opens, and CONNECT
/// echoes its tunnel.
struct Origin {
    addr: SocketAddress,
    /// The connections it accepted so far.
    accepted: Arc<AtomicUsize>,
    gate: Arc<Notify>,
}

async fn origin() -> SocketAddress {
    serve_origin().await.addr
}

async fn serve_origin() -> Origin {
    let exec = Executor::new();
    let listener = TcpListener::build(exec.clone())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().into();
    let gate = Arc::new(Notify::new());
    let opens = gate.clone();
    let http = Arc::new(
        HttpServer::auto(exec.clone())
            .service(service_fn(move |request| respond(request, opens.clone()))),
    );
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepts = accepted.clone();
    exec.spawn_task(listener.serve(service_fn(move |stream: TcpStream| {
        accepts.fetch_add(1, Ordering::SeqCst);
        let http = http.clone();
        async move { http.serve(stream).await }
    })));
    Origin {
        addr,
        accepted,
        gate,
    }
}

async fn respond(request: Request, gate: Arc<Notify>) -> Result<Response, Infallible> {
    if request.method() == Method::CONNECT {
        let upgrade = handle_upgrade(&request);
        tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(upgrade.await.unwrap());
            tokio::io::copy(&mut read, &mut write).await
        });
        return Ok(Response::new(Body::empty()));
    }
    let first = stream::iter([Ok::<_, BoxError>(Bytes::from_static(b"first"))]);
    let body = match &*request.uri().path_or_root() {
        "/slow" => Body::from_stream(first.chain(stream::pending())),
        "/gated" => Body::from_stream(first.chain(stream::once(async move {
            gate.notified().await;
            Ok(Bytes::from_static(b"second"))
        }))),
        _ => Body::from("done"),
    };
    Ok(Response::new(body))
}

fn connector(exec: Executor) -> HttpConnectRequestAdapter<HttpConnector<TcpConnector, Body>> {
    HttpConnectRequestAdapter::new(HttpConnector::new(TcpConnector::new(), exec))
}

fn request(addr: SocketAddress, path: &str, version: Version) -> Request {
    Request::builder()
        .uri(format!("http://{addr}{path}"))
        .version(version)
        .body(Body::empty())
        .unwrap()
}

/// Cancel `root` and give up the test's own hold, so only the work under test can hold it.
fn cancel(root: Scope) -> WeakScope {
    root.cancel(Cause::Owner);
    root.into_weak_scope()
}

/// Whether a join of `root` is still pending after [`HOLD`].
async fn join_is_held(root: &WeakScope) -> bool {
    match root.clone().into_scope() {
        Some(scope) => timeout(HOLD, scope.join()).await.is_err(),
        // A cancelled scope without holders refuses a new hold: it is drained.
        None => false,
    }
}

async fn assert_join_completes(root: WeakScope) {
    if let Some(scope) = root.into_scope() {
        timeout(LIMIT, scope.join())
            .await
            .expect("released work lets the join complete")
            .expect("joined before any hard phase");
    }
}

async fn read_to_end(response: Response) -> Bytes {
    timeout(LIMIT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes()
}

async fn established_connection_holds_the_join_until_dropped(version: Version) {
    let addr = origin().await;
    let root = Scope::new();
    let client = connector(Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request(addr, "/", version)))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    assert_eq!(read_to_end(response).await, "done");

    let root = cancel(root);
    assert!(
        join_is_held(&root).await,
        "a live connection holds the join"
    );
    drop(conn);
    assert_join_completes(root).await;
}

#[tokio::test]
async fn established_http1_connection_holds_the_join_until_dropped() {
    established_connection_holds_the_join_until_dropped(Version::HTTP_11).await;
}

#[tokio::test]
async fn established_http2_connection_holds_the_join_until_dropped() {
    established_connection_holds_the_join_until_dropped(Version::HTTP_2).await;
}

#[tokio::test]
async fn retained_client_extensions_do_not_hold_the_join() {
    let addr = origin().await;
    let root = Scope::new();
    let client = connector(Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request(addr, "/", Version::HTTP_11)))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let request_extensions = input.extensions().clone();
    let conn_extensions = conn.extensions().clone();
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    let response_extensions = response.extensions().clone();
    assert_eq!(read_to_end(response).await, "done");

    let root = cancel(root);
    drop(conn);
    assert_join_completes(root).await;
    drop((request_extensions, conn_extensions, response_extensions));
}

#[tokio::test]
async fn live_http1_response_body_holds_the_join_until_dropped() {
    let addr = origin().await;
    let root = Scope::new();
    let client = connector(Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } = timeout(
        LIMIT,
        client.serve(request(addr, "/slow", Version::HTTP_11)),
    )
    .await
    .unwrap()
    .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    let mut body = response.into_body();
    let first = timeout(LIMIT, body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), "first");
    assert!(!body.is_end_stream());

    let root = cancel(root);
    assert!(
        join_is_held(&root).await,
        "a live response body holds the join"
    );
    drop(body);
    assert_join_completes(root).await;
}

/// A CONNECT tunnel to the echoing origin, after one echoed ping, with every other handle on
/// the executor of `root` released.
async fn tunnel(addr: SocketAddress, root: &Scope) -> Upgraded {
    let client = connector(Executor::from(root.clone()));
    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri(Uri::from_authority_form(addr.into()))
        .version(Version::HTTP_11)
        .body(Body::empty())
        .unwrap();
    let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.serve(connect))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    assert!(response.status().is_success());
    let mut tunnel = timeout(LIMIT, handle_upgrade(response))
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    tunnel.write_all(b"ping").await.unwrap();
    let mut echo = [0; 4];
    timeout(LIMIT, tunnel.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"ping");
    tunnel
}

#[tokio::test]
async fn http1_connect_tunnel_holds_the_join_until_dropped() {
    let addr = origin().await;
    let root = Scope::new();
    let tunnel = tunnel(addr, &root).await;

    let root = cancel(root);
    assert!(join_is_held(&root).await, "a live tunnel holds the join");
    drop(tunnel);
    assert_join_completes(root).await;
}

#[tokio::test]
async fn http1_connect_tunnel_is_cut_at_the_hard_phase() {
    let addr = origin().await;
    let root = Scope::new();
    let mut tunnel = tunnel(addr, &root).await;

    root.abort(Cause::Owner);
    let err = timeout(LIMIT, tunnel.write_all(b"ping"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
}

type Pool = MultiplexPool<HttpClientService<Body>, HttpConnId>;
type PooledClient =
    HttpConnectRequestAdapter<HttpPooledConnector<HttpConnector<TcpConnector, Body>>>;

/// A pooled connector with a handle on its pool, so the connector can be let go of alone.
fn pooled(exec: Executor) -> (PooledClient, Pool) {
    let pool = HttpPooledConnectorConfig::default().build_pool();
    let client = HttpConnectRequestAdapter::new(BindBodyToConnLayer::new().into_layer(
        PooledConnector::new(
            HttpConnector::new(TcpConnector::new(), exec),
            pool.clone(),
            HttpConnIdentifier::new(),
        ),
    ));
    (client, pool)
}

/// A pool with one idle connection, made on the executor of `root`, with every other handle
/// on that executor released.
async fn idle_pooled(addr: SocketAddress, root: &Scope) -> Pool {
    let (client, pool) = pooled(Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request(addr, "/", Version::HTTP_11)))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    assert_eq!(read_to_end(response).await, "done");
    pool
}

#[tokio::test]
async fn idle_pooled_connection_closes_on_cancel_with_the_pool_alive() {
    let addr = origin().await;
    let root = Scope::new();
    let pool = idle_pooled(addr, &root).await;

    let root = cancel(root);
    assert_join_completes(root).await;
    drop(pool);
}

async fn next_data(body: &mut Body) -> Bytes {
    timeout(LIMIT, body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap()
}

/// An in-flight body on a pooled connection goes on after the cancel, a new request is served
/// on a new connection, and the join completes once the body is done with the pool alive.
async fn active_pooled_connection_drains_with_the_pool_alive(version: Version) {
    let origin = serve_origin().await;
    let root = Scope::new();
    let (client, pool) = pooled(Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request(origin.addr, "/gated", version)))
            .await
            .unwrap()
            .unwrap();
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    let mut body = response.into_body();
    assert_eq!(next_data(&mut body).await, "first");
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);

    let root = cancel(root);
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request(origin.addr, "/", version)))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    assert_eq!(read_to_end(response).await, "done");
    assert_eq!(
        origin.accepted.load(Ordering::SeqCst),
        2,
        "a request after the cancel dials a new connection"
    );

    assert!(
        join_is_held(&root).await,
        "an in-flight body holds the join"
    );
    origin.gate.notify_one();
    let rest = timeout(LIMIT, body.collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    assert_eq!(rest, "second");
    assert_join_completes(root).await;
    drop(pool);
}

#[tokio::test]
async fn active_pooled_http1_connection_drains_with_the_pool_alive() {
    active_pooled_connection_drains_with_the_pool_alive(Version::HTTP_11).await;
}

#[tokio::test]
async fn active_pooled_http2_connection_drains_with_the_pool_alive() {
    active_pooled_connection_drains_with_the_pool_alive(Version::HTTP_2).await;
}

#[tokio::test]
async fn idle_pooled_connection_is_cut_at_the_hard_phase() {
    let addr = origin().await;
    let root = Scope::new();
    let pool = idle_pooled(addr, &root).await;

    let observer = root.clone_weak();
    root.abort(Cause::Owner);
    drop(root);
    timeout(LIMIT, observer.drained())
        .await
        .expect("the cut connection releases the scope while the pool still has it");
    drop(pool);
}
