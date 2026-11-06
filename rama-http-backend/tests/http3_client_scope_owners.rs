//! An HTTP/3 client connection on an executor holds that executor's scope while it lives, is
//! drained by its pool once that scope is cancelled and is cut at its hard phase.
#![cfg(feature = "quic")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{
    convert::Infallible,
    io::ErrorKind,
    num::NonZeroUsize,
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
    extensions::{Extensions, ExtensionsRef as _},
    futures::{StreamExt as _, stream},
    graceful::{Cause, Scope, WeakScope},
    rt::Executor,
    service::{BoxService, service_fn},
};
use rama_http::io::upgrade::{Upgraded, handle_upgrade};
use rama_http_backend::{
    client::{
        BindBodyToConnLayer, Http3Transport, HttpClientService, HttpConnId, HttpConnIdentifier,
        HttpConnectRequestAdapter, HttpConnector, HttpPooledConnector, HttpPooledConnectorConfig,
    },
    server::HttpServer,
};
use rama_http_core::h3::{connection::Config, transport::BoxedConnection};
use rama_http_types::{
    Body, Method, Request, Response, Version,
    body::{StreamingBody as _, util::BodyExt as _},
    proto::ext::Protocol,
};
use rama_net::{
    address::{Authority, Domain, SocketAddress},
    client::{
        ConnectRequest, ConnectionError, EstablishedClientConnection,
        pool::{ConnectionReuse, ConnectionReusePolicy, MultiplexPool, PooledConnector, ReuseKey},
    },
    conn::{ConnectionHealth, ConnectionHealthWatcher},
    uri::Uri,
};
use rama_quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

/// How long a join must stay pending to count as held.
const HOLD: Duration = Duration::from_millis(200);
const LIMIT: Duration = Duration::from_secs(10);

// The fixture always dials the same origin with the same identity and trust anchors.
#[derive(Debug)]
struct FixedTlsPolicy;

impl ConnectionReusePolicy for FixedTlsPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        self.connection_key()
    }
}

type Dialer = BoxService<
    ConnectRequest,
    EstablishedClientConnection<Http3Transport, ConnectRequest>,
    ConnectionError,
>;

/// An HTTP/3 origin outside of any client scope over an in-memory link: `/` answers at once,
/// `/slow` sends one chunk and never ends, `/gated` sends one chunk and the second once its
/// gate opens, and CONNECT (extended or not) echoes its tunnel.
struct Origin {
    /// Cancelling it sends a GOAWAY on every connection, whose in-flight requests go on.
    server: Scope,
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    dialer: Dialer,
    /// The connections the client dialed so far.
    dials: Arc<AtomicUsize>,
    gate: Arc<Notify>,
}

impl Origin {
    fn close(self) {
        self.client_endpoint.close(0_u32, b"test complete");
        self.server_endpoint.close(0_u32, b"test complete");
    }
}

fn serve_origin() -> Origin {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("server identity");
    let alpn = || [b"h3".as_slice().into()].into_iter().collect();
    let server_tls = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().expect("certificate").clone()])
        .expect("trust anchors");
    let transport = || {
        let mut transport = TransportConfig::default();
        transport.maybe_set_max_idle_timeout(None);
        Config::default()
            .configure_transport(&mut transport)
            .expect("HTTP/3 transport config");
        Arc::new(transport)
    };
    let mut server_config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
        .expect("server TLS config");
    server_config.set_transport_config(transport());
    let mut client_config = ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
        .expect("client TLS config");
    client_config.set_transport_config(transport());
    let (server_socket, client_socket) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(443),
        SocketAddress::local_ipv4(444),
        NonZeroUsize::MIN,
    );
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .expect("server endpoint");
    let client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .expect("client endpoint");
    let address = server_endpoint.local_addr().expect("server address");

    let gate = Arc::new(Notify::new());
    let server = Scope::new();
    let mut http = HttpServer::new_http3(Executor::from(server.clone()));
    http.http3_mut().extended_connect = true;
    let opens = gate.clone();
    let http = Arc::new(http.service(service_fn(move |request| respond(request, opens.clone()))));
    let accepting = server_endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            let http = http.clone();
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    _ = http.serve(connection).await;
                }
            });
        }
    });

    let dials = Arc::new(AtomicUsize::new(0));
    let dialer = BoxService::new(service_fn({
        let endpoint = client_endpoint.clone();
        let dials = dials.clone();
        move |input: ConnectRequest| {
            let endpoint = endpoint.clone();
            let client_config = client_config.clone();
            let dials = dials.clone();
            async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let connection = endpoint
                    .connect_with(client_config, address, "localhost")
                    .expect("start QUIC connection")
                    .await
                    .expect("connect QUIC");
                connection
                    .extensions()
                    .insert(ConnectionReuse::new(FixedTlsPolicy));
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    conn: Http3Transport {
                        connection: BoxedConnection::new(connection),
                        config: Arc::new(Config::default()),
                    },
                    input,
                })
            }
        }
    }));
    Origin {
        server,
        client_endpoint,
        server_endpoint,
        dialer,
        dials,
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

fn connector(
    origin: &Origin,
    exec: Executor,
) -> HttpConnectRequestAdapter<HttpConnector<Dialer, Body>> {
    HttpConnectRequestAdapter::new(HttpConnector::new(origin.dialer.clone(), exec))
}

fn request(path: &str) -> Request {
    Request::builder()
        .uri(format!("https://localhost{path}"))
        .version(Version::HTTP_3)
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

/// Abort `root` and give up the test's own hold; the hard phase alone must release it.
async fn assert_abort_drains(root: Scope) {
    let observer = root.clone_weak();
    root.abort(Cause::Owner);
    drop(root);
    timeout(LIMIT, observer.drained())
        .await
        .expect("the cut connection releases the scope");
}

async fn read_to_end(response: Response) -> Bytes {
    timeout(LIMIT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes()
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

type Pool = MultiplexPool<HttpClientService<Body>, HttpConnId>;
type PooledClient = HttpConnectRequestAdapter<HttpPooledConnector<HttpConnector<Dialer, Body>>>;

/// A pooled connector with a handle on its pool, so the connector can be let go of alone.
fn pooled(origin: &Origin, exec: Executor) -> (PooledClient, Pool) {
    let pool = HttpPooledConnectorConfig {
        idle_timeout: None,
        ..Default::default()
    }
    .build_pool();
    let client = HttpConnectRequestAdapter::new(BindBodyToConnLayer::new().into_layer(
        PooledConnector::new(
            HttpConnector::new(origin.dialer.clone(), exec),
            pool.clone(),
            HttpConnIdentifier::new(),
        ),
    ));
    (client, pool)
}

/// A pool with one idle connection, made on the executor of `root`, with every other handle
/// on that executor released.
async fn idle_pooled(origin: &Origin, root: &Scope) -> Pool {
    let (client, pool) = pooled(origin, Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.serve(request("/")))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    assert_eq!(read_to_end(response).await, "done");
    pool
}

/// A response whose body has sent its first chunk and does not end on its own, on a
/// connection made on the executor of `root`, with every other handle on it released.
async fn live_body(origin: &Origin, root: &Scope) -> Body {
    let client = connector(origin, Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request("/slow")))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    let mut body = response.into_body();
    assert_eq!(next_data(&mut body).await, "first");
    assert!(!body.is_end_stream());
    body
}

/// A pooled CONNECT tunnel, extended or not, to the echoing origin after one echoed ping,
/// with every other handle on the executor of `root` released but the pool.
async fn tunnel(origin: &Origin, root: &Scope, extended: bool) -> (Upgraded, Pool) {
    let (client, pool) = pooled(origin, Executor::from(root.clone()));
    let connect = if extended {
        let connect = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost/echo")
            .version(Version::HTTP_3)
            .body(Body::empty())
            .unwrap();
        connect.extensions().insert(Protocol::from_static("echo"));
        connect
    } else {
        Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::from_authority_form(Authority::from((
                Domain::from_static("localhost"),
                443,
            ))))
            .version(Version::HTTP_3)
            .body(Body::empty())
            .unwrap()
    };
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
    (tunnel, pool)
}

#[tokio::test(start_paused = true)]
async fn established_http3_connection_holds_the_join_until_dropped() {
    let origin = serve_origin();
    let root = Scope::new();
    let client = connector(&origin, Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.serve(request("/")))
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
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn idle_pooled_http3_connection_closes_on_cancel_with_the_pool_alive() {
    let origin = serve_origin();
    let root = Scope::new();
    let pool = idle_pooled(&origin, &root).await;

    let root = cancel(root);
    assert_join_completes(root).await;
    drop(pool);
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn idle_pooled_http3_connection_is_cut_at_the_hard_phase() {
    let origin = serve_origin();
    let root = Scope::new();
    let pool = idle_pooled(&origin, &root).await;

    assert_abort_drains(root).await;
    drop(pool);
    origin.close();
}

/// An in-flight body on a pooled connection goes on after the cancel, a new request is served
/// on a new connection, and the join completes once the body is done with the pool alive.
#[tokio::test(start_paused = true)]
async fn active_pooled_http3_connection_drains_with_the_pool_alive() {
    let origin = serve_origin();
    let root = Scope::new();
    let (client, pool) = pooled(&origin, Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request("/gated")))
            .await
            .unwrap()
            .unwrap();
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    let mut body = response.into_body();
    assert_eq!(next_data(&mut body).await, "first");
    assert_eq!(origin.dials.load(Ordering::SeqCst), 1);

    let root = cancel(root);
    let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.serve(request("/")))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    drop(conn);
    assert_eq!(read_to_end(response).await, "done");
    assert_eq!(
        origin.dials.load(Ordering::SeqCst),
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
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn live_http3_response_body_holds_the_join_until_dropped() {
    let origin = serve_origin();
    let root = Scope::new();
    let body = live_body(&origin, &root).await;

    let root = cancel(root);
    assert!(
        join_is_held(&root).await,
        "a live response body holds the join"
    );
    drop(body);
    assert_join_completes(root).await;
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn live_http3_response_body_is_cut_at_the_hard_phase() {
    let origin = serve_origin();
    let root = Scope::new();
    let mut body = live_body(&origin, &root).await;

    assert_abort_drains(root).await;
    let frame = timeout(LIMIT, body.frame()).await.unwrap();
    assert!(
        matches!(frame, Some(Err(_))),
        "a cut body fails instead of ending"
    );
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn live_http3_response_body_on_a_draining_connection_is_cut_at_the_hard_phase() {
    let origin = serve_origin();
    let root = Scope::new();
    let client = connector(&origin, Executor::from(root.clone()));
    let EstablishedClientConnection { conn, input } =
        timeout(LIMIT, client.serve(request("/slow")))
            .await
            .unwrap()
            .unwrap();
    drop(client);
    let response = timeout(LIMIT, conn.serve(input)).await.unwrap().unwrap();
    let health = conn.extensions().clone();
    drop(conn);
    let mut body = response.into_body();
    assert_eq!(next_data(&mut body).await, "first");

    origin.server.cancel(Cause::Owner);
    // The client marks a connection broken once it sees the GOAWAY.
    timeout(LIMIT, async {
        while health
            .get_ref::<ConnectionHealthWatcher>()
            .is_none_or(|watcher| watcher.health() == ConnectionHealth::Healthy)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the client sees the GOAWAY");
    assert_abort_drains(root).await;
    let frame = timeout(LIMIT, body.frame()).await.unwrap();
    assert!(
        matches!(frame, Some(Err(_))),
        "a cut body fails instead of ending"
    );
    origin.close();
}

async fn http3_tunnel_holds_the_join_until_dropped(extended: bool) {
    let origin = serve_origin();
    let root = Scope::new();
    let (tunnel, pool) = tunnel(&origin, &root, extended).await;

    let root = cancel(root);
    assert!(join_is_held(&root).await, "a live tunnel holds the join");
    drop(tunnel);
    assert_join_completes(root).await;
    drop(pool);
    origin.close();
}

async fn http3_tunnel_is_cut_at_the_hard_phase(extended: bool) {
    let origin = serve_origin();
    let root = Scope::new();
    let (mut tunnel, pool) = tunnel(&origin, &root, extended).await;

    assert_abort_drains(root).await;
    // A tunnel write is buffered until flushed.
    let ping = async {
        tunnel.write_all(b"ping").await?;
        tunnel.flush().await
    };
    let err = timeout(LIMIT, ping).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    let mut echo = [0; 4];
    assert!(
        timeout(LIMIT, tunnel.read(&mut echo))
            .await
            .unwrap()
            .is_err(),
        "a cut tunnel fails instead of ending"
    );
    drop(pool);
    origin.close();
}

#[tokio::test(start_paused = true)]
async fn http3_connect_tunnel_holds_the_join_until_dropped() {
    http3_tunnel_holds_the_join_until_dropped(false).await;
}

#[tokio::test(start_paused = true)]
async fn http3_extended_connect_tunnel_holds_the_join_until_dropped() {
    http3_tunnel_holds_the_join_until_dropped(true).await;
}

#[tokio::test(start_paused = true)]
async fn http3_connect_tunnel_is_cut_at_the_hard_phase() {
    http3_tunnel_is_cut_at_the_hard_phase(false).await;
}

#[tokio::test(start_paused = true)]
async fn http3_extended_connect_tunnel_is_cut_at_the_hard_phase() {
    http3_tunnel_is_cut_at_the_hard_phase(true).await;
}
