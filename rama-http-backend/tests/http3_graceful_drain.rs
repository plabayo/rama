//! A graceful HTTP/3 shutdown closes a connection whose peer stopped acknowledging, once its
//! requests ended, after `goaway_drain_timeout` instead of waiting for acknowledgements.
#![cfg(feature = "quic")]
#![expect(
    clippy::expect_used,
    reason = "integration test failures identify the failed step"
)]

use rama_core::{
    extensions::ExtensionsRef as _,
    graceful::{Cause, Scope, WeakScope, scope_context},
    rt::Executor,
    service::service_fn,
};
use rama_http::{Body, Request, Response, StatusCode, body::util::BodyExt as _};
use rama_http_backend::server::HttpServer;
use rama_http_core::h3::{client, connection::Config};
use rama_net::address::SocketAddress;
use rama_quic::{
    ClientConfig, ConnectionError, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions,
};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::{MemoryDatagramControl, MemoryDatagramSocket};
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::{Instant, timeout},
};

const LIMIT: Duration = Duration::from_secs(10);
/// `H3_NO_ERROR` (RFC 9114 §8.1).
const H3_NO_ERROR: u64 = 0x100;

/// How the fixture's one request meets the graceful shutdown.
#[derive(Debug, Clone, Copy)]
enum Scenario {
    /// The client stops acknowledging when the request arrives; the shutdown follows the
    /// response.
    PeerGone,
    /// As `PeerGone`, with a bodyless (204) response, whose end is acknowledged on its own path.
    PeerGoneBodyless,
    /// A healthy client; the shutdown follows the response.
    Healthy,
    /// A healthy client; the shutdown starts while the request runs, answered this much later.
    AnsweredDuringShutdown(Duration),
    /// The scope is aborted while the request runs, which is never answered.
    AbortedWhileRunning,
}

/// What starts the shutdown.
#[derive(Debug, Clone, Copy)]
enum Trigger {
    /// The executor's shutdown guard.
    Guard,
    /// The executor's scope.
    Scope,
}

struct Endpoints {
    server: Endpoint,
    client: Endpoint,
    client_config: ClientConfig,
    client_faults: MemoryDatagramControl,
    address: std::net::SocketAddr,
}

/// An HTTP/3 server endpoint and a client endpoint that reaches it over memory.
fn endpoints() -> Endpoints {
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
    let client_faults = client_socket.fault_control();
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .expect("server endpoint");
    let client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .expect("client endpoint");
    let address = server_endpoint.local_addr().expect("server address");

    Endpoints {
        server: server_endpoint,
        client: client_endpoint,
        client_config,
        client_faults,
        address,
    }
}

/// Serve one request with `goaway_drain_timeout` as `scenario` describes and start a graceful
/// shutdown. Returns how long the server took to end after the shutdown started and the client
/// connection's close, if the server ended within `wait`.
async fn shutdown(
    goaway_drain_timeout: Option<Duration>,
    scenario: Scenario,
    trigger: Trigger,
    wait: Duration,
) -> Option<(Duration, ConnectionError)> {
    let Endpoints {
        server: server_endpoint,
        client: client_endpoint,
        client_config,
        client_faults,
        address,
    } = endpoints();

    let (signal, signalled) = oneshot::channel::<()>();
    let signalled = async move {
        _ = signalled.await;
    };
    let (shutdown, root) = match trigger {
        Trigger::Guard => (Some(Scope::new().with_signal(signalled)), Scope::never()),
        Trigger::Scope => (None, Scope::new().with_signal(signalled)),
    };
    let executor = match &shutdown {
        Some(shutdown) => Executor::from(shutdown.clone()),
        None => Executor::from(root.clone()),
    };
    let aborting = matches!(scenario, Scenario::AbortedWhileRunning);
    let arrived = Arc::new(Notify::new());
    let respond = Arc::new(Notify::new());
    let bodyless = matches!(scenario, Scenario::PeerGoneBodyless);
    let mut server = HttpServer::new_http3(executor);
    server.http3_mut().goaway_drain_timeout = goaway_drain_timeout;
    let served = tokio::spawn({
        let endpoint = server_endpoint.clone();
        let arrived = arrived.clone();
        let respond = respond.clone();
        async move {
            let incoming = endpoint.accept().await.expect("incoming connection");
            let connection = incoming.await.expect("accepted QUIC connection");
            server
                .serve(
                    connection,
                    service_fn(move |_: Request| {
                        let arrived = arrived.clone();
                        let respond = respond.clone();
                        async move {
                            arrived.notify_one();
                            respond.notified().await;
                            let response = if bodyless {
                                let mut response = Response::new(Body::empty());
                                *response.status_mut() = StatusCode::NO_CONTENT;
                                response
                            } else {
                                Response::new(Body::from("done"))
                            };
                            Ok::<_, Infallible>(response)
                        }
                    }),
                )
                .await
                .expect("server completed gracefully");
        }
    });
    drop(shutdown);

    let connection = client_endpoint
        .connect_with(client_config, address, "localhost")
        .expect("start QUIC connection")
        .await
        .expect("connect QUIC");
    let (mut requests, driver) =
        client::handshake::<Body, _>(connection.clone(), Config::default(), Executor::new())
            .expect("HTTP/3 client");
    tokio::spawn(driver.run());
    let request = Request::builder()
        .uri("https://localhost/")
        .body(Body::empty())
        .expect("request");
    let exchange = async {
        let response = requests.send_request(request).await.ok()?;
        Some(response.into_body().collect().await.ok()?.to_bytes())
    };
    let mut started = None;
    let mut signal = Some(signal);
    let answer = async {
        arrived.notified().await;
        match scenario {
            // From here on the client sends nothing: it never acknowledges the response.
            Scenario::PeerGone | Scenario::PeerGoneBodyless => client_faults.drop_next(usize::MAX),
            Scenario::Healthy => {}
            Scenario::AbortedWhileRunning => {
                started = Some(Instant::now());
                root.abort(Cause::Reason("test"));
                return;
            }
            Scenario::AnsweredDuringShutdown(after) => {
                started = Some(Instant::now());
                signal
                    .take()
                    .expect("signal")
                    .send(())
                    .expect("shutdown signal");
                tokio::time::sleep(after).await;
            }
        }
        respond.notify_one();
    };
    let (body, ()) = timeout(LIMIT, async { tokio::join!(exchange, answer) })
        .await
        .expect("the exchange completes");
    if aborting {
        assert!(body.is_none(), "an aborted request is cut");
    } else {
        let expected: &[u8] = if bodyless { b"" } else { b"done" };
        let body = body.expect("the response is delivered");
        assert_eq!(body.as_ref(), expected, "the response is delivered whole");
    }

    // An abort dropped the scope's signals, the receiver with them.
    if let Some(signal) = signal.take().filter(|_| !aborting) {
        started = Some(Instant::now());
        signal.send(()).expect("shutdown signal");
    }
    let started = started.expect("the shutdown started");
    let served = timeout(wait, served).await.ok()?;
    served.expect("server task");
    let ended = started.elapsed();
    let closed = timeout(LIMIT, connection.closed())
        .await
        .expect("the client connection closes");
    Some((ended, closed))
}

fn closed_cleanly(closed: &ConnectionError) -> bool {
    matches!(closed, ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == H3_NO_ERROR)
}

#[tokio::test]
async fn a_peer_that_stopped_acknowledging_is_closed_after_the_goaway_drain_timeout() {
    let (ended, closed) = shutdown(
        Some(Duration::from_millis(300)),
        Scenario::PeerGone,
        Trigger::Guard,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(3), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn a_bodyless_response_to_a_peer_that_stopped_acknowledging_is_bounded_too() {
    let (ended, closed) = shutdown(
        Some(Duration::from_millis(300)),
        Scenario::PeerGoneBodyless,
        Trigger::Guard,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(3), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn without_a_goaway_drain_timeout_the_server_waits_for_acknowledgements() {
    let ended = shutdown(
        None,
        Scenario::PeerGone,
        Trigger::Guard,
        Duration::from_secs(3),
    )
    .await;
    assert!(ended.is_none(), "the server waited for the peer: {ended:?}");
}

#[tokio::test]
async fn a_goaway_drain_timeout_beyond_the_clock_waits_instead_of_failing() {
    let ended = shutdown(
        Some(Duration::MAX),
        Scenario::PeerGone,
        Trigger::Guard,
        Duration::from_secs(3),
    )
    .await;
    assert!(ended.is_none(), "the server waited for the peer: {ended:?}");
}

#[tokio::test]
async fn a_healthy_peer_ends_the_drain_before_the_timeout() {
    let (ended, closed) = shutdown(
        Some(Duration::from_secs(5)),
        Scenario::Healthy,
        Trigger::Guard,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(2), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn requests_still_running_are_not_cut_by_the_goaway_drain_timeout() {
    // The response comes well after the timeout: it is still delivered whole.
    let (ended, closed) = shutdown(
        Some(Duration::from_millis(100)),
        Scenario::AnsweredDuringShutdown(Duration::from_millis(600)),
        Trigger::Guard,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended >= Duration::from_millis(600), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn a_scope_cancel_drains_like_the_guard() {
    let (ended, closed) = shutdown(
        Some(Duration::from_secs(5)),
        Scenario::Healthy,
        Trigger::Scope,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(2), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn requests_running_at_a_scope_cancel_finish_whole() {
    let (ended, closed) = shutdown(
        Some(Duration::from_millis(100)),
        Scenario::AnsweredDuringShutdown(Duration::from_millis(600)),
        Trigger::Scope,
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended >= Duration::from_millis(600), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn a_scope_abort_drops_the_connection_with_its_running_request() {
    let (ended, _closed) = shutdown(None, Scenario::AbortedWhileRunning, Trigger::Scope, LIMIT)
        .await
        .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(2), "{ended:?}");
}

#[tokio::test]
async fn default_connections_get_isolated_cancellable_scopes() {
    let Endpoints {
        server: server_endpoint,
        client: client_endpoint,
        client_config,
        address,
        ..
    } = endpoints();
    let (scopes_tx, mut scopes) = mpsc::unbounded_channel();
    let respond = Arc::new(Notify::new());
    let server = HttpServer::new_http3(Executor::new());
    let serving = tokio::spawn({
        let respond = respond.clone();
        async move {
            let mut served = Vec::new();
            for _ in 0..2 {
                let incoming = server_endpoint.accept().await.expect("incoming connection");
                let connection = incoming.await.expect("accepted QUIC connection");
                let server = server.clone();
                let scopes_tx = scopes_tx.clone();
                let respond = respond.clone();
                served.push(tokio::spawn(async move {
                    server
                        .serve(
                            connection,
                            service_fn(move |req: Request| {
                                let scope =
                                    scope_context(req.extensions()).and_then(WeakScope::into_scope);
                                scopes_tx.send(scope).expect("test receives scopes");
                                let respond = respond.clone();
                                async move {
                                    respond.notified().await;
                                    Ok::<_, Infallible>(Response::new(Body::from("done")))
                                }
                            }),
                        )
                        .await
                }));
            }
            served
        }
    });

    let mut clients = Vec::new();
    for _ in 0..2 {
        let connection = client_endpoint
            .connect_with(client_config.clone(), address, "localhost")
            .expect("start QUIC connection")
            .await
            .expect("connect QUIC");
        let (mut requests, driver) =
            client::handshake::<Body, _>(connection.clone(), Config::default(), Executor::new())
                .expect("HTTP/3 client");
        tokio::spawn(driver.run());
        let request = Request::builder()
            .uri("https://localhost/")
            .body(Body::empty())
            .expect("request");
        // The request handle is handed back: dropping it would close the client connection.
        let exchange = tokio::spawn(async move {
            let response = requests.send_request(request).await.expect("response");
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            (requests, body)
        });
        let scope = timeout(LIMIT, scopes.recv())
            .await
            .expect("the request arrives")
            .flatten()
            .expect("every request sees its connection scope");
        assert!(!scope.is_never());
        clients.push((connection, exchange, scope));
    }

    // Cancelled from state the handler sees: only its own connection drains.
    let mut served = timeout(LIMIT, serving)
        .await
        .expect("both accepted")
        .expect("task")
        .into_iter();
    let (first_served, second_served) = (
        served.next().expect("first"),
        served.next().expect("second"),
    );
    clients[0].2.cancel(Cause::Reason("handler"));
    assert!(!clients[1].2.is_cancelled());
    respond.notify_waiters();
    let mut clients = clients.into_iter();
    let (_first_connection, first_exchange, _) = clients.next().expect("first");
    let (_first_requests, body) = timeout(LIMIT, first_exchange)
        .await
        .expect("answered")
        .expect("task");
    assert_eq!(body.as_ref(), b"done");
    timeout(LIMIT, first_served)
        .await
        .expect("the cancelled connection ends")
        .expect("task")
        .expect("served");

    let (_second_connection, second_exchange, second_scope) = clients.next().expect("second");
    let (_second_requests, body) = timeout(LIMIT, second_exchange)
        .await
        .expect("answered")
        .expect("task");
    assert_eq!(body.as_ref(), b"done");
    assert!(!second_scope.is_cancelled());
    assert!(!second_served.is_finished(), "the sibling keeps serving");
    second_scope.abort(Cause::Owner);
    timeout(LIMIT, second_served)
        .await
        .expect("the aborted connection ends")
        .expect("task")
        .expect("served");
}
