//! A graceful HTTP/3 shutdown closes a connection whose peer stopped acknowledging, once its
//! requests ended, after `goaway_drain_timeout` instead of waiting for acknowledgements.

#![expect(
    clippy::expect_used,
    reason = "integration test failures identify the failed step"
)]

use rama_core::{graceful::Shutdown, rt::Executor, service::service_fn};
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
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    sync::{Notify, oneshot},
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
}

/// Serve one request with `goaway_drain_timeout` as `scenario` describes and start a graceful
/// shutdown. Returns how long the server took to end after the shutdown started and the client
/// connection's close, if the server ended within `wait`.
async fn shutdown(
    goaway_drain_timeout: Option<Duration>,
    scenario: Scenario,
    wait: Duration,
) -> Option<(Duration, ConnectionError)> {
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

    let (signal, signalled) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        _ = signalled.await;
    });
    let arrived = Arc::new(Notify::new());
    let respond = Arc::new(Notify::new());
    let bodyless = matches!(scenario, Scenario::PeerGoneBodyless);
    let mut server = HttpServer::new_http3(Executor::graceful(shutdown.guard()));
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
        let response = requests.send_request(request).await.expect("response");
        response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
    };
    let mut started = None;
    let mut signal = Some(signal);
    let answer = async {
        arrived.notified().await;
        match scenario {
            // From here on the client sends nothing: it never acknowledges the response.
            Scenario::PeerGone | Scenario::PeerGoneBodyless => client_faults.drop_next(usize::MAX),
            Scenario::Healthy => {}
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
    let expected: &[u8] = if bodyless { b"" } else { b"done" };
    assert_eq!(body.as_ref(), expected, "the response is delivered whole");

    if let Some(signal) = signal.take() {
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
    let (ended, closed) = shutdown(Some(Duration::from_millis(300)), Scenario::PeerGone, LIMIT)
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
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended < Duration::from_secs(3), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}

#[tokio::test]
async fn without_a_goaway_drain_timeout_the_server_waits_for_acknowledgements() {
    let ended = shutdown(None, Scenario::PeerGone, Duration::from_secs(3)).await;
    assert!(ended.is_none(), "the server waited for the peer: {ended:?}");
}

#[tokio::test]
async fn a_goaway_drain_timeout_beyond_the_clock_waits_instead_of_failing() {
    let ended = shutdown(
        Some(Duration::MAX),
        Scenario::PeerGone,
        Duration::from_secs(3),
    )
    .await;
    assert!(ended.is_none(), "the server waited for the peer: {ended:?}");
}

#[tokio::test]
async fn a_healthy_peer_ends_the_drain_before_the_timeout() {
    let (ended, closed) = shutdown(Some(Duration::from_secs(5)), Scenario::Healthy, LIMIT)
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
        LIMIT,
    )
    .await
    .expect("the server ends within the limit");
    assert!(ended >= Duration::from_millis(600), "{ended:?}");
    assert!(closed_cleanly(&closed), "{closed:?}");
}
