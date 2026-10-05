//! A CONNECT proxy reflects how each side of a tunnel ends (RFC 9113 §8.5, RFC 9114 §4.4):
//! an orderly end stays orderly, and a reset on one side resets the other, over HTTP/1,
//! HTTP/2 and HTTP/3.

use super::{TEST_TIMEOUT, credentials};
use rama::{
    Layer, Service, ServiceInput,
    http::{
        Body, Method, Request, Response, StatusCode,
        core::{client::conn, h2::Reason, h3},
        io::upgrade::{Upgraded, handle_upgrade},
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        matcher::MethodMatcher,
        server::HttpServer,
    },
    io::AbortIo,
    net::{address::SocketAddress, proxy::IoForwardService, tls::ApplicationProtocol, uri::Uri},
    quic::{ClientConfig, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::server::{ServerAuthData, TlsServerConfig},
};
use std::{convert::Infallible, io, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
    spawn,
    sync::oneshot,
    time::timeout,
};

#[derive(Clone, Copy, Debug)]
enum Wire {
    H1,
    H2,
    H3,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum End {
    /// The origin writes, then closes in order.
    OriginFin,
    /// The origin writes, then resets.
    OriginReset,
    /// The client aborts its tunnel.
    ClientAbort,
}

/// The proxied service: CONNECT establishes egress first, then relays the tunnel.
fn proxy() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let executor = Executor::new();
    UpgradeLayer::new(
        executor.clone(),
        MethodMatcher::CONNECT,
        EagerHttpProxyConnector::new(TcpConnector::new(), IoForwardService::new(executor)),
    )
    .into_layer(service_fn(async |_: Request| {
        Ok::<_, Infallible>(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap(),
        )
    }))
}

async fn tcp_proxy() -> SocketAddr {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::new())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    spawn(listener.serve(HttpServer::auto(Executor::new()).service(proxy())));
    address
}

async fn quic_proxy(auth: ServerAuthData) -> (SocketAddr, Endpoint) {
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let executor = Executor::new();
    let endpoint = Endpoint::build(executor.clone())
        .with_server_config(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let address = endpoint.local_addr().unwrap();
    spawn({
        let endpoint = endpoint.clone();
        let server = HttpServer::new_http3(executor.clone());
        let service = proxy();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let server = server.clone();
                let service = service.clone();
                executor.spawn_task(async move {
                    if let Ok(connection) = incoming.await {
                        _ = server.serve(connection, service).await;
                    }
                });
            }
        }
    });
    (address, endpoint)
}

/// A client tunnel through the proxy to `origin`, plus a way to abort it.
trait Tunnel: AsyncRead + AsyncWrite + Unpin + Send {
    fn abort(self: Box<Self>);
}

impl Tunnel for TokioTcpStream {
    fn abort(self: Box<Self>) {
        self.set_zero_linger().unwrap();
    }
}

impl Tunnel for Upgraded {
    fn abort(self: Box<Self>) {
        use rama::extensions::ExtensionsRef as _;
        self.extensions().self_get_arc::<AbortIo>().unwrap().abort();
    }
}

fn connect_request(origin: SocketAddr) -> Request {
    Request::builder()
        .method(Method::CONNECT)
        .uri(Uri::parse_authority_form(origin.to_string()).unwrap())
        .body(Body::empty())
        .unwrap()
}

async fn tunnel(version: Wire, origin: SocketAddr) -> (Box<dyn Tunnel>, Option<Endpoint>) {
    match version {
        Wire::H1 => {
            let mut stream = TokioTcpStream::connect(tcp_proxy().await).await.unwrap();
            stream
                .write_all(
                    format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
            (Box::new(stream), None)
        }
        Wire::H2 => {
            let io = TokioTcpStream::connect(tcp_proxy().await).await.unwrap();
            let (mut client, connection) = conn::http2::Builder::new(Executor::new())
                .handshake::<_, Body>(ServiceInput::new(io))
                .await
                .unwrap();
            spawn(connection);
            let response = client.send_request(connect_request(origin)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            (Box::new(handle_upgrade(response).await.unwrap()), None)
        }
        Wire::H3 => {
            let (auth, tls) = credentials();
            let (address, _server) = quic_proxy(auth).await;
            let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let endpoint = Endpoint::build(Executor::new())
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
            let connection = endpoint
                .connect_with(config, address, "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut client, driver) = h3::client::handshake::<Body>(
                connection,
                h3::connection::Config::default(),
                Executor::new(),
            )
            .unwrap();
            spawn(driver.run());
            let response = client.send_request(connect_request(origin)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let tunnel = handle_upgrade(response).await.unwrap();
            (Box::new(tunnel), Some(endpoint))
        }
    }
}

/// How the client side of the tunnel observed the end.
fn assert_reset(version: Wire, error: &io::Error) {
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionReset,
        "{version:?}: {error}"
    );
    let cause = error.get_ref();
    match version {
        Wire::H1 => {}
        Wire::H2 => assert_eq!(
            cause
                .and_then(|cause| cause.downcast_ref::<rama::http::core::h2::Error>())
                .and_then(|cause| cause.reason()),
            Some(Reason::CONNECT_ERROR)
        ),
        Wire::H3 => assert_eq!(
            cause
                .and_then(|cause| cause.downcast_ref::<h3::Error>())
                .map(|cause| cause.code()),
            Some(rama::http::proto::h3::Code::H3_CONNECT_ERROR)
        ),
    }
}

#[tokio::test]
async fn connect_tunnels_reflect_how_each_side_ends() {
    for version in [Wire::H1, Wire::H2, Wire::H3] {
        for end in [End::OriginFin, End::OriginReset, End::ClientAbort] {
            timeout(TEST_TIMEOUT * 2, run(version, end))
                .await
                .unwrap_or_else(|_| panic!("{version:?} {end:?} timed out"));
        }
    }
}

async fn run(version: Wire, end: End) {
    let origin = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    // The origin resets only once its data arrived, so the reset cannot discard it.
    let (received, reset) = oneshot::channel::<()>();
    let origin_task = spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        match end {
            End::OriginFin => {
                stream.shutdown().await.unwrap();
                // Wait for the client's orderly end in turn.
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
                rest
            }
            End::OriginReset => {
                reset.await.unwrap();
                stream.set_zero_linger().unwrap();
                drop(stream);
                Vec::new()
            }
            End::ClientAbort => {
                let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{version:?}");
                Vec::new()
            }
        }
    });

    let (mut tunnel, endpoint) = tunnel(version, origin_address).await;
    let mut hello = [0; 5];
    tunnel.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    _ = received.send(());
    match end {
        End::OriginFin => {
            let mut rest = Vec::new();
            tunnel.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "{version:?}");
            tunnel.write_all(b"bye").await.unwrap();
            tunnel.shutdown().await.unwrap();
            assert_eq!(origin_task.await.unwrap(), b"bye", "{version:?}");
        }
        End::OriginReset => {
            let error = loop {
                match tunnel.read(&mut [0; 16]).await {
                    Ok(0) => panic!("{version:?}: an origin reset must not read as an end"),
                    Ok(_) => {}
                    Err(error) => break error,
                }
            };
            assert_reset(version, &error);
            origin_task.await.unwrap();
        }
        End::ClientAbort => {
            tunnel.abort();
            origin_task.await.unwrap();
        }
    }
    if let Some(endpoint) = endpoint {
        endpoint.close(0u32, b"done");
    }
}
