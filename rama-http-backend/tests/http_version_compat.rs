//! Every ordered HTTP/1.1, HTTP/2 and HTTP/3 relay pair over memory transports.
//! Real wire engines exercise version adaptation, framing and streaming together.
#![expect(clippy::expect_used, reason = "test assertions identify failed stages")]

use rama_core::{
    Service, ServiceInput,
    futures::stream,
    rt::{Executor, spawn},
    service::service_fn,
};
use rama_http::{
    Body, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version,
    body::{Frame, util::BodyExt as _},
    layer::version_adapter::{ResponseVersionAdapter, adapt_request_version},
};
use rama_http_backend::{
    client::{Http3Transport, HttpClientService, http_connect},
    server::HttpServer,
};
use rama_http_core::h3::connection::Config;
use rama_net::address::SocketAddress;
use rama_quic::{Connection, Endpoint, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::timeout};

const LIMIT: Duration = Duration::from_secs(20);
const VERSIONS: [Version; 3] = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];

/// A connected in-memory QUIC pair.
struct QuicPair {
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    client: Connection,
    server: Connection,
}

impl QuicPair {
    async fn new() -> Self {
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
            .expect("server identity");
        let alpn = || [b"h3".as_slice().into()].into_iter().collect();
        let server_tls = TlsServerConfig::new()
            .with_alpn(alpn())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn())
            .try_with_server_trust_anchors([identity
                .cert_chain
                .last()
                .expect("certificate")
                .clone()])
            .expect("trust anchors");
        let transport = || {
            let mut transport = TransportConfig::default();
            Config::default()
                .configure_transport(&mut transport)
                .expect("transport config");
            Arc::new(transport)
        };
        let mut server_config =
            rama_quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
                .expect("server config");
        server_config.set_transport_config(transport());
        let mut client_config =
            rama_quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
                .expect("client config");
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
        let accept = spawn({
            let endpoint = server_endpoint.clone();
            async move {
                endpoint
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accepted")
            }
        });
        let client = client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().expect("server address"),
                "localhost",
            )
            .expect("connect")
            .await
            .expect("connected");
        let server = accept.await.expect("accept task");
        Self {
            client_endpoint,
            server_endpoint,
            client,
            server,
        }
    }

    async fn close(self) {
        self.client.close(0u32, b"test complete");
        tokio::join!(
            self.client_endpoint.shutdown(),
            self.server_endpoint.shutdown()
        );
    }
}

fn handshake_request(version: Version) -> Request {
    Request::builder()
        .version(version)
        .uri("https://localhost/compat?x=1")
        .body(Body::empty())
        .expect("request")
}

/// One HTTP hop: `service` behind a real server engine on `version`, and a client of it.
struct Hop {
    client: Arc<HttpClientService<Body>>,
    quic: Option<QuicPair>,
}

impl Hop {
    async fn start<S>(version: Version, service: S) -> Self
    where
        S: Service<rama_http::Request, Output = Response, Error = Infallible> + Clone,
    {
        let executor = Executor::default();
        if version == Version::HTTP_3 {
            let quic = QuicPair::new().await;
            let server = HttpServer::new_http3(executor.clone());
            let service = server.service(service);
            let connection = quic.server.clone();
            spawn(async move {
                _ = service.serve(connection).await;
            });
            let transport = Http3Transport {
                connection: quic.client.clone(),
                config: Arc::new(Config::default()),
            };
            let client = http_connect(transport, handshake_request(version), executor)
                .await
                .expect("HTTP/3 client")
                .conn;
            return Self {
                client: Arc::new(client),
                quic: Some(quic),
            };
        }
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        spawn({
            let executor = executor.clone();
            async move {
                if version == Version::HTTP_2 {
                    let server = HttpServer::new_h2(executor);
                    _ = server.serve(ServiceInput::new(server_io), service).await;
                } else {
                    _ = HttpServer::new_http1(executor)
                        .serve(ServiceInput::new(server_io), service)
                        .await;
                }
            }
        });
        let client = http_connect(
            ServiceInput::new(client_io),
            handshake_request(version),
            executor,
        )
        .await
        .expect("stream client")
        .conn;
        Self {
            client: Arc::new(client),
            quic: None,
        }
    }

    async fn close(self) {
        drop(self.client);
        if let Some(quic) = self.quic {
            quic.close().await;
        }
    }
}

async fn matrix(ingress: Version, egress: Version) {
    let (upload_end, observed_end) = tokio::sync::oneshot::channel();
    let upload_end = Arc::new(parking_lot::Mutex::new(Some(upload_end)));
    let origin = Hop::start(
        egress,
        service_fn(move |req: Request| {
            let upload_end = upload_end.clone();
            async move {
                assert_eq!(req.version(), egress);
                assert_eq!(req.uri().path_or_root(), "/compat");
                assert_eq!(req.uri().query_or_empty(), "x=1");
                assert_eq!(req.headers()["x-compat"], "preserved");
                if egress >= Version::HTTP_2 {
                    assert!(!req.headers().contains_key("transfer-encoding"));
                    assert!(!req.headers().contains_key("connection"));
                }
                let method = req.method().clone();
                let no_content = req.headers().contains_key("x-no-content");
                let observe = req.headers().contains_key("x-observe-upload");
                let mut body = req.into_body();
                if observe {
                    let sender = upload_end.lock().take();
                    body = Body::from_frame_stream(stream::unfold(
                        (body, sender),
                        |(mut body, mut sender)| async move {
                            let Some(frame) = body.frame().await else {
                                if let Some(sender) = sender {
                                    _ = sender.send(true);
                                }
                                return None;
                            };
                            if frame.is_err()
                                && let Some(sender) = sender.take()
                            {
                                _ = sender.send(false);
                            }
                            Some((frame, (body, sender)))
                        },
                    ));
                }
                let mut response = Response::new(body);
                if method == Method::HEAD {
                    *response.body_mut() = Body::from("not sent for HEAD");
                }
                if no_content {
                    *response.status_mut() = StatusCode::NO_CONTENT;
                    *response.body_mut() = Body::empty();
                }
                response
                    .headers_mut()
                    .insert("trailer", HeaderValue::from_static("x-checksum"));
                response
                    .headers_mut()
                    .insert("x-origin", HeaderValue::from_static("preserved"));
                Ok::<_, Infallible>(response)
            }
        }),
    )
    .await;
    let upstream = origin.client.clone();
    let relay = Arc::new(
        ResponseVersionAdapter::new(
            service_fn(move |mut req: Request| {
                let upstream = upstream.clone();
                async move {
                    adapt_request_version(&mut req, egress)?;
                    upstream.serve(req).await
                }
            })
            .boxed(),
        )
        .boxed(),
    );
    let proxy = Hop::start(
        ingress,
        service_fn(move |req: Request| {
            let relay = relay.clone();
            async move { Ok::<_, Infallible>(relay.serve(req).await.expect("relay")) }
        }),
    )
    .await;
    for kind in 0..4 {
        let body = match kind {
            0 => Body::empty(),
            1 => Body::from("known length payload"),
            3 => Body::from(vec![b'x'; 256 * 1024]),
            _ => Body::from_frame_stream(stream::iter([
                Ok::<_, Infallible>(Frame::data("chunk one".into())),
                Ok(Frame::data(" and chunk two".into())),
            ])),
        };
        let mut req = handshake_request(ingress);
        *req.method_mut() = Method::POST;
        req.headers_mut()
            .insert("x-compat", HeaderValue::from_static("preserved"));
        *req.body_mut() = body;
        let response = proxy.client.serve(req).await.expect("response");
        assert_eq!(response.version(), ingress);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-origin"], "preserved");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let expected = match kind {
            0 => vec![],
            1 => b"known length payload".to_vec(),
            2 => b"chunk one and chunk two".to_vec(),
            _ => vec![b'x'; 256 * 1024],
        };
        assert_eq!(bytes.as_ref(), expected.as_slice());
    }
    // Keep the producer open until the first echoed bytes reach the client.
    // Collecting either request or response in the proxy deadlocks this assertion.
    let (tx, rx) = mpsc::channel(1);
    let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|frame| (Ok::<_, Infallible>(frame), rx))
    }));
    let mut req = handshake_request(ingress);
    *req.method_mut() = Method::POST;
    req.headers_mut()
        .insert("x-compat", HeaderValue::from_static("preserved"));
    req.headers_mut()
        .insert("te", HeaderValue::from_static("trailers"));
    req.headers_mut()
        .insert("trailer", HeaderValue::from_static("x-checksum"));
    *req.body_mut() = body;
    tx.send(Frame::data("first".into()))
        .await
        .expect("first chunk");
    let mut response = proxy
        .client
        .serve(req)
        .await
        .expect("stream response")
        .into_body();
    let first = response
        .frame()
        .await
        .expect("first frame")
        .expect("first data");
    assert_eq!(first.data_ref().expect("data").as_ref(), b"first");
    tx.send(Frame::data("second".into()))
        .await
        .expect("second chunk");
    // Trailers are explicitly announced to HTTP/1 peers.
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", HeaderValue::from_static("done"));
    tx.send(Frame::trailers(trailers)).await.expect("trailers");
    drop(tx);
    let rest = response.collect().await.expect("stream rest");
    assert_eq!(
        rest.trailers().expect("preserved trailers")["x-checksum"],
        "done"
    );
    assert_eq!(rest.to_bytes().as_ref(), b"second");
    for method in [Method::HEAD, Method::GET] {
        let mut req = handshake_request(ingress);
        *req.method_mut() = method.clone();
        req.headers_mut()
            .insert("x-compat", HeaderValue::from_static("preserved"));
        if method == Method::GET {
            req.headers_mut()
                .insert("x-no-content", HeaderValue::from_static("1"));
        }
        let response = proxy.client.serve(req).await.expect("bodyless response");
        assert_eq!(
            response.status(),
            if method == Method::HEAD {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            }
        );
        assert!(
            response
                .into_body()
                .collect()
                .await
                .expect("bodyless payload")
                .to_bytes()
                .is_empty()
        );
    }
    // A failed streaming upload must not become a successful truncated echo.
    let (tx, rx) = mpsc::channel(1);
    let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|frame| (frame, rx))
    }));
    let mut req = handshake_request(ingress);
    *req.method_mut() = Method::POST;
    req.headers_mut()
        .insert("x-compat", HeaderValue::from_static("preserved"));
    req.headers_mut()
        .insert("x-observe-upload", HeaderValue::from_static("1"));
    *req.body_mut() = body;
    tx.send(Ok(Frame::data("before failure".into())))
        .await
        .expect("initial data");
    let mut response = proxy
        .client
        .serve(req)
        .await
        .expect("failure response head")
        .into_body();
    assert!(
        response
            .frame()
            .await
            .expect("initial frame")
            .expect("initial bytes")
            .is_data()
    );
    tx.send(Err(std::io::Error::other("injected upload failure")))
        .await
        .expect("inject failure");
    drop(tx);
    assert!(
        response.collect().await.is_err(),
        "{ingress:?} -> {egress:?}: upload error was swallowed"
    );
    // Cancellation drops the observer sender. A clean origin EOS is forbidden,
    // even if the first-hop reset already made the client report an error.
    assert_ne!(
        observed_end.await,
        Ok(true),
        "{ingress:?} -> {egress:?}: origin saw clean EOF after upload failure"
    );
    proxy.close().await;
    origin.close().await;
}

#[tokio::test]
async fn all_http_version_pairs_stream_requests_and_responses() {
    for ingress in VERSIONS {
        for egress in VERSIONS {
            timeout(LIMIT, matrix(ingress, egress))
                .await
                .unwrap_or_else(|_| panic!("{ingress:?} -> {egress:?} stalled"));
        }
    }
}

/// Fresh connections isolate each failure from the previous stream's teardown.
#[tokio::test]
async fn all_http_version_pairs_reject_truncated_responses() {
    for ingress in VERSIONS {
        for egress in VERSIONS {
            for short_length in [false, true] {
                timeout(LIMIT, async {
                    let (tx, rx) = mpsc::channel(1);
                    let rx = Arc::new(parking_lot::Mutex::new(Some(rx)));
                    let origin = Hop::start(egress, service_fn(move |req: Request| {
                        assert_eq!(req.version(), egress);
                        let rx = rx.lock().take().expect("one request");
                        async move {
                            let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
                                rx.recv().await.map(|frame| (frame, rx))
                            }));
                            let mut response = Response::new(body);
                            if short_length {
                                response.headers_mut().insert("content-length", HeaderValue::from_static("100"));
                            }
                            Ok::<_, Infallible>(response)
                        }
                    })).await;
                    let upstream = origin.client.clone();
                    let relay = ResponseVersionAdapter::new(service_fn(move |mut req: Request| {
                        let upstream = upstream.clone();
                        async move {
                            adapt_request_version(&mut req, egress).expect("adapt request");
                            let response = upstream.serve(req).await.unwrap_or_else(|_| {
                                let mut response = Response::new(Body::empty());
                                *response.status_mut() = StatusCode::BAD_GATEWAY;
                                response
                            });
                            Ok::<_, Infallible>(response)
                        }
                    }));
                    let relay = Arc::new(relay);
                    let proxy = Hop::start(ingress, service_fn(move |req| {
                        let relay = relay.clone();
                        async move { Ok::<_, Infallible>(relay.serve(req).await.expect("relay response")) }
                    })).await;
                    tx.send(Ok(Frame::data("first".into()))).await.expect("first chunk");
                    let response = proxy.client.serve(handshake_request(ingress)).await;
                    let mut response = match response {
                        Ok(response) if response.status() == StatusCode::OK => Some(response.into_body()),
                        Ok(response) => {
                            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                            None
                        }
                        Err(_) => None,
                    };
                    if let Some(body) = &mut response {
                        let first = body.frame().await.expect("initial frame").expect("initial data");
                        assert_eq!(first.data_ref().expect("data").as_ref(), b"first");
                    }
                    if !short_length {
                        tx.send(Err(std::io::Error::other("injected origin failure"))).await.expect("inject error");
                    }
                    drop(tx);
                    if let Some(body) = response {
                        assert!(body.collect().await.is_err(), "{ingress:?} -> {egress:?}, short length={short_length}: truncated response succeeded");
                    }
                    proxy.close().await;
                    origin.close().await;
                }).await.unwrap_or_else(|_| panic!("{ingress:?} -> {egress:?}, short length={short_length}: stalled"));
            }
        }
    }
}
