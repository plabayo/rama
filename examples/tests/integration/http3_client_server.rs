//! HTTP/3 executable and public API end-to-end coverage.
use super::utils;
use rama::{
    bytes::Bytes,
    crypto::pem::PemEncode as _,
    error::BoxError,
    extensions::{Egress, Extensions, ExtensionsRef as _},
    futures::{StreamExt as _, stream},
    graceful::WeakScope,
    http::{
        Body, HeaderMap, Method, Request, Response, Version,
        body::{Frame, util::BodyExt as _},
        client::EasyHttpWebClient,
        core::h3::{client as h3_client, connection::Config as H3Config},
        server::HttpServer,
        service::client::HttpClientExt as _,
    },
    layer::MapInputLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{
        ClientConfig, Endpoint, ServerConfig, TransportConfig, client::SharedQuicEndpoint,
        tls::TlsOptions,
    },
    service::service_fn,
    tls::{
        client::{NegotiatedTlsParameters, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::fs::tempdir,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{fs, process::Command, spawn, time::timeout};

#[cfg(all(
    feature = "rustls",
    feature = "boring",
    any(feature = "ring", feature = "aws-lc")
))]
use {
    parking_lot::Mutex,
    rama::{
        Layer as _,
        net::extensions::StreamTransformed,
        quic::tls::BoringTlsProvider,
        tcp::server::TcpListener,
        tls::rustls::{client::RustlsClientConfigExt as _, server::TlsAcceptorLayer},
    },
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http3_client_server() {
    utils::init_tracing();
    let directory = tempdir().unwrap();
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    fs::write(&cert, auth.cert_chain[0].to_pem()).await.unwrap();
    fs::write(&key, auth.private_key.to_pem()).await.unwrap();
    let mut server = utils::ExampleRunner::capturing(
        utils::example!("http3_client_server"),
        [
            "server",
            "--listen",
            "127.0.0.1:0",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ],
    );
    let line = server
        .wait_for_line("HTTP/3 listening on ", Duration::from_secs(30))
        .await;
    let address: SocketAddr = line
        .split("HTTP/3 listening on ")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let url = format!("https://localhost:{}/", address.port());
    for body in [None, Some("streamed HTTP/3 echo")] {
        let mut command = Command::from(utils::ExampleRunner::command(utils::example!(
            "http3_client_server"
        )));
        command
            .kill_on_drop(true)
            .env("RUST_LOG", "http3_client_server=info")
            .args(["client", "--ca"])
            .arg(&cert)
            .args(["--url", &url, "--count", "3"]);
        if let Some(body) = body {
            command.args(["--body", body]);
        }
        let output = timeout(Duration::from_secs(30), command.output())
            .await
            .unwrap()
            .unwrap();
        let output_text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "{output_text}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output_text.matches("HTTP/3 response").count(),
            3,
            "{output_text}"
        );
        assert_eq!(
            output_text
                .matches(body.unwrap_or("hello over HTTP/3"))
                .count(),
            3
        );
    }
    // Keep an accepted echo response open across Ctrl-C. GOAWAY must reach the
    // client while QUIC remains alive to deliver and acknowledge its last bytes.
    let endpoint = Endpoint::build(WeakScope::detached())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors(auth.cert_chain.clone())
        .unwrap()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    let connection = endpoint
        .connect_with(config, address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut client, driver) =
        h3_client::handshake::<Body, _>(connection, H3Config::default(), WeakScope::detached())
            .unwrap();
    let driver = spawn(driver.run());
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let body = Body::from_frame_stream(stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|frame| (frame, receiver))
    }));
    sender
        .send(Ok::<_, Infallible>(Frame::data(Bytes::from_static(
            b"before shutdown",
        ))))
        .await
        .unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(body)
        .unwrap();
    let mut response = timeout(REQUEST_TIMEOUT, client.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        timeout(REQUEST_TIMEOUT, response.body_mut().frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "before shutdown"
    );
    let (status, ()) = tokio::join!(server.interrupt_within(Duration::from_secs(20)), async {
        timeout(REQUEST_TIMEOUT, client.closed_or_draining())
            .await
            .unwrap();
        assert!(client.is_draining(), "HTTP/3 drains before QUIC closes");
        sender
            .send(Ok(Frame::data(Bytes::from_static(b"after shutdown"))))
            .await
            .unwrap();
        drop(sender);
        let received = timeout(REQUEST_TIMEOUT, response.into_body().collect())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.to_bytes(), "after shutdown");
    });
    assert!(status.success(), "{}", server.said());
    drop(client);
    endpoint.shutdown().await;
    let _result = driver.await.unwrap();
    assert_eq!(
        server.said().matches("accepted HTTP/3 connection").count(),
        3,
        "each executable client reuses one connection; a third drains during Ctrl-C"
    );
    assert!(server.said().contains("HTTP/3 shutdown joined"));
}

#[tokio::test]
#[ignore = "spawns example processes"]
async fn public_builders_reuse_h3_with_common_bodies_and_trailers() -> Result<(), BoxError> {
    for capture_chain in [false, true] {
        timeout(Duration::from_secs(20), async {
            let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
            let tls = TlsClientConfig::new()
                .try_with_server_trust_anchors(auth.cert_chain.clone())?
                .with_store_server_cert_chain(capture_chain);
            let server_tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let server = HttpServer::new_http3(WeakScope::detached());
            let mut transport = TransportConfig::default();
            server.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())?;
            config.set_transport_config(Arc::new(transport));
            let endpoint = Endpoint::build(WeakScope::detached())
                .with_server_config(config)
                .bind_address(SocketAddress::local_ipv4(0))
                .await?;
            let address = endpoint.local_addr()?;
            let accepted = Arc::new(AtomicUsize::new(0));
            let task = spawn({
                let endpoint = endpoint.clone();
                let accepted = accepted.clone();
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let server = server.clone();
                        spawn(async move {
                            if let Ok(connection) = incoming.await {
                                let _result = server
                                    .serve(
                                        connection,
                                        service_fn(async |request: Request| {
                                            assert_eq!(request.version(), Version::HTTP_3);
                                            Ok::<_, Infallible>(Response::new(request.into_body()))
                                        }),
                                    )
                                    .await;
                            }
                        });
                    }
                }
            });
            let client_endpoint = Endpoint::build(WeakScope::detached())
                .bind_address(SocketAddress::local_ipv4(0))
                .await?;
            let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
                .with_default_tcp_connector()
                .with_custom_quic_connector(SharedQuicEndpoint::supplied(
                    client_endpoint.clone(),
                    WeakScope::detached(),
                ))
                .with_default_dns_connector()
                .with_default_proxy_support()
                .with_default_tls_support(tls.clone())
                .with_default_http_connector()
                .with_default_connection_pool()
                .build_client()
                .with_jit_layer(MapInputLayer::new(move |request: Request| {
                    let egress = request
                        .extensions()
                        .get_ref::<Egress<Extensions>>()
                        .unwrap();
                    let parameters = egress.0.get_ref::<NegotiatedTlsParameters>().unwrap();
                    assert_eq!(
                        parameters
                            .peer_certificate_chain
                            .as_ref()
                            .is_some_and(|chain| !chain.is_empty()),
                        capture_chain
                    );
                    request
                }));
            for _ in 0..3 {
                let mut trailers = HeaderMap::new();
                trailers.insert("x-complete", "yes".parse()?);
                let body = Body::from_frame_stream(stream::iter([
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"common body"))),
                    Ok(Frame::trailers(trailers)),
                ]));
                let response = client
                    .post(format!("https://localhost:{}/echo", address.port()))
                    .version(Version::HTTP_3)
                    .body(body)
                    .send_with_timeout(REQUEST_TIMEOUT)
                    .await?;
                assert_eq!(response.version(), Version::HTTP_3);
                let received = response.into_body().collect().await?;
                assert_eq!(
                    received
                        .trailers()
                        .and_then(|h| h.get("x-complete"))
                        .map(|h| h.as_bytes()),
                    Some(b"yes".as_slice())
                );
                assert_eq!(received.to_bytes(), "common body");
            }
            // Dropping a streaming response cancels only that request. A second request
            // must still complete over the same multiplexed connection.
            let body = Body::from_frame_stream(
                stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                    b"first chunk",
                )))])
                .chain(stream::pending()),
            );
            let mut response = client
                .post(format!("https://localhost:{}/cancel", address.port()))
                .version(Version::HTTP_3)
                .body(body)
                .send_with_timeout(REQUEST_TIMEOUT)
                .await?;
            let frame = response.body_mut().frame().await.unwrap()?;
            assert_eq!(frame.data_ref().unwrap().as_ref(), b"first chunk");
            drop(response);
            let response = client
                .post(format!("https://localhost:{}/after-cancel", address.port()))
                .version(Version::HTTP_3)
                .body("connection survived cancellation")
                .send_with_timeout(REQUEST_TIMEOUT)
                .await?;
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                "connection survived cancellation"
            );
            assert_eq!(accepted.load(Ordering::SeqCst), 1);
            drop(client);
            client_endpoint.close(0u32, b"done");
            endpoint.close(0u32, b"done");
            task.abort();
            tokio::join!(client_endpoint.shutdown(), endpoint.shutdown());
            Ok::<_, BoxError>(())
        })
        .await??;
    }
    Ok(())
}

#[cfg(all(
    feature = "rustls",
    feature = "boring",
    any(feature = "ring", feature = "aws-lc")
))]
#[tokio::test]
#[ignore = "opens real sockets"]
async fn http_client_preserves_explicit_tls_provider() -> Result<(), BoxError> {
    // In a dual-backend build each leg keeps the backend it was given: TCP rustls, QUIC
    // boringssl. Only rustls runs the counting hook, so HTTP/3 must leave the count alone.
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
    let trust_anchors = auth.cert_chain.clone();
    let tcp_auth = ServerAuthData::new(auth.cert_chain.clone(), auth.private_key.clone_key());
    let scope = WeakScope::detached();

    let tcp_tls = TlsServerConfig::new()
        .with_server_auth(tcp_auth)
        .with_alpn([ApplicationProtocol::HTTP_2].into_iter().collect());
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), scope.clone()).await?;
    let tcp_port = listener.local_addr()?.port();
    let tcp_task = spawn(async move {
        listener
            .serve(TlsAcceptorLayer::new(tcp_tls).into_layer(
                HttpServer::auto(WeakScope::detached()).service(service_fn(
                    async |request: Request| {
                        Ok::<_, Infallible>(Response::new(Body::from(format!(
                            "{:?}",
                            request.version()
                        ))))
                    },
                )),
            ))
            .await;
    });

    let h3_server = HttpServer::new_http3(scope.clone());
    let mut transport = TransportConfig::default();
    h3_server.http3().configure_transport(&mut transport)?;
    let h3_tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut h3_config = ServerConfig::try_from_rama_tls(&h3_tls, TlsOptions::default())?;
    h3_config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(scope.clone())
        .with_server_config(h3_config)
        .bind_address(SocketAddress::local_ipv4(0))
        .await?;
    let h3_port = endpoint.local_addr()?.port();
    let h3_task = spawn(endpoint.clone().serve(
        scope,
        h3_server.service(service_fn(async |request: Request| {
            Ok::<_, Infallible>(Response::new(Body::from(format!(
                "{:?}",
                request.version()
            ))))
        })),
    ));

    let called = Arc::new(AtomicUsize::new(0));
    let tls = TlsClientConfig::default_http()
        .try_with_server_trust_anchors(trust_anchors)?
        .with_modify_rustls_config({
            let called = called.clone();
            move |config| {
                called.fetch_add(1, Ordering::Relaxed);
                Ok(config)
            }
        });
    let transformed = Arc::new(Mutex::new(Vec::new()));
    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_default_proxy_support()
        .with_tls_support_using_rustls(tls)
        .with_quic_tls_provider(Arc::new(BoringTlsProvider::new()))
        .with_default_http_connector::<Body>()
        .with_default_connection_pool()
        .build_client()
        .with_jit_layer(MapInputLayer::new({
            let transformed = transformed.clone();
            move |request: Request| {
                if let Some(egress) = request.extensions().get_ref::<Egress<Extensions>>() {
                    *transformed.lock() = egress
                        .0
                        .iter_ref::<StreamTransformed>()
                        .map(|marker| marker.by)
                        .collect();
                }
                request
            }
        }));

    let response = client
        .get(format!("https://localhost:{tcp_port}/"))
        .version(Version::HTTP_2)
        .send_with_timeout(REQUEST_TIMEOUT)
        .await?;
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "HTTP/2.0");
    assert_eq!(called.load(Ordering::Relaxed), 1);
    let tcp_transformed = transformed.lock().clone();
    assert!(
        tcp_transformed.contains(&"rama-tls-rustls::TlsConnector"),
        "{tcp_transformed:?}"
    );

    let response = client
        .get(format!("https://localhost:{h3_port}/"))
        .version(Version::HTTP_3)
        .send_with_timeout(REQUEST_TIMEOUT)
        .await?;
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "HTTP/3.0");
    assert_eq!(called.load(Ordering::Relaxed), 1);

    drop(client);
    endpoint.close(0u32, b"done");
    tcp_task.abort();
    h3_task.abort();
    endpoint.shutdown().await;
    Ok(())
}
