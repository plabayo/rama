//! HTTP/3 executable and public API end-to-end coverage.
use super::utils;
use rama::{
    Service, ServiceInput,
    crypto::pem::PemEncode as _,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    futures::StreamExt as _,
    http::{
        Body, HeaderMap, Request, Response, Version,
        body::{Frame, util::BodyExt as _},
        client::{EasyHttpConnectorBuilder, Http3Connector},
        server::HttpServer,
    },
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

#[tokio::test]
#[ignore]
async fn test_http3_client_server() {
    utils::init_tracing();
    let directory = rama::utils::fs::tempdir().unwrap();
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, auth.cert_chain[0].to_pem()).unwrap();
    std::fs::write(&key, auth.private_key.to_pem()).unwrap();
    let mut server = utils::ExampleRunner::capturing(
        "http3_client_server",
        None,
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
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_http3_client_server"));
        command
            .kill_on_drop(true)
            .env("RUST_LOG", "http3_client_server=info")
            .args(["client", "--ca"])
            .arg(&cert)
            .args(["--url", &url, "--count", "3"]);
        if let Some(body) = body {
            command.args(["--body", body]);
        }
        let output = tokio::time::timeout(Duration::from_secs(30), command.output())
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
    assert!(
        server
            .interrupt_within(Duration::from_secs(20))
            .await
            .success(),
        "{}",
        server.said()
    );
    assert_eq!(
        server.said().matches("accepted HTTP/3 connection").count(),
        2,
        "each executable client reuses one connection"
    );
    assert!(server.said().contains("HTTP/3 shutdown joined"));
}

#[tokio::test]
#[ignore]
async fn public_builders_reuse_h3_with_common_bodies_and_trailers() -> Result<(), BoxError> {
    for capture_chain in [false, true] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
            let tls = TlsClientConfig::new()
                .try_with_server_trust_anchors(auth.cert_chain.clone())?
                .with_store_server_cert_chain(capture_chain);
            let server_tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([b"h3".as_slice().into()].into_iter().collect());
            let server = HttpServer::new_http3(Executor::new());
            let mut transport = TransportConfig::default();
            server.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())?;
            config.set_transport_config(Arc::new(transport));
            let endpoint = Endpoint::build(Executor::new())
                .with_server_config(config)
                .bind_address(rama::net::address::SocketAddress::local_ipv4(0))
                .await?;
            let address = endpoint.local_addr()?;
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let task = tokio::spawn({
                let endpoint = endpoint.clone();
                let accepted = accepted.clone();
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = incoming.await {
                                let _result = server
                                    .serve(
                                        ServiceInput {
                                            input: connection,
                                            extensions: Extensions::new(),
                                        },
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
            let client_endpoint = Endpoint::build(Executor::new())
                .bind_address(rama::net::address::SocketAddress::local_ipv4(0))
                .await?;
            let client = EasyHttpConnectorBuilder::new()
                .with_http3_connector(
                    Http3Connector::<Body>::builder(Executor::new())
                        .with_endpoint(client_endpoint.clone())
                        .with_tls_config(tls)
                        .build()
                        .await?,
                )
                .with_default_fallback_connector()?
                .build_client()
                .with_jit_layer(rama::layer::MapInputLayer::new(move |request: Request| {
                    let egress = request
                        .extensions()
                        .get_ref::<rama::extensions::Egress<Extensions>>()
                        .unwrap();
                    let parameters = egress
                        .0
                        .get_ref::<rama::tls::client::NegotiatedTlsParameters>()
                        .unwrap();
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
                let body = Body::from_frame_stream(rama::futures::stream::iter([
                    Ok::<_, Infallible>(Frame::data(rama::bytes::Bytes::from_static(
                        b"common body",
                    ))),
                    Ok(Frame::trailers(trailers)),
                ]));
                let request = Request::builder()
                    .method(rama::http::Method::POST)
                    .version(Version::HTTP_3)
                    .uri(format!("https://localhost:{}/echo", address.port()))
                    .body(body)?;
                let response = client.serve(request).await?;
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
                rama::futures::stream::iter([Ok::<_, Infallible>(Frame::data(
                    rama::bytes::Bytes::from_static(b"first chunk"),
                ))])
                .chain(rama::futures::stream::pending()),
            );
            let request = Request::builder()
                .method(rama::http::Method::POST)
                .version(Version::HTTP_3)
                .uri(format!("https://localhost:{}/cancel", address.port()))
                .body(body)?;
            let mut response = client.serve(request).await?;
            let frame = response.body_mut().frame().await.unwrap()?;
            assert_eq!(frame.data_ref().unwrap().as_ref(), b"first chunk");
            drop(response);
            let request = Request::builder()
                .method(rama::http::Method::POST)
                .version(Version::HTTP_3)
                .uri(format!("https://localhost:{}/after-cancel", address.port()))
                .body(Body::from("connection survived cancellation"))?;
            let response = client.serve(request).await?;
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                "connection survived cancellation"
            );
            assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
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

#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
#[tokio::test]
#[ignore]
async fn default_tcp_fallback_preserves_explicit_tls_provider() -> Result<(), BoxError> {
    use rama::{
        error::BoxErrorExt as _,
        tls::{TlsBackend, rustls::client::RustlsClientConfigExt as _},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A native policy hook must remain active on TCP even in a dual-provider build.
    // Fail during configuration so this test needs no certificate or remote peer.
    let called = Arc::new(AtomicUsize::new(0));
    let tls = TlsClientConfig::default_http().with_modify_rustls_config({
        let called = called.clone();
        move |_| {
            called.fetch_add(1, Ordering::Relaxed);
            Err(BoxError::from_static_str(
                "intentional native TLS policy failure",
            ))
        }
    });
    let listener =
        tokio::net::TcpListener::bind(rama::net::address::SocketAddress::local_ipv4(0).into_std())
            .await?;
    let address = listener.local_addr()?;
    let connector = Http3Connector::<Body>::builder(Executor::new())
        .with_tls_backend(TlsBackend::Rustls)
        .with_tls_config(tls)
        .build()
        .await?;
    let client = EasyHttpConnectorBuilder::new()
        .with_http3_connector(connector)
        .with_default_fallback_connector()?
        .build_client();
    let request = Request::builder()
        .uri(format!("https://{address}/"))
        .body(Body::empty())?;
    tokio::time::timeout(Duration::from_secs(5), client.serve(request))
        .await?
        .unwrap_err();
    assert_eq!(called.load(Ordering::Relaxed), 1);
    Ok(())
}
