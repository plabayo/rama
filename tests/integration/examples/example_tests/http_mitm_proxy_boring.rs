use std::{convert::Infallible, sync::Arc, time::Duration};

use super::utils;

use rama::{
    Layer,
    bytes::Bytes,
    extensions::Extensions,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Body, BodyExtractExt, Request, StatusCode, Version,
        client::EasyHttpWebClient,
        client::proxy::layer::SetProxyAuthHttpHeaderLayer,
        headers::ContentType,
        layer::compression::{CompressionLayer, predicate::Always},
        layer::retry::{ManagedPolicy, RetryLayer},
        matcher::HttpMatcher,
        server::HttpServer,
        service::client::HttpClientExt as _,
        service::web::{
            Router,
            response::{Headers, IntoResponse as _, Json},
        },
        ws::handshake::server::{WebSocketAcceptor, WebSocketMatcher},
    },
    layer::ConsumeErrLayer,
    net::{address::ProxyAddress, tls::ApplicationProtocol, tls::server::SelfSignedData},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::Level,
    tls::boring::client::TlsConnectorDataBuilder,
    tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

use serde_json::{Value, json};

#[tokio::test]
#[ignore]
async fn test_http_mitm_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63003",
                Arc::new(
                    Router::new()
                        .with_match_route(
                            "/echo",
                            HttpMatcher::custom(WebSocketMatcher::new()),
                            ConsumeErrLayer::trace(Level::DEBUG)
                                .into_layer(WebSocketAcceptor::new().into_echo_service()),
                        )
                        .with_get("/{*any}", async |req: Request| {
                            Json(json!({
                                "method": req.method().as_str(),
                                "path": req.uri().path(),
                            }))
                        }),
                ),
            )
            .await
            .unwrap();
    });

    tokio::spawn(async {
        HttpServer::http1(Executor::default())
            .listen(
                "127.0.0.1:63013",
                Arc::new((
                    ConsumeErrLayer::default(),
                    CompressionLayer::new().with_compress_predicate(Always::new()),
                ).into_layer(Router::new()
                    .with_get("/response-stream", async || {
                        Ok::<_, Infallible>(
                            (
                                Headers::single(ContentType::html_utf8()),
                                Body::from_stream(
                                    stream_fn(move |mut yielder| async move {
                                        yielder
                                            .yield_item(Bytes::from_static(
                                                b"<!DOCTYPE html>
                <html lang=en>
                <head>
                <meta charset='utf-8'>
                <title>Chunked transfer encoding test</title>
                </head>
                <body><h1>Chunked transfer encoding test</h1>",
                                            ))
                                            .await;

                                        tokio::time::sleep(Duration::from_millis(100)).await;

                                        yielder
                                            .yield_item(Bytes::from_static(
                                                b"<h5>This is a chunked response after 100 ms.</h5>",
                                            ))
                                            .await;

                                        tokio::time::sleep(Duration::from_secs(1)).await;

                                        yielder
                                            .yield_item(Bytes::from_static(
                                                b"<h5>This is a chunked response after 1 second.
                The server should not close the stream before all chunks are sent to a client.</h5></body></html>",
                                            ))
                                            .await;
                                    })
                                    .map(Ok::<_, Infallible>),
                                ),
                            )
                                .into_response(),
                        )
                    })),
            ))
            .await
            .unwrap();
    });

    let data = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .expect("self signed acceptor data")
    .with_alpn_protocols_http_auto()
    .try_with_env_key_logger()
    .expect("with env key logger")
    .build();

    let executor = Executor::default();

    let mut http_tp = HttpServer::auto(executor);
    http_tp.h2_mut().set_enable_connect_protocol();
    let tcp_service = TlsAcceptorLayer::new(data).into_layer(
        http_tp.service(Arc::new(
            Router::new()
                .with_match_route(
                    "/echo",
                    HttpMatcher::custom(WebSocketMatcher::new()),
                    ConsumeErrLayer::trace(Level::DEBUG).into_layer(
                        WebSocketAcceptor::new()
                            .with_per_message_deflate_overwrite_extensions()
                            .into_echo_service(),
                    ),
                )
                .with_get("/{*any}", async |req: Request| {
                    Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    }))
                }),
        )),
    );

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63004", Executor::default())
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let data_http1_no_alpn = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Example h1 Server Acceptor".to_owned()),
        ..Default::default()
    })
    .expect("self signed acceptor data")
    .try_with_env_key_logger()
    .expect("with env key logger")
    .build();

    let http_1_over_tls_server = HttpServer::http1(Executor::default());
    let http_1_over_tls_server_tcp = TlsAcceptorLayer::new(data_http1_no_alpn).into_layer(
        http_1_over_tls_server.service(Arc::new(Router::new().with_get("/ping", "pong"))),
    );

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63008", Executor::default())
            .await
            .unwrap_or_else(|e| {
                panic!("bind TCP Listener: secure web service (for h1 traffic): {e}")
            })
            .serve(http_1_over_tls_server_tcp)
            .await;
    });

    let runner = utils::ExampleRunner::interactive("http_mitm_proxy_boring", Some("boring"));

    let proxy_address = ProxyAddress::try_from("http://john:secret@127.0.0.1:62017").unwrap();

    // test http request proxy flow
    let result = runner
        .get("http://127.0.0.1:63003/foo/bar")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    let mut extensions = Extensions::new();
    extensions.insert(proxy_address.clone());

    // test transfer chunked encoding over MITM Proxy
    for http_version in [Version::HTTP_10, Version::HTTP_11] {
        let resp = (
            SetProxyAuthHttpHeaderLayer::default(),
            RetryLayer::new(
                ManagedPolicy::default().with_backoff(
                    ExponentialBackoff::new(
                        Duration::from_millis(100),
                        Duration::from_secs(60),
                        0.01,
                        HasherRng::default,
                    )
                    .unwrap(),
                ),
            ),
        )
            .into_layer(EasyHttpWebClient::default())
            .get("http://127.0.0.1:63013/response-stream")
            .version(http_version)
            .extension(proxy_address.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        assert!(!resp.headers().contains_key("content-length"));

        let payload = resp.try_into_string().await.unwrap();
        assert!(payload.contains("<title>Chunked transfer encoding test</title>"));
        assert!(payload.contains("This is a chunked response after 100 ms"));
        assert!(payload.contains("all chunks are sent to a client.</h5></body></html>"));
    }

    // test ws proxy flow
    let mut ws = runner
        .websocket("ws://127.0.0.1:63003/echo")
        .handshake(extensions.clone())
        .await
        .expect("ws handshake to receive");
    ws.send_message("You bastard!".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "You shazbot!",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // test ws proxy flow w/ deflate ext
    let mut ws = runner
        .websocket("ws://127.0.0.1:63003/echo")
        .with_per_message_deflate_overwrite_extensions()
        .handshake(extensions.clone())
        .await
        .expect("ws handshake to receive");
    ws.send_message("You bastard!".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "You shazbot!",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // test https request proxy flow
    let result = runner
        .get("https://127.0.0.1:63004/foo/bar")
        .extension(proxy_address.clone())
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test wss proxy flow
    let mut ws = runner
        .websocket_h2("wss://127.0.0.1:63004/echo")
        .handshake(extensions.clone())
        .await
        .expect("ws handshake to receive");
    ws.send_message("You bastard!".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "You shazbot!",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // test wss proxy flow w/ deflate ext
    let mut ws = runner
        .websocket_h2("wss://127.0.0.1:63004/echo")
        .with_per_message_deflate_overwrite_extensions()
        .handshake(extensions.clone())
        .await
        .expect("ws handshake to receive");
    ws.send_message("You bastard!".into())
        .await
        .expect("ws message to be sent");
    assert_eq!(
        "You shazbot!",
        ws.recv_message()
            .await
            .expect("echo ws message to be received")
            .into_text()
            .expect("echo ws message to be a text message")
            .as_str()
    );

    // test https request proxy flow for the different http versions
    for desired_app_protocol in [
        None,
        Some(ApplicationProtocol::HTTP_10),
        Some(ApplicationProtocol::HTTP_11),
        Some(ApplicationProtocol::HTTP_2),
    ] {
        let builder = runner
            .get("https://127.0.0.1:63008/ping")
            .extension(proxy_address.clone());

        let builder = if let Some(app_protocol) = desired_app_protocol {
            let tls_config = TlsConnectorDataBuilder::new()
                .try_with_rama_alpn_protos(&[app_protocol])
                .unwrap();
            builder.extension(tls_config)
        } else {
            builder
        };

        let pong = builder
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!("pong", pong);
    }
}
