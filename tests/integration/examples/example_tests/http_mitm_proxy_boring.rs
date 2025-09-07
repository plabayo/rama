use super::utils;
use rama::{
    Context, Layer,
    http::{
        BodyExtractExt, Request,
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{Router, response::Json},
        ws::handshake::server::{WebSocketAcceptor, WebSocketMatcher},
    },
    layer::ConsumeErrLayer,
    net::{address::ProxyAddress, tls::server::SelfSignedData},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::Level,
    tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
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
                Router::new()
                    .match_route(
                        "/echo",
                        HttpMatcher::custom(WebSocketMatcher::new()),
                        ConsumeErrLayer::trace(Level::DEBUG)
                            .into_layer(WebSocketAcceptor::new().into_echo_service()),
                    )
                    .get("/{*any}", async |req: Request| {
                        Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path(),
                        }))
                    }),
            )
            .await
            .unwrap();
    });

    let data = TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .expect("self signed acceptor data")
    .with_alpn_protocols_http_auto()
    .with_env_key_logger()
    .expect("with env key logger")
    .build();

    let executor = Executor::default();

    let mut http_tp = HttpServer::auto(executor);
    http_tp.h2_mut().enable_connect_protocol();
    let tcp_service = TlsAcceptorLayer::new(data).into_layer(
        http_tp.service(
            Router::new()
                .match_route(
                    "/echo",
                    HttpMatcher::custom(WebSocketMatcher::new()),
                    ConsumeErrLayer::trace(Level::DEBUG).into_layer(
                        WebSocketAcceptor::new()
                            .with_per_message_deflate_overwrite_extensions()
                            .into_echo_service(),
                    ),
                )
                .get("/{*any}", async |req: Request| {
                    Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    }))
                }),
        ),
    );

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63004")
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let runner = utils::ExampleRunner::interactive("http_mitm_proxy_boring", Some("boring"));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("http://john:secret@127.0.0.1:62017").unwrap());

    // test http request proxy flow
    let result = runner
        .get("http://127.0.0.1:63003/foo/bar")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test ws proxy flow
    let mut ws = runner
        .websocket("ws://127.0.0.1:63003/echo")
        .handshake(ctx.clone())
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
        .handshake(ctx.clone())
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
        .send(ctx.clone())
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
        .handshake(ctx.clone())
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
        .handshake(ctx.clone())
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
}
