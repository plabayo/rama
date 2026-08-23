#![expect(
    clippy::expect_used,
    reason = "integration tests use expectation messages to identify failed stages"
)]

use rama_core::{
    Layer, ServiceInput,
    extensions::ExtensionsRef,
    layer::{ArcLayer, ConsumeErrLayer},
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Version,
    layer::{
        har::{
            layer::HARExportLayer,
            recorder::{FileRecorder, Recorder},
            spec::{LogFile, WebSocketMessageType},
        },
        upgrade::mitm::HttpUpgradeMitmRelayLayer,
    },
    proto::h2::ext::Protocol,
};
use rama_http_backend::{client::http_connect, server::HttpServer};
use rama_ws::{
    Message,
    handshake::{
        client::HttpClientWebSocketExt,
        matcher::HttpWebSocketRelayServiceRequestMatcher,
        mitm::{
            WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayIoLayer,
            WebSocketRelayMessage, WebSocketRelayOutput, WebSocketRelayService,
        },
        server::WebSocketAcceptor,
    },
    layer::har::HARWebSocketLayer,
};
use std::convert::Infallible;

#[tokio::test]
async fn protocol_engines_graft_har_capture_across_relay_upgrades() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        assert_protocol_relay_file_recording(version).await;
    }
}

async fn assert_protocol_relay_file_recording(version: Version) {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(
        dir.path().to_owned(),
        format!("protocol-relay-{}", version_label(version)),
    );
    let (client_io, proxy_ingress_io) = tokio::io::duplex(16 * 1024);
    let (proxy_egress_io, server_io) = tokio::io::duplex(16 * 1024);
    let executor = Executor::default();

    let upstream =
        ConsumeErrLayer::trace_as_debug().into_layer(WebSocketAcceptor::new().into_echo_service());
    let upstream_task = tokio::spawn({
        let executor = executor.clone();
        async move {
            if version == Version::HTTP_2 {
                let mut server = HttpServer::new_h2(executor);
                server.h2_mut().set_enable_connect_protocol();
                server.serve(ServiceInput::new(server_io), upstream).await
            } else {
                HttpServer::new_http1(executor)
                    .serve(ServiceInput::new(server_io), upstream)
                    .await
            }
        }
    });

    let upstream_client = http_connect::<_, _, Body>(
        ServiceInput::new(proxy_egress_io),
        protocol_request(version),
        executor.clone(),
    )
    .await
    .expect("connect proxy to upstream protocol engine")
    .conn;
    let upstream_client = HARExportLayer::new(recorder.clone(), true).into_layer(upstream_client);
    let relay = WebSocketRelayIoLayer::new().into_layer(HARWebSocketLayer::new().into_layer(
        WebSocketRelayService::new(service_fn(transform_relay_message)),
    ));
    let proxy = HttpUpgradeMitmRelayLayer::new(
        executor.clone(),
        HttpWebSocketRelayServiceRequestMatcher::new(relay),
    )
    .into_layer(upstream_client);
    let proxy = ArcLayer::new().into_layer(ConsumeErrLayer::trace_as_debug().into_layer(proxy));
    let proxy_task = tokio::spawn({
        let executor = executor.clone();
        async move {
            if version == Version::HTTP_2 {
                let mut server = HttpServer::new_h2(executor);
                server.h2_mut().set_enable_connect_protocol();
                server
                    .serve(ServiceInput::new(proxy_ingress_io), proxy)
                    .await
            } else {
                HttpServer::new_http1(executor)
                    .serve(ServiceInput::new(proxy_ingress_io), proxy)
                    .await
            }
        }
    });

    let downstream_client = http_connect::<_, _, Body>(
        ServiceInput::new(client_io),
        protocol_request(version),
        executor,
    )
    .await
    .expect("connect downstream protocol engine to proxy")
    .conn;
    let mut client = if version == Version::HTTP_2 {
        downstream_client
            .websocket_h2("wss://example.test/socket")
            .handshake(rama_core::extensions::Extensions::new())
            .await
    } else {
        downstream_client
            .websocket("ws://example.test/socket")
            .handshake(rama_core::extensions::Extensions::new())
            .await
    }
    .expect("wire-level WebSocket handshake through proxy");
    client
        .send_message(Message::text("hello"))
        .await
        .expect("send through wire relay");
    assert_eq!(
        client.recv_message().await.expect("wire relay response"),
        Message::text("relayed-HELLO")
    );
    drop(client);

    tokio::time::timeout(std::time::Duration::from_secs(2), recorder.stop_record())
        .await
        .expect("finalize HAR recording");
    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "temporary HAR artifacts are removed");
    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(files[0].path()).await.expect("read HAR"))
            .expect("parse HAR");
    let data_messages = log.log.entries[0]
        .web_socket_messages
        .as_deref()
        .expect("Chromium WebSocket messages")
        .iter()
        .filter(|message| message.r#type != WebSocketMessageType::Error)
        .collect::<Vec<_>>();
    assert_eq!(data_messages.len(), 2);
    assert_eq!(data_messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(data_messages[0].data.as_str(), "HELLO");
    assert_eq!(data_messages[1].r#type, WebSocketMessageType::Receive);
    assert_eq!(data_messages[1].data.as_str(), "relayed-HELLO");

    proxy_task.abort();
    upstream_task.abort();
    _ = proxy_task.await;
    _ = upstream_task.await;
}

async fn transform_relay_message(
    WebSocketRelayInput {
        direction,
        message,
        extensions,
    }: WebSocketRelayInput,
) -> Result<WebSocketRelayOutput, Infallible> {
    let message = match (direction, message) {
        (WebSocketRelayDirection::Ingress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(text.as_str().to_uppercase().into())
        }
        (WebSocketRelayDirection::Egress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(format!("relayed-{text}").into())
        }
        (_, message) => message,
    };
    Ok(WebSocketRelayOutput {
        messages: vec![message],
        extensions,
    })
}

fn protocol_request(version: Version) -> Request {
    let mut request = Request::new(Body::empty());
    *request.version_mut() = version;
    if version == Version::HTTP_2 {
        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = "https://example.test/socket".parse().expect("HTTP/2 URI");
        request
            .extensions()
            .insert(Protocol::from_static("websocket"));
    } else {
        *request.method_mut() = Method::GET;
        *request.uri_mut() = "ws://example.test/socket".parse().expect("HTTP/1 URI");
    }
    request
}

fn version_label(version: Version) -> &'static str {
    if version == Version::HTTP_2 {
        "h2"
    } else {
        "h1"
    }
}
