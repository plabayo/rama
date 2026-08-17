use parking_lot::Mutex;
use rama_core::{
    Layer, Service, ServiceInput, bytes::Bytes, error::BoxError, extensions::ExtensionsRef,
    io::BridgeIo, rt::Executor, service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    body::util::BodyExt as _,
    headers::{self, HeaderMapExt as _},
    layer::{
        har::{
            layer::HARExportLayer,
            recorder::{
                FileRecorder, HarFilePath, Recorder, WebSocketCapture, WebSocketCaptureRecorder,
            },
            spec::{LogFile, WebSocketMessage, WebSocketMessageType},
        },
        upgrade::mitm::HttpUpgradeMitmRelayLayer,
    },
    proto::h2::ext::Protocol,
};
use rama_ws::{
    AsyncWebSocket, Message,
    handshake::matcher::HttpWebSocketRelayServiceRequestMatcher,
    handshake::mitm::{
        WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayIoService,
        WebSocketRelayMessage, WebSocketRelayOutput, WebSocketRelayService,
    },
    layer::har::HARWebSocketLayer,
    protocol::Role,
};
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct CaptureState {
    messages: Mutex<Vec<WebSocketMessage>>,
    closes: AtomicUsize,
}

struct TestRecorder(Arc<CaptureState>);

impl WebSocketCaptureRecorder for TestRecorder {
    async fn record(&self, message: WebSocketMessage) -> Result<(), BoxError> {
        self.0.messages.lock().push(message);
        Ok(())
    }
}

async fn transform_relay_message(
    input: WebSocketRelayInput,
) -> Result<WebSocketRelayOutput, Infallible> {
    let WebSocketRelayInput {
        direction,
        message,
        extensions,
    } = input;
    let messages = match (direction, message) {
        (WebSocketRelayDirection::Ingress, WebSocketRelayMessage::Text(text)) if text == "drop" => {
            Vec::new()
        }
        (WebSocketRelayDirection::Ingress, WebSocketRelayMessage::Text(text)) => {
            vec![WebSocketRelayMessage::Text(
                text.as_str().to_uppercase().into(),
            )]
        }
        (WebSocketRelayDirection::Egress, WebSocketRelayMessage::Text(text)) => {
            vec![WebSocketRelayMessage::Text(
                format!("relayed-{text}").into(),
            )]
        }
        (_, message) => vec![message],
    };
    Ok(WebSocketRelayOutput {
        messages,
        extensions,
    })
}

#[tokio::test]
async fn relay_har_records_only_final_forwarded_messages() {
    let state = Arc::new(CaptureState::default());
    let capture = WebSocketCapture::new(TestRecorder(state.clone()), {
        let state = state.clone();
        move || {
            state.closes.fetch_add(1, Ordering::AcqRel);
        }
    });

    let (client_io, ingress_io) = tokio::io::duplex(16 * 1024);
    let (egress_io, server_io) = tokio::io::duplex(16 * 1024);
    let ingress_io = ServiceInput::new(ingress_io);
    let egress_io = ServiceInput::new(egress_io);
    egress_io.extensions().insert(capture);

    let middleware = service_fn(transform_relay_message);
    let relay = WebSocketRelayIoService::new(
        HARWebSocketLayer::new().into_layer(WebSocketRelayService::new(middleware)),
    );
    let relay_task = tokio::spawn(async move {
        relay
            .serve(BridgeIo(ingress_io, egress_io))
            .await
            .expect("relay is infallible");
    });

    let mut client =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;
    let mut server =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None).await;

    client
        .send_message(Message::text("hello"))
        .await
        .expect("client send");
    assert_eq!(
        server.recv_message().await.expect("server receive"),
        Message::text("HELLO")
    );

    client
        .send_message(Message::text("drop"))
        .await
        .expect("client send dropped message");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), server.recv_message())
            .await
            .is_err(),
        "dropped relay output must not reach the peer"
    );

    server
        .send_message(Message::text("world"))
        .await
        .expect("server send");
    assert_eq!(
        client.recv_message().await.expect("client receive"),
        Message::text("relayed-world")
    );

    drop(client);
    drop(server);
    tokio::time::timeout(std::time::Duration::from_secs(2), relay_task)
        .await
        .expect("relay stops after both peers disconnect")
        .expect("relay task succeeds");

    let messages = state.messages.lock();
    let data_messages = messages
        .iter()
        .filter(|message| message.r#type != WebSocketMessageType::Error)
        .collect::<Vec<_>>();
    assert_eq!(data_messages.len(), 2);
    assert_eq!(data_messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(data_messages[0].data.as_str(), "HELLO");
    assert_eq!(data_messages[1].r#type, WebSocketMessageType::Receive);
    assert_eq!(data_messages[1].data.as_str(), "relayed-world");
    drop(messages);
    assert_eq!(state.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn relay_har_flows_through_http_upgrade_into_file_recorder() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        assert_upgrade_relay_file_recording(version).await;
    }
}

#[expect(
    clippy::expect_used,
    reason = "test helper uses expectation messages to identify the failed relay stage"
)]
async fn assert_upgrade_relay_file_recording(version: Version) {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(
        dir.path().to_owned(),
        format!(
            "relay-{}",
            if version == Version::HTTP_2 {
                "h2"
            } else {
                "h1"
            }
        ),
    );

    let (client_io, ingress_io) = tokio::io::duplex(16 * 1024);
    let (egress_io, server_io) = tokio::io::duplex(16 * 1024);
    let (ingress_pending, ingress_upgrade) = rama_http::io::upgrade::pending();
    ingress_pending.fulfill(rama_http::io::upgrade::Upgraded::new(
        ServiceInput::new(ingress_io),
        Bytes::new(),
    ));
    let (egress_pending, egress_upgrade) = rama_http::io::upgrade::pending();
    egress_pending.fulfill(rama_http::io::upgrade::Upgraded::new(
        ServiceInput::new(egress_io),
        Bytes::new(),
    ));
    let egress_upgrade = Arc::new(Mutex::new(Some(egress_upgrade)));

    let upstream = service_fn(move |request: Request| {
        let egress_upgrade = egress_upgrade.clone();
        async move {
            assert_eq!(request.version(), version);
            let mut response = Response::new(Body::empty());
            *response.version_mut() = version;
            *response.status_mut() = if version == Version::HTTP_2 {
                StatusCode::OK
            } else {
                StatusCode::SWITCHING_PROTOCOLS
            };
            if version != Version::HTTP_2 {
                response
                    .headers_mut()
                    .typed_insert(headers::Upgrade::websocket());
                response
                    .headers_mut()
                    .typed_insert(headers::Connection::upgrade());
            }
            response
                .extensions()
                .insert(egress_upgrade.lock().take().expect("one upstream upgrade"));
            Ok::<_, BoxError>(response)
        }
    });
    let upstream = HARExportLayer::new(recorder.clone(), true).into_layer(upstream);
    let relay = WebSocketRelayIoService::new(HARWebSocketLayer::new().into_layer(
        WebSocketRelayService::new(service_fn(transform_relay_message)),
    ));
    let service = HttpUpgradeMitmRelayLayer::new(
        Executor::default(),
        HttpWebSocketRelayServiceRequestMatcher::new(relay),
    )
    .into_layer(upstream);

    let mut request = Request::new(Body::empty());
    *request.version_mut() = version;
    *request.uri_mut() = "ws://example.test/socket".parse().expect("request URI");
    if version == Version::HTTP_2 {
        *request.method_mut() = Method::CONNECT;
        request
            .extensions()
            .insert(Protocol::from_static("websocket"));
    } else {
        *request.method_mut() = Method::GET;
        request
            .headers_mut()
            .typed_insert(headers::Upgrade::websocket());
        request
            .headers_mut()
            .typed_insert(headers::Connection::upgrade());
    }
    request.extensions().insert(ingress_upgrade);

    let response = service.serve(request).await.expect("HTTP upgrade relay");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path on upgrade response")
        .to_path_buf();
    response
        .into_body()
        .collect()
        .await
        .expect("consume upgrade response body");

    let mut client =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;
    let mut server =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None).await;
    client
        .send_message(Message::text("hello"))
        .await
        .expect("client send");
    assert_eq!(
        server.recv_message().await.expect("server receive"),
        Message::text("HELLO")
    );
    server
        .send_message(Message::text("world"))
        .await
        .expect("server send");
    assert_eq!(
        client.recv_message().await.expect("client receive"),
        Message::text("relayed-world")
    );
    drop(client);
    drop(server);

    tokio::time::timeout(std::time::Duration::from_secs(2), recorder.stop_record())
        .await
        .expect("finalize relay HAR");
    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let messages = log.log.entries[0]
        .web_socket_messages
        .as_ref()
        .expect("Chromium WebSocket messages");
    let data_messages = messages
        .iter()
        .filter(|message| message.r#type != WebSocketMessageType::Error)
        .collect::<Vec<_>>();
    assert_eq!(data_messages.len(), 2);
    assert_eq!(data_messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(data_messages[0].data.as_str(), "HELLO");
    assert_eq!(data_messages[1].r#type, WebSocketMessageType::Receive);
    assert_eq!(data_messages[1].data.as_str(), "relayed-world");

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "temporary relay artifacts are removed");
}
