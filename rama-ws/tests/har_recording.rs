use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::futures::SinkExt;
use rama_core::service::service_fn;
use rama_core::{Layer, ServiceInput};
use rama_http::headers::{self, HeaderMapExt};
use rama_http::layer::har::layer::HARExportLayer;
use rama_http::layer::har::recorder::{FileRecorder, HarFilePath, Recorder};
use rama_http::layer::har::spec::{LogFile, WebSocketMessageOpcode, WebSocketMessageType};
use rama_http::{Body, Response, StatusCode, Version};
use rama_ws::handshake::client::HttpClientWebSocketExt;
use rama_ws::protocol::{Message, Role};
use rama_ws::runtime::AsyncWebSocket;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn websocket_messages_flow_from_upgrade_into_file_recorder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-live".to_owned());

    let transport = service_fn(async |request: rama_http::Request| {
        let key = request
            .headers()
            .typed_get::<headers::SecWebSocketKey>()
            .expect("handshake key");
        let accept = headers::SecWebSocketAccept::try_from(key).expect("accept key");
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (pending, on_upgrade) = rama_http::io::upgrade::pending();
        pending.fulfill(rama_http::io::upgrade::Upgraded::new(
            ServiceInput::new(client_io),
            Bytes::new(),
        ));

        tokio::spawn(async move {
            let mut server =
                AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None)
                    .await;
            assert_eq!(
                server.recv_message().await.expect("server receive"),
                Message::text("from-client")
            );
            server
                .send_message(Message::binary(vec![0, 1, 2, 0xff]))
                .await
                .expect("server send");
            server
                .send_message(Message::Ping(vec![7, 8].into()))
                .await
                .expect("server ping");
            assert_eq!(
                server.recv_message().await.expect("automatic pong"),
                Message::Pong(vec![7, 8].into()),
            );

            // Reserved opcode 3 is a protocol error and exercises Chromium's
            // `{type:"error", opcode:-1}` record shape.
            let mut raw = server.into_inner();
            raw.write_all(&[0x83, 0x00])
                .await
                .expect("write malformed frame");
        });

        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.version_mut() = Version::HTTP_11;
        response
            .headers_mut()
            .typed_insert(headers::Upgrade::websocket());
        response
            .headers_mut()
            .typed_insert(headers::Connection::upgrade());
        response.headers_mut().typed_insert(accept);
        response.extensions().insert(on_upgrade);
        Ok::<_, BoxError>(response)
    });
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(transport);

    let mut client = service
        .websocket("ws://example.test/socket")
        .handshake(Extensions::new())
        .await
        .expect("WebSocket handshake");
    let path = client
        .response()
        .extensions
        .get_ref::<HarFilePath>()
        .expect("HAR path on handshake response")
        .to_path_buf();

    client
        .send_message(Message::text("from-client"))
        .await
        .expect("client send");
    assert_eq!(
        client.recv_message().await.expect("client receive"),
        Message::binary(vec![0, 1, 2, 0xff])
    );
    assert_eq!(
        client.recv_message().await.expect("client ping"),
        Message::Ping(vec![7, 8].into()),
    );
    client.flush().await.expect("flush automatic pong");
    client
        .recv_message()
        .await
        .expect_err("reserved opcode must fail");
    drop(client);

    recorder.stop_record().await;
    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let entry = log.log.entries.first().expect("handshake entry");
    let messages = entry
        .web_socket_messages
        .as_ref()
        .expect("WebSocket extension");
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(messages[0].opcode, WebSocketMessageOpcode::TEXT);
    assert_eq!(messages[0].data.as_str(), "from-client");
    assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
    assert_eq!(messages[1].opcode, WebSocketMessageOpcode::BINARY);
    assert_eq!(messages[1].data.as_str(), "AAEC/w==");
    assert_eq!(messages[2].r#type, WebSocketMessageType::Error);
    assert_eq!(messages[2].opcode, WebSocketMessageOpcode::ERROR);
    assert!(
        messages
            .iter()
            .all(|message| message.time > 1_700_000_000.0)
    );

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "WebSocket artifacts must be removed");
}

#[tokio::test]
async fn stop_finalizes_har_without_closing_live_web_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-stop".to_owned());

    let transport = service_fn(async |request: rama_http::Request| {
        let key = request
            .headers()
            .typed_get::<headers::SecWebSocketKey>()
            .expect("handshake key");
        let accept = headers::SecWebSocketAccept::try_from(key).expect("accept key");
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (pending, on_upgrade) = rama_http::io::upgrade::pending();
        pending.fulfill(rama_http::io::upgrade::Upgraded::new(
            ServiceInput::new(client_io),
            Bytes::new(),
        ));

        tokio::spawn(async move {
            let mut server =
                AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None)
                    .await;
            for expected in ["before-stop", "after-stop"] {
                assert_eq!(
                    server.recv_message().await.expect("server receive"),
                    Message::text(expected),
                );
                server
                    .send_message(Message::text(format!("echo-{expected}")))
                    .await
                    .expect("server send");
            }
        });

        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.version_mut() = Version::HTTP_11;
        response
            .headers_mut()
            .typed_insert(headers::Upgrade::websocket());
        response
            .headers_mut()
            .typed_insert(headers::Connection::upgrade());
        response.headers_mut().typed_insert(accept);
        response.extensions().insert(on_upgrade);
        Ok::<_, BoxError>(response)
    });
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(transport);
    let mut client = service
        .websocket("ws://example.test/live")
        .handshake(Extensions::new())
        .await
        .expect("WebSocket handshake");
    let path = client
        .response()
        .extensions
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();

    client
        .send_message(Message::text("before-stop"))
        .await
        .expect("client send before stop");
    assert_eq!(
        client.recv_message().await.expect("echo before stop"),
        Message::text("echo-before-stop"),
    );

    tokio::time::timeout(Duration::from_secs(2), recorder.stop_record())
        .await
        .expect("stop must not await the live WebSocket");
    let log: LogFile = serde_json::from_slice(&tokio::fs::read(&path).await.expect("read HAR"))
        .expect("parse HAR");
    let entry = &log.log.entries[0];
    let messages = entry
        .web_socket_messages
        .as_ref()
        .expect("WebSocket extension");
    assert_eq!(messages.len(), 2);
    assert!(entry.time < 2_000, "entry time must describe the handshake");

    // Stopping the recorder closes only its capture sink. The application
    // stream remains usable, and later traffic cannot mutate the closed HAR.
    client
        .send_message(Message::text("after-stop"))
        .await
        .expect("client send after stop");
    assert_eq!(
        client.recv_message().await.expect("echo after stop"),
        Message::text("echo-after-stop"),
    );
    drop(client);
    let unchanged: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("reread HAR"))
            .expect("reparse HAR");
    assert_eq!(
        unchanged.log.entries[0]
            .web_socket_messages
            .as_ref()
            .expect("WebSocket extension")
            .len(),
        2,
    );

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "WebSocket artifacts must be removed");
}
