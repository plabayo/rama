use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_core::futures::stream;
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_http::body::util::{BodyExt, Channel};
use rama_http::layer::har::layer::HARExportLayer;
use rama_http::layer::har::recorder::{
    FileRecorder, HarFilePath, LogMetaInfo, Recorder, WebSocketCapture,
};
use rama_http::layer::har::spec::{
    Browser, Creator, LogFile, WebSocketMessage, WebSocketMessageType,
};
use rama_http::proto::h2::ext::Protocol;
use rama_http::{Body, Request, Response};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

async fn stop_recording(recorder: &FileRecorder) {
    let stopped = tokio::time::timeout(Duration::from_secs(2), recorder.stop_record()).await;
    assert!(stopped.is_ok(), "recording must stop promptly");
}

async fn wait_for_recording_file_cleanup(dir: &std::path::Path) -> Result<(), BoxError> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let count = std::fs::read_dir(dir)?
                .collect::<Result<Vec<_>, _>>()?
                .len();
            if count == 1 {
                return Ok::<_, std::io::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn open_bodies_do_not_delay_response_or_stop() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "streaming".to_owned());
    let (mut response_tx, response_body) = Channel::<Bytes>::new(1);
    let response_body = Arc::new(Mutex::new(Some(response_body)));

    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn({
        let response_body = response_body.clone();
        move |mut request: Request| {
            let response_body = response_body.clone();
            async move {
                let first = request
                    .body_mut()
                    .frame()
                    .await
                    .expect("request frame")
                    .expect("request data")
                    .into_data()
                    .expect("data frame");
                assert_eq!(first, "request-prefix");
                let body = response_body.lock().take().expect("one request");
                Ok::<_, Infallible>(Response::new(Body::new(body)))
            }
        }
    }));

    let (mut request_tx, request_body) = Channel::<Bytes>::new(1);
    request_tx
        .send_data(Bytes::from_static(b"request-prefix"))
        .await
        .expect("queue request prefix");
    let request = Request::builder()
        .method("POST")
        .uri("https://example.test/open")
        .header("content-type", "text/plain")
        .body(Body::new(request_body))
        .expect("request");

    // Both channel senders remain open. The old collect-first implementation
    // could not return from serve in this state.
    let mut response = tokio::time::timeout(Duration::from_secs(2), service.serve(request))
        .await
        .expect("serve must not wait for either body to end")
        .expect("response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path extension")
        .to_path_buf();

    response_tx
        .send_data(Bytes::from_static(b"response-prefix"))
        .await
        .expect("queue response prefix");
    let first = response
        .body_mut()
        .frame()
        .await
        .expect("response frame")
        .expect("response data")
        .into_data()
        .expect("data frame");
    assert_eq!(first, "response-prefix");

    stop_recording(&recorder).await;

    // Cancelling recording drops only the observer. The live body continues.
    response_tx
        .send_data(Bytes::from_static(b"response-after-stop"))
        .await
        .expect("body receiver remains alive");
    let after_stop = response
        .body_mut()
        .frame()
        .await
        .expect("response frame after stop")
        .expect("response data after stop")
        .into_data()
        .expect("data frame after stop");
    assert_eq!(after_stop, "response-after-stop");

    let log: LogFile = serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR"))
        .expect("complete HAR JSON");
    assert_eq!(log.log.entries.len(), 1);
    let entry = &log.log.entries[0];
    assert_eq!(entry.request.body_size, 14);
    assert_eq!(
        entry.request.post_data.as_ref().unwrap().text.as_deref(),
        Some("request-prefix")
    );
    let recorded_response = &entry.response;
    assert_eq!(recorded_response.body_size, 15);
    assert_eq!(
        recorded_response.content.text.as_deref(),
        Some("response-prefix")
    );

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "all temporary artifacts must be removed");
}

#[tokio::test]
async fn storage_creation_failure_does_not_break_http_service() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let invalid_dir = dir.path().join("not-a-directory");
    tokio::fs::write(&invalid_dir, b"occupied")
        .await
        .expect("create path blocker");
    let recorder = FileRecorder::new(invalid_dir.clone(), "unwritable".to_owned());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        |_request: Request| async move {
            Ok::<_, Infallible>(Response::new(Body::from("still served")))
        },
    ));

    let response = service
        .serve(Request::new(Body::from("still consumed")))
        .await
        .expect("HTTP service remains available");
    assert!(response.extensions().get_ref::<HarFilePath>().is_none());
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes(),
        Bytes::from_static(b"still served"),
    );

    stop_recording(&recorder).await;
    assert_eq!(
        tokio::fs::read(invalid_dir).await.expect("path blocker"),
        b"occupied"
    );
}

#[tokio::test]
async fn concurrent_streams_are_serialized_without_interleaving() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "concurrent".to_owned());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        async |request: Request| {
            let marker = request.uri().path_or_root().to_string();
            request
                .into_body()
                .collect()
                .await
                .expect("consume request body");
            let chunks = match marker.as_str() {
                "/text" => vec![
                    Ok::<_, Infallible>(Bytes::from_static(b"quoted: \"")),
                    Ok(Bytes::from_static("snowman: ☃\n".as_bytes())),
                ],
                "/binary" => vec![
                    Ok(Bytes::from_static(&[0, 1, 2])),
                    Ok(Bytes::from_static(&[0xff, 0xfe, 0xfd])),
                ],
                _ => Vec::new(),
            };
            Ok::<_, Infallible>(Response::new(Body::from_stream(stream::iter(chunks))))
        },
    ));

    let text_request = Request::builder()
        .method("POST")
        .uri("https://example.test/text")
        .body(Body::from_stream(stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(b"text-")),
            Ok(Bytes::from_static(b"request")),
        ])))
        .unwrap();
    let binary_request = Request::builder()
        .method("POST")
        .uri("https://example.test/binary")
        .body(Body::from_stream(stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(&[9, 8, 7])),
            Ok(Bytes::from_static(&[0xff, 0x00])),
        ])))
        .unwrap();

    let (text_response, binary_response) =
        tokio::join!(service.serve(text_request), service.serve(binary_request));
    let text_response = text_response.expect("text response");
    let path = text_response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    let binary_response = binary_response.expect("binary response");
    let (text_body, binary_body) = tokio::join!(
        text_response.into_body().collect(),
        binary_response.into_body().collect()
    );
    assert_eq!(
        text_body.expect("text body").to_bytes(),
        "quoted: \"snowman: ☃\n"
    );
    assert_eq!(
        binary_body.expect("binary body").to_bytes().as_ref(),
        &[0, 1, 2, 0xff, 0xfe, 0xfd]
    );

    stop_recording(&recorder).await;
    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    assert_eq!(log.log.entries.len(), 2);

    let text = log
        .log
        .entries
        .iter()
        .find(|entry| entry.request.url.ends_with("/text"))
        .expect("text entry");
    assert_eq!(
        text.request.post_data.as_ref().unwrap().text.as_deref(),
        Some("text-request")
    );
    assert_eq!(
        text.response.content.text.as_deref(),
        Some("quoted: \"snowman: ☃\n")
    );

    let binary = log
        .log
        .entries
        .iter()
        .find(|entry| entry.request.url.ends_with("/binary"))
        .expect("binary entry");
    assert_eq!(
        binary.request.post_data.as_ref().unwrap().text.as_deref(),
        Some("CQgH/wA=")
    );
    let binary_content = &binary.response.content;
    assert_eq!(binary_content.text.as_deref(), Some("AAEC//79"));
    assert_eq!(binary_content.encoding.as_deref(), Some("base64"));
}

#[tokio::test]
async fn form_request_streams_text_and_structured_parameters() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "form".to_owned());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        async |request: Request| {
            request
                .into_body()
                .collect()
                .await
                .expect("consume form body");
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    let form = "a=1&space=hello+world&unicode=%E2%98%83&a=2";
    let request = Request::builder()
        .method("POST")
        .uri("https://example.test/form")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .expect("form request");

    let response = service.serve(request).await.expect("form response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response
        .into_body()
        .collect()
        .await
        .expect("empty response");
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let post_data = log.log.entries[0]
        .request
        .post_data
        .as_ref()
        .expect("form post data");
    assert_eq!(post_data.text.as_deref(), Some(form));
    let params = post_data.params.as_ref().expect("structured form params");
    let params = params
        .iter()
        .map(|param| (param.name.as_str(), param.value.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        params,
        vec![
            ("a", Some("1")),
            ("space", Some("hello world")),
            ("unicode", Some("☃")),
            ("a", Some("2")),
        ]
    );
}

#[tokio::test]
async fn streaming_file_uses_configured_log_metadata() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new_with_log_meta_info(
        dir.path().to_owned(),
        "metadata".to_owned(),
        LogMetaInfo {
            version: rama_utils::str::non_empty_str!("1.2"),
            creator: Creator {
                name: "custom-recorder".into(),
                version: "4.0".into(),
                comment: Some("creator-comment".into()),
            },
            browser: Some(Browser {
                name: "custom-browser".into(),
                version: Some("123".into()),
                comment: None,
            }),
            comment: Some("log-comment".into()),
        },
    );
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        |_request: Request| async move { Ok::<_, Infallible>(Response::new(Body::empty())) },
    ));

    let response = service
        .serve(Request::new(Body::empty()))
        .await
        .expect("response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response
        .into_body()
        .collect()
        .await
        .expect("empty response");
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    assert_eq!(log.log.version.as_ref(), "1.2");
    assert_eq!(log.log.creator.name.as_str(), "custom-recorder");
    assert_eq!(log.log.creator.version.as_str(), "4.0");
    assert_eq!(log.log.creator.comment.as_deref(), Some("creator-comment"));
    assert_eq!(
        log.log
            .browser
            .as_ref()
            .map(|browser| browser.name.as_str()),
        Some("custom-browser")
    );
    assert_eq!(
        log.log
            .browser
            .as_ref()
            .and_then(|browser| browser.version.as_deref()),
        Some("123")
    );
    assert_eq!(log.log.comment.as_deref(), Some("log-comment"));
}

#[tokio::test]
async fn entry_time_ends_with_http_body_not_artifact_serialization() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "timing".to_owned());
    let (response_tx, response_body) = Channel::<Bytes>::new(1);
    let response_body = Arc::new(Mutex::new(Some(response_body)));
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn({
        let response_body = response_body.clone();
        move |_request: Request| {
            let body = response_body.lock().take().expect("one request");
            async move { Ok::<_, Infallible>(Response::new(Body::new(body))) }
        }
    }));

    let response = service
        .serve(Request::new(Body::empty()))
        .await
        .expect("response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();

    tokio::time::sleep(Duration::from_millis(40)).await;
    drop(response_tx);
    response
        .into_body()
        .collect()
        .await
        .expect("finish delayed body");
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    assert!(log.log.entries[0].request.post_data.is_none());
    let content = &log.log.entries[0].response.content;
    assert!(content.text.is_none());
    assert!(content.encoding.is_none());
    assert!(
        log.log.entries[0].time >= 30,
        "entry time must include response streaming: {}ms",
        log.log.entries[0].time,
    );
}

#[tokio::test]
async fn utf8_split_at_serializer_chunk_boundary_stays_text() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "utf8-boundary".to_owned());
    // The first three bytes of a four-byte scalar end the first 8 KiB read,
    // while the first byte of a three-byte scalar ends the second read.
    let mut expected = "a".repeat(8189);
    expected.push('🦀');
    expected.push_str(&"b".repeat(8190));
    expected.push_str("☃\"\n");
    let response_bytes = Bytes::copy_from_slice(expected.as_bytes());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        move |_request: Request| {
            let response_bytes = response_bytes.clone();
            async move { Ok::<_, Infallible>(Response::new(Body::from(response_bytes))) }
        },
    ));

    let response = service
        .serve(Request::new(Body::empty()))
        .await
        .expect("response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response
        .into_body()
        .collect()
        .await
        .expect("consume response");
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let content = &log.log.entries[0].response.content;
    assert_eq!(content.text.as_deref(), Some(expected.as_str()));
    assert!(content.encoding.is_none());
}

#[tokio::test]
async fn web_socket_upgrade_emits_empty_chromium_message_extension() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-empty".to_owned());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        |_request: Request| async move {
            Response::builder()
                .status(rama_http::StatusCode::SWITCHING_PROTOCOLS)
                .version(rama_http::Version::HTTP_11)
                .body(Body::empty())
        },
    ));
    let request = Request::builder()
        .uri("ws://example.test/empty")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();

    let response = service.serve(request).await.expect("upgrade response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response.into_body().collect().await.expect("empty body");
    wait_for_recording_file_cleanup(dir.path()).await.unwrap();
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    assert_eq!(
        log.log.entries[0].resource_type.as_deref(),
        Some("websocket")
    );
    assert_eq!(
        log.log.entries[0]
            .web_socket_messages
            .as_deref()
            .expect("Chromium WebSocket extension"),
        &[],
    );
}

#[tokio::test]
async fn concurrent_web_socket_sessions_share_one_file_without_interleaving() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-concurrent".to_owned());
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
        |_request: Request| async move {
            Response::builder()
                .status(rama_http::StatusCode::SWITCHING_PROTOCOLS)
                .version(rama_http::Version::HTTP_11)
                .body(Body::empty())
        },
    ));
    let request = |name: &str| {
        Request::builder()
            .uri(format!("ws://example.test/{name}"))
            .header("upgrade", "websocket")
            .body(Body::empty())
            .expect("WebSocket request")
    };

    let (response_a, response_b) =
        tokio::join!(service.serve(request("a")), service.serve(request("b")),);
    let response_a = response_a.expect("first upgrade response");
    let response_b = response_b.expect("second upgrade response");
    let path_a = response_a
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("first HAR path")
        .to_path_buf();
    let path_b = response_b
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("second HAR path")
        .to_path_buf();
    assert_eq!(path_a, path_b, "both sessions belong to one HAR file");
    let lease_a = response_a
        .extensions()
        .get_ref::<WebSocketCapture>()
        .expect("first capture")
        .lease()
        .expect("claim first capture");
    let lease_b = response_b
        .extensions()
        .get_ref::<WebSocketCapture>()
        .expect("second capture")
        .lease()
        .expect("claim second capture");

    let (record_a, record_b) = tokio::join!(
        lease_a.record(WebSocketMessage::text(
            WebSocketMessageType::Send,
            1_800_000_000.25,
            "message-a",
        )),
        lease_b.record(WebSocketMessage::text(
            WebSocketMessageType::Receive,
            1_800_000_000.5,
            "message-b",
        )),
    );
    record_a.expect("record first message");
    record_b.expect("record second message");
    drop(lease_a);
    drop(lease_b);
    response_a
        .into_body()
        .collect()
        .await
        .expect("first empty body");
    response_b
        .into_body()
        .collect()
        .await
        .expect("second empty body");
    wait_for_recording_file_cleanup(dir.path()).await.unwrap();
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path_a).await.expect("read concurrent HAR"))
            .expect("parse concurrent HAR");
    assert_eq!(log.log.entries.len(), 2);
    for (suffix, expected_type, expected_data) in [
        ("/a", WebSocketMessageType::Send, "message-a"),
        ("/b", WebSocketMessageType::Receive, "message-b"),
    ] {
        let entry = log
            .log
            .entries
            .iter()
            .find(|entry| entry.request.url.ends_with(suffix))
            .expect("matching WebSocket entry");
        let messages = entry
            .web_socket_messages
            .as_deref()
            .expect("Chromium WebSocket messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].r#type, expected_type);
        assert_eq!(messages[0].data.as_str(), expected_data);
    }

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "all temporary artifacts are removed");
}

#[tokio::test]
async fn opaque_web_socket_lease_streams_and_stop_detaches_it() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-lease".to_owned());
    let (lease_tx, lease_rx) = tokio::sync::oneshot::channel();
    let lease_tx = Arc::new(Mutex::new(Some(lease_tx)));
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn({
        let lease_tx = lease_tx.clone();
        move |request: Request| {
            let lease = request
                .extensions()
                .get_ref::<WebSocketCapture>()
                .expect("opaque WebSocket capture")
                .lease()
                .expect("single lease");
            lease_tx
                .lock()
                .take()
                .expect("one request")
                .send(lease)
                .expect("lease receiver");
            async move {
                Response::builder()
                    .status(rama_http::StatusCode::SWITCHING_PROTOCOLS)
                    .version(rama_http::Version::HTTP_11)
                    .body(Body::empty())
            }
        }
    }));
    let request = Request::builder()
        .uri("ws://example.test/lease")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();

    let response = service.serve(request).await.expect("upgrade response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response.into_body().collect().await.expect("empty body");
    let lease = lease_rx.await.expect("capture lease");
    lease
        .record(WebSocketMessage::text(
            WebSocketMessageType::Send,
            1_800_000_000.25,
            "before-stop",
        ))
        .await
        .expect("record message");

    stop_recording(&recorder).await;
    lease
        .record(WebSocketMessage::text(
            WebSocketMessageType::Send,
            1_800_000_001.25,
            "after-stop",
        ))
        .await
        .expect("closed capture is a no-op");
    drop(lease);

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let messages = log.log.entries[0]
        .web_socket_messages
        .as_deref()
        .expect("Chromium WebSocket extension");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].data.as_str(), "before-stop");

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1, "WebSocket artifacts must be removed");
}

#[tokio::test]
async fn http2_extended_connect_records_web_socket_messages() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "websocket-h2".to_owned());
    let (lease_tx, lease_rx) = tokio::sync::oneshot::channel();
    let lease_tx = Arc::new(Mutex::new(Some(lease_tx)));
    let service = HARExportLayer::new(recorder.clone(), true).into_layer(service_fn({
        let lease_tx = lease_tx.clone();
        move |request: Request| {
            let lease = request
                .extensions()
                .get_ref::<WebSocketCapture>()
                .expect("HTTP/2 WebSocket capture")
                .lease()
                .expect("single lease");
            lease_tx
                .lock()
                .take()
                .expect("one request")
                .send(lease)
                .expect("lease receiver");
            async move {
                Response::builder()
                    .status(rama_http::StatusCode::OK)
                    .version(rama_http::Version::HTTP_2)
                    .body(Body::empty())
            }
        }
    }));
    let request = Request::builder()
        .method(rama_http::Method::CONNECT)
        .uri("https://example.test/h2-websocket")
        .version(rama_http::Version::HTTP_2)
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(Protocol::from_static("websocket"));

    let response = service
        .serve(request)
        .await
        .expect("extended CONNECT response");
    let path = response
        .extensions()
        .get_ref::<HarFilePath>()
        .expect("HAR path")
        .to_path_buf();
    response.into_body().collect().await.expect("empty body");
    let lease = lease_rx.await.expect("capture lease");
    lease
        .record(WebSocketMessage::text(
            WebSocketMessageType::Send,
            1_800_000_000.5,
            "over-h2",
        ))
        .await
        .expect("record HTTP/2 WebSocket message");
    drop(lease);
    wait_for_recording_file_cleanup(dir.path()).await.unwrap();
    stop_recording(&recorder).await;

    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(path).await.expect("read HAR")).expect("parse HAR");
    let entry = &log.log.entries[0];
    assert_eq!(entry.request.method.as_str(), "CONNECT");
    assert_eq!(
        entry
            .web_socket_messages
            .as_deref()
            .expect("WebSocket extension")[0]
            .data
            .as_str(),
        "over-h2"
    );
}

#[tokio::test]
async fn service_error_serializes_a_request_only_entry() {
    let dir = rama_utils::fs::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(dir.path().to_owned(), "request-only".to_owned());
    let service =
        HARExportLayer::new(recorder.clone(), true).into_layer(service_fn(
            |_request: Request| async move {
                Err::<Response, _>(std::io::Error::other("service failed"))
            },
        ));

    service
        .serve(Request::new(Body::empty()))
        .await
        .expect_err("inner service error");
    stop_recording(&recorder).await;

    let files = std::fs::read_dir(dir.path())
        .expect("read recording dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert_eq!(files.len(), 1);
    let log: LogFile =
        serde_json::from_slice(&tokio::fs::read(files[0].path()).await.expect("read HAR"))
            .expect("parse HAR");
    assert_eq!(log.log.entries.len(), 1);
    let response = &log.log.entries[0].response;
    assert_eq!(response.status, 0);
    assert_eq!(response.status_text.as_deref(), Some(""));
    assert_eq!(response.headers_size, -1);
    assert_eq!(response.body_size, -1);
    assert_eq!(response.content.size, 0);
}
