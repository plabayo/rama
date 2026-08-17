use rama_http::layer::har::{
    recorder::{FileRecorder, HarFilePath, Recorder},
    spec::{Entry, Log, LogFile, WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType},
};
use serde_json::{Value, json};

const SEND_TIME: f64 = 1_558_730_482.507_147_3;
const RECEIVE_TIME: f64 = 1_558_730_482.588_386_3;

fn entry_value(web_socket_messages: Option<Value>) -> Value {
    let mut entry = json!({
        "startedDateTime": "2019-05-24T18:01:22.500Z",
        "time": 1,
        "request": {
            "method": "GET",
            "url": "wss://example.test/socket",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0
        },
        "response": {
            "status": 101,
            "statusText": "Switching Protocols",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": null},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0
        },
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 0}
    });
    if let Some(messages) = web_socket_messages {
        entry["_webSocketMessages"] = messages;
    }
    entry
}

fn chromium_messages() -> Value {
    json!([
        {
            "type": "send",
            "time": SEND_TIME,
            "opcode": 1,
            "data": "Hello, WebSockets!"
        },
        {
            "type": "receive",
            "time": RECEIVE_TIME,
            "opcode": 2,
            "data": "AAECqg=="
        },
        {
            "type": "error",
            "time": RECEIVE_TIME + 1.0,
            "opcode": -1,
            "data": "Invalid frame header"
        }
    ])
}

#[test]
fn chromium_websocket_extension_deserializes_and_round_trips() {
    let entry: Entry =
        serde_json::from_value(entry_value(Some(chromium_messages()))).expect("deserialize entry");
    let messages = entry.web_socket_messages.as_ref().expect("messages");

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(messages[0].opcode, WebSocketMessageOpcode::TEXT);
    assert!((messages[0].time - SEND_TIME).abs() < f64::EPSILON);
    assert_eq!(messages[0].data.as_str(), "Hello, WebSockets!");
    assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
    assert_eq!(
        messages[1]
            .binary_data()
            .expect("binary opcode")
            .expect("valid base64"),
        [0, 1, 2, 0xaa]
    );
    assert_eq!(messages[2].r#type, WebSocketMessageType::Error);
    assert_eq!(messages[2].opcode, WebSocketMessageOpcode::ERROR);

    let encoded = serde_json::to_value(entry).expect("serialize entry");
    assert_eq!(encoded["_webSocketMessages"], chromium_messages());
}

#[test]
fn websocket_empty_array_is_distinct_from_a_non_websocket_entry() {
    let websocket: Entry =
        serde_json::from_value(entry_value(Some(json!([])))).expect("deserialize websocket");
    assert_eq!(websocket.web_socket_messages, Some(Vec::new()));
    assert_eq!(
        serde_json::to_value(websocket).expect("serialize websocket entry")["_webSocketMessages"],
        json!([])
    );

    let ordinary: Entry =
        serde_json::from_value(entry_value(None)).expect("deserialize ordinary entry");
    assert!(ordinary.web_socket_messages.is_none());
    assert!(
        serde_json::to_value(ordinary)
            .expect("serialize ordinary entry")
            .get("_webSocketMessages")
            .is_none()
    );
}

#[tokio::test]
async fn file_recorder_preserves_websocket_messages_in_complete_har() {
    let temp = tempfile::tempdir().expect("tempdir");
    let recorder = FileRecorder::new(temp.path().to_owned(), "websocket".to_owned());
    let entry: Entry =
        serde_json::from_value(entry_value(Some(chromium_messages()))).expect("deserialize entry");

    let extensions = recorder
        .record(Log {
            entries: vec![entry],
            ..Default::default()
        })
        .await
        .expect("recorder extensions");
    let path = extensions
        .get_ref::<HarFilePath>()
        .expect("HAR file path")
        .to_path_buf();
    recorder.stop_record().await;

    let bytes = tokio::fs::read(path).await.expect("read HAR file");
    let log_file: LogFile = serde_json::from_slice(&bytes).expect("parse complete HAR file");
    let messages: &[WebSocketMessage] = log_file.log.entries[0]
        .web_socket_messages
        .as_deref()
        .expect("recorded messages");

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
    assert_eq!(messages[1].opcode, WebSocketMessageOpcode::BINARY);
    assert_eq!(messages[2].opcode.as_i32(), -1);
}
