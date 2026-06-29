use super::JsonCaptureBody;
use crate::{
    Body,
    body::{
        Frame,
        util::{BodyExt, StreamBody},
    },
};
use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::futures::stream;
use rama_json::capture::{CaptureHandler, CaptureResult, CapturedValue, OwnedCapturedValue};
use rama_json::path::JsonPath;
use std::sync::Arc;

#[derive(Debug, Default)]
struct Recorder {
    values: Vec<OwnedCapturedValue>,
}

impl CaptureHandler for Recorder {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
        self.values.push(value.into_owned());
        Ok(())
    }
}

fn name_path() -> JsonPath {
    JsonPath::builder().member("name").build()
}

fn user_path() -> JsonPath {
    JsonPath::builder().member("user").build()
}

#[tokio::test]
async fn body_captures_selected_values_and_forwards_unchanged() {
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(br#"{"name":"#)),
        Ok(Bytes::from_static(br#""Ada","ok":true}"#)),
    ];
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let body = JsonCaptureBody::new(
        Body::from_stream(stream::iter(chunks)),
        &[name_path()],
        64,
        Recorder::default(),
    )
    .on_end(move |handler| {
        *sink.lock() = handler.values;
    });

    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada","ok":true}"#);
    let captured = captured.lock();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path().to_string(), "$.name");
    assert_eq!(captured[0].as_str().as_deref(), Some("Ada"));
}

#[tokio::test]
async fn body_captures_object_subtrees() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let body = JsonCaptureBody::new(
        Body::from(br#"{"user":{"id":7,"name":"Ada"},"ok":true}"#.as_slice()),
        &[user_path()],
        128,
        Recorder::default(),
    )
    .on_end(move |handler| {
        *sink.lock() = handler.values;
    });

    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"user":{"id":7,"name":"Ada"},"ok":true}"#);
    let captured = captured.lock();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path().to_string(), "$.user");
    assert_eq!(
        captured[0].deserialize::<serde_json::Value>().unwrap(),
        serde_json::json!({"id": 7, "name": "Ada"})
    );
}

#[tokio::test]
async fn body_surfaces_capture_limit() {
    let body = JsonCaptureBody::new(
        Body::from(br#"{"user":{"id":7,"name":"Ada"}}"#.as_slice()),
        &[user_path()],
        8,
        Recorder::default(),
    );

    body.collect()
        .await
        .expect_err("capture limit should surface as a body error");
}

#[tokio::test]
async fn body_delivers_trailers_after_capture() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let mut trailers = crate::HeaderMap::new();
    trailers.insert("x-done", "yes".parse().expect("header"));
    let frames = [
        Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(br#"{"name":"Ada"}"#))),
        Ok(Frame::trailers(trailers)),
    ];
    let inner = StreamBody::new(stream::iter(frames));
    let mut body = JsonCaptureBody::new(inner, &[name_path()], 64, Recorder::default()).on_end(
        move |handler| {
            *sink.lock() = handler.values;
        },
    );

    let first = body
        .frame()
        .await
        .expect("first frame")
        .expect("first frame ok")
        .into_data()
        .expect("data");
    assert_eq!(&first[..], br#"{"name":"Ada"}"#);

    let second = body
        .frame()
        .await
        .expect("second frame")
        .expect("second frame ok")
        .into_trailers()
        .expect("trailers");
    assert_eq!(second.get("x-done").unwrap(), "yes");
    assert!(body.frame().await.is_none());
    assert_eq!(captured.lock()[0].as_str().as_deref(), Some("Ada"));
}
