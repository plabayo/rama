use super::JsonCaptureBody;
use crate::{Body, StreamingBody, body::Frame, body::util::BodyExt};
use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::futures::stream;
use rama_json::capture::{CaptureHandler, CaptureResult, CapturedValue, OwnedCapturedValue};
use rama_json::path::JsonPath;
use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll};

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

#[test]
fn body_delivers_trailers_after_capture() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let mut trailers = crate::HeaderMap::new();
    trailers.insert("x-done", "yes".parse().expect("header"));
    let inner = TwoFrameBody::new([
        Frame::data(Bytes::from_static(br#"{"name":"Ada"}"#)),
        Frame::trailers(trailers),
    ]);
    let mut body = JsonCaptureBody::new(inner, &[name_path()], 64, Recorder::default()).on_end(
        move |handler| {
            *sink.lock() = handler.values;
        },
    );

    let first = poll_body(&mut body)
        .expect("first frame")
        .expect("first frame ok")
        .into_data()
        .expect("data");
    assert_eq!(&first[..], br#"{"name":"Ada"}"#);

    let second = poll_body(&mut body)
        .expect("second frame")
        .expect("second frame ok")
        .into_trailers()
        .expect("trailers");
    assert_eq!(second.get("x-done").unwrap(), "yes");
    assert!(poll_body(&mut body).is_none());
    assert_eq!(captured.lock()[0].as_str().as_deref(), Some("Ada"));
}

fn poll_body<B: StreamingBody + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match std::pin::Pin::new(body).poll_frame(&mut cx) {
        Poll::Ready(frame) => frame,
        Poll::Pending => panic!("body unexpectedly pending"),
    }
}

struct TwoFrameBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl TwoFrameBody {
    fn new(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Self {
        Self {
            frames: frames.into_iter().collect(),
        }
    }
}

impl StreamingBody for TwoFrameBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front().map(Ok))
    }
}
