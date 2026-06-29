use super::{JsonRequestRewriteLayer, JsonRewriteBody, JsonRewriteLayer};
use crate::{Body, Request, Response, StreamingBody, body::Frame, body::util::BodyExt, header};
use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::stream;
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_json::path::JsonPath;
use rama_json::rewrite::{HandlerResult, JsonValue, JsonValueHandler};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

#[derive(Clone)]
struct ReplaceWith(&'static str);

impl JsonValueHandler for ReplaceWith {
    fn handle_value(&mut self, _selector: usize, value: &mut JsonValue<'_>) -> HandlerResult {
        value.replace(self.0)
    }
}

fn path(s: &str) -> JsonPath {
    s.parse().expect("valid JSONPath")
}

#[tokio::test]
async fn body_rewrites_json_directly() {
    let body = JsonRewriteBody::new(
        Body::from(r#"{"user":{"name":"Ada"}}"#),
        &[path("$.user.name")],
        ReplaceWith("Grace"),
    );
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"user":{"name":"Grace"}}"#);
}

#[tokio::test]
async fn body_rewrites_across_multiple_frames() {
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(br#"{"user":{"na"#)),
        Ok(Bytes::from_static(br#"me":"Ada"}"#)),
        Ok(Bytes::from_static(br#"}"#)),
    ];
    let body = JsonRewriteBody::new(
        Body::from_stream(stream::iter(chunks)),
        &[path("$.user.name")],
        ReplaceWith("Grace"),
    );
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"user":{"name":"Grace"}}"#);
}

#[tokio::test]
async fn body_rewrites_value_split_across_frames() {
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(br#"{"user":{"name":"A"#)),
        Ok(Bytes::from_static(br#"da"}}"#)),
    ];
    let body = JsonRewriteBody::new(
        Body::from_stream(stream::iter(chunks)),
        &[path("$.user.name")],
        ReplaceWith("Grace"),
    );
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"user":{"name":"Grace"}}"#);
}

#[tokio::test]
async fn body_surfaces_handler_error() {
    #[derive(Clone)]
    struct Boom;

    impl JsonValueHandler for Boom {
        fn handle_value(&mut self, _selector: usize, _value: &mut JsonValue<'_>) -> HandlerResult {
            Err(rama_json::JsonError::new(
                rama_json::JsonErrorKind::UnexpectedToken("boom"),
            ))
        }
    }

    let body = JsonRewriteBody::new(Body::from(r#"{"name":"Ada"}"#), &[path("$.name")], Boom);
    body.collect()
        .await
        .expect_err("handler error should surface as a body error");
}

#[tokio::test]
async fn body_surfaces_inner_body_error() {
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(br#"{"name":"Ada"}"#)),
        Err(std::io::Error::other("inner body failed")),
    ];
    let body = JsonRewriteBody::new(
        Body::from_stream(stream::iter(chunks)),
        &[path("$.name")],
        ReplaceWith("Grace"),
    );

    body.collect()
        .await
        .expect_err("inner body error should surface");
}

#[tokio::test]
async fn body_surfaces_buffered_input_limit() {
    let body = JsonRewriteBody::with_max_buffered_bytes(
        Body::from_stream(stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(br#"{"name":"#)),
            Ok(Bytes::from_static(br#""unterminated"#)),
        ])),
        &[path("$.name")],
        ReplaceWith("Grace"),
        8,
    );

    body.collect()
        .await
        .expect_err("buffered input limit should surface as a body error");
}

#[tokio::test]
async fn body_passthrough_forwards_unchanged() {
    let body: JsonRewriteBody<Body, ReplaceWith> =
        JsonRewriteBody::passthrough(Body::from(r#"{"name":"Ada"}"#));
    assert_eq!(body.size_hint().exact(), Some(14));
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada"}"#);
}

#[tokio::test]
async fn layer_rewrites_json_and_strips_content_length() {
    let svc = JsonRewriteLayer::new([path("$.user.name")], ReplaceWith("Grace")).into_layer(
        service_fn(async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, "23")
                    .header(header::ETAG, "\"old\"")
                    .body(Body::from(r#"{"user":{"name":"Ada"}}"#))
                    .expect("response"),
            )
        }),
    );

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    assert!(res.headers().get(header::CONTENT_LENGTH).is_none());
    assert!(res.headers().get(header::ETAG).is_none());
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"user":{"name":"Grace"}}"#);
    assert_ne!(out.len(), 23);
}

#[tokio::test]
async fn layer_rewrite_can_set_buffered_input_limit() {
    let svc = JsonRewriteLayer::new([path("$.name")], ReplaceWith("Grace"))
        .with_max_buffered_bytes(8)
        .into_layer(service_fn(async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from_stream(stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from_static(br#"{"name":"#)),
                        Ok(Bytes::from_static(br#""unterminated"#)),
                    ])))
                    .expect("response"),
            )
        }));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    res.into_body()
        .collect()
        .await
        .expect_err("buffered input limit should surface as a body error");
}

#[tokio::test]
async fn layer_rewrites_structured_json_content_type() {
    let svc = JsonRewriteLayer::new([path("$.name")], ReplaceWith("Grace")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/problem+json")
                    .body(Body::from(r#"{"name":"Ada"}"#))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Grace"}"#);
}

#[tokio::test]
async fn layer_with_empty_selectors_is_passthrough() {
    let svc = JsonRewriteLayer::new([], ReplaceWith("Grace")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, "14")
                    .body(Body::from(r#"{"name":"Ada"}"#))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    assert_eq!(
        res.headers().get(header::CONTENT_LENGTH),
        Some(&"14".parse().expect("header"))
    );
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada"}"#);
}

#[tokio::test]
async fn layer_passthrough_for_non_json() {
    let svc = JsonRewriteLayer::new([path("$.name")], ReplaceWith("Grace")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from(r#"{"name":"Ada"}"#))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada"}"#);
}

#[tokio::test]
async fn layer_skips_content_encoded() {
    let svc = JsonRewriteLayer::new([path("$.name")], ReplaceWith("Grace")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from(r#"{"name":"Ada"}"#))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada"}"#);
}

#[tokio::test]
async fn request_layer_rewrites_json_and_strips_content_length() {
    let svc = JsonRequestRewriteLayer::new([path("$.user.name")], ReplaceWith("Grace")).into_layer(
        service_fn(async |req: Request<JsonRewriteBody<Body, ReplaceWith>>| {
            assert!(req.headers().get(header::CONTENT_LENGTH).is_none());
            let out = req.into_body().collect().await.expect("collect").to_bytes();
            assert_eq!(&out[..], br#"{"user":{"name":"Grace"}}"#);
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );

    svc.serve(
        Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, "23")
            .body(Body::from(r#"{"user":{"name":"Ada"}}"#))
            .expect("request"),
    )
    .await
    .expect("serve");
}

#[tokio::test]
async fn request_layer_passthrough_for_non_json() {
    let svc = JsonRequestRewriteLayer::new([path("$.name")], ReplaceWith("Grace")).into_layer(
        service_fn(async |req: Request<JsonRewriteBody<Body, ReplaceWith>>| {
            assert_eq!(
                req.headers().get(header::CONTENT_LENGTH),
                Some(&"14".parse().expect("header"))
            );
            let out = req.into_body().collect().await.expect("collect").to_bytes();
            assert_eq!(&out[..], br#"{"name":"Ada"}"#);
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );

    svc.serve(
        Request::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, "14")
            .body(Body::from(r#"{"name":"Ada"}"#))
            .expect("request"),
    )
    .await
    .expect("serve");
}

#[tokio::test]
async fn request_layer_skips_content_encoded() {
    let svc = JsonRequestRewriteLayer::new([path("$.name")], ReplaceWith("Grace")).into_layer(
        service_fn(async |req: Request<JsonRewriteBody<Body, ReplaceWith>>| {
            let out = req.into_body().collect().await.expect("collect").to_bytes();
            assert_eq!(&out[..], br#"{"name":"Ada"}"#);
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );

    svc.serve(
        Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(Body::from(r#"{"name":"Ada"}"#))
            .expect("request"),
    )
    .await
    .expect("serve");
}

#[tokio::test]
async fn request_layer_custom_policy_can_skip_rewrite() {
    let svc = JsonRequestRewriteLayer::new([path("$.name")], ReplaceWith("Grace"))
        .with_rewrite_policy(|_| false)
        .into_layer(service_fn(
            async |req: Request<JsonRewriteBody<Body, ReplaceWith>>| {
                let out = req.into_body().collect().await.expect("collect").to_bytes();
                assert_eq!(&out[..], br#"{"name":"Ada"}"#);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        ));

    svc.serve(
        Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"name":"Ada"}"#))
            .expect("request"),
    )
    .await
    .expect("serve");
}

#[tokio::test]
async fn request_layer_rewrite_can_set_buffered_input_limit() {
    let svc = JsonRequestRewriteLayer::new([path("$.name")], ReplaceWith("Grace"))
        .with_max_buffered_bytes(8)
        .into_layer(service_fn(
            async |req: Request<JsonRewriteBody<Body, ReplaceWith>>| {
                req.into_body().collect().await?;
                Ok::<_, BoxError>(Response::new(Body::empty()))
            },
        ));

    svc.serve(
        Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(br#"{"name":"#)),
                Ok(Bytes::from_static(br#""unterminated"#)),
            ])))
            .expect("request"),
    )
    .await
    .expect_err("buffered input limit should surface from request body");
}

struct TestBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl TestBody {
    fn new(frames: Vec<Frame<Bytes>>) -> Self {
        Self {
            frames: frames.into(),
        }
    }
}

impl StreamingBody for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.frames.pop_front() {
            Some(frame) => Poll::Ready(Some(Ok(frame))),
            None => Poll::Ready(None),
        }
    }
}

fn poll_body<B: StreamingBody + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match Pin::new(body).poll_frame(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => None,
    }
}

#[test]
fn body_delivers_trailers_after_rewriter_output() {
    let mut trailers = crate::HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().expect("header"));
    let inner = TestBody::new(vec![
        Frame::data(Bytes::from_static(br#"{"name":"Ada"}"#)),
        Frame::trailers(trailers),
    ]);
    let mut body = JsonRewriteBody::new(inner, &[path("$.name")], ReplaceWith("Grace"));

    let first = poll_body(&mut body)
        .expect("first frame")
        .expect("frame ok")
        .into_data()
        .expect("data");
    assert_eq!(&first[..], br#"{"name":"Grace"}"#);

    let received_trailers = poll_body(&mut body)
        .expect("trailers frame")
        .expect("frame ok")
        .into_trailers()
        .expect("trailers");
    assert_eq!(
        received_trailers.get("x-checksum").expect("trailer"),
        "abc123"
    );
    assert!(poll_body(&mut body).is_none());
}

#[derive(Default)]
struct NameRecorder {
    names: Vec<String>,
}

impl JsonValueHandler for NameRecorder {
    fn handle_value(&mut self, _selector: usize, value: &mut JsonValue<'_>) -> HandlerResult {
        if let Some(name) = value.as_str() {
            self.names.push(name.into_owned());
        }
        value.replace("redacted")
    }
}

#[tokio::test]
async fn on_end_recovers_handler_state_at_clean_eof() {
    let calls = Arc::new(AtomicUsize::new(0));
    let recovered: Arc<Mutex<Option<NameRecorder>>> = Arc::new(Mutex::new(None));

    let (calls_cb, sink) = (calls.clone(), recovered.clone());
    let body = JsonRewriteBody::new(
        Body::from(r#"{"users":[{"name":"Ada"},{"name":"Grace"}]}"#),
        &[path("$..name")],
        NameRecorder::default(),
    )
    .on_end(move |handler: NameRecorder| {
        calls_cb.fetch_add(1, Ordering::SeqCst);
        *sink.lock() = Some(handler);
    });

    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(
        &out[..],
        br#"{"users":[{"name":"redacted"},{"name":"redacted"}]}"#
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let handler = recovered.lock().take().expect("on_end fired");
    assert_eq!(handler.names, vec!["Ada".to_owned(), "Grace".to_owned()]);
}

#[tokio::test]
async fn on_end_does_not_fire_on_error_path() {
    #[derive(Clone)]
    struct Boom;

    impl JsonValueHandler for Boom {
        fn handle_value(&mut self, _selector: usize, _value: &mut JsonValue<'_>) -> HandlerResult {
            Err(rama_json::JsonError::new(
                rama_json::JsonErrorKind::UnexpectedToken("boom"),
            ))
        }
    }

    let fired = Arc::new(AtomicUsize::new(0));
    let flag = fired.clone();
    let body = JsonRewriteBody::new(Body::from(r#"{"name":"Ada"}"#), &[path("$.name")], Boom)
        .on_end(move |_handler: Boom| {
            flag.fetch_add(1, Ordering::SeqCst);
        });

    body.collect()
        .await
        .expect_err("handler error should surface as a body error");
    assert_eq!(fired.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn on_end_does_not_fire_in_passthrough() {
    let fired = Arc::new(AtomicUsize::new(0));
    let flag = fired.clone();
    let body: JsonRewriteBody<Body, ReplaceWith> = JsonRewriteBody::passthrough(Body::from(
        r#"{"name":"Ada"}"#,
    ))
    .on_end(move |_handler: ReplaceWith| {
        flag.fetch_add(1, Ordering::SeqCst);
    });

    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], br#"{"name":"Ada"}"#);
    assert_eq!(fired.load(Ordering::SeqCst), 0);
}
