use super::{HtmlRewriteBody, HtmlRewriteLayer};
use crate::protocols::html::rewrite::{Element, ElementContentHandler, HandlerResult};
use crate::protocols::html::selector::Selector;
use crate::{Body, Request, Response, StreamingBody, body::Frame, body::util::BodyExt, header};
use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::futures::stream;
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// A plain struct handler (`Clone + Send`): appends text as `<body>`'s last
/// child. No interior-mutability ceremony needed.
#[derive(Clone)]
struct AppendToBody(&'static str);

impl ElementContentHandler for AppendToBody {
    fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
        element.append(self.0);
        Ok(())
    }
}

fn sel(s: &str) -> Selector {
    s.parse().expect("valid selector")
}

#[tokio::test]
async fn body_rewrites_html_directly() {
    let body = HtmlRewriteBody::new(
        Body::from("<body>hello</body>"),
        &[sel("body")],
        AppendToBody("!"),
    );
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello!</body>");
}

#[tokio::test]
async fn body_rewrites_across_multiple_frames() {
    // The matched element straddles frame boundaries; the streamed result must
    // equal the one-shot rewrite.
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(b"<body>he")),
        Ok(Bytes::from_static(b"llo</bo")),
        Ok(Bytes::from_static(b"dy>")),
    ];
    let body = HtmlRewriteBody::new(
        Body::from_stream(stream::iter(chunks)),
        &[sel("body")],
        AppendToBody("!"),
    );
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello!</body>");
}

#[tokio::test]
async fn body_surfaces_handler_error() {
    #[derive(Clone)]
    struct Boom;
    impl ElementContentHandler for Boom {
        fn handle_element(&mut self, _selector: usize, _el: &mut Element<'_>) -> HandlerResult {
            Err("boom".into())
        }
    }
    let body = HtmlRewriteBody::new(Body::from("<body>x</body>"), &[sel("body")], Boom);
    body.collect()
        .await
        .expect_err("handler error should surface as a body error");
}

#[tokio::test]
async fn body_passthrough_forwards_unchanged() {
    let body: HtmlRewriteBody<Body, AppendToBody> =
        HtmlRewriteBody::passthrough(Body::from("<body>hello</body>"));
    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello</body>");
}

#[tokio::test]
async fn layer_rewrites_html_and_strips_content_length() {
    let svc = HtmlRewriteLayer::new([sel("body")], AppendToBody("!")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CONTENT_LENGTH, "18")
                    .header(header::ETAG, "\"old\"")
                    .body(Body::from("<body>hello</body>"))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    // The stale Content-Length must be gone (the body length changed).
    assert!(res.headers().get(header::CONTENT_LENGTH).is_none());
    assert!(res.headers().get(header::ETAG).is_none());
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello!</body>");
}

#[tokio::test]
async fn layer_with_empty_selectors_is_passthrough() {
    let svc =
        HtmlRewriteLayer::new([], AppendToBody("!")).into_layer(service_fn(async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::CONTENT_LENGTH, "18")
                    .body(Body::from("<body>hello</body>"))
                    .expect("response"),
            )
        }));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    assert_eq!(
        res.headers().get(header::CONTENT_LENGTH),
        Some(&"18".parse().expect("header"))
    );
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello</body>");
}

#[tokio::test]
async fn layer_passthrough_for_non_html() {
    let svc = HtmlRewriteLayer::new([sel("body")], AppendToBody("!")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("<body>hello</body>"))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello</body>");
}

#[tokio::test]
async fn layer_skips_content_encoded() {
    let svc = HtmlRewriteLayer::new([sel("body")], AppendToBody("!")).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from("<body>hello</body>"))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    // Content-encoded bodies are not rewritten (the rewriter sees raw bytes).
    assert_eq!(&out[..], b"<body>hello</body>");
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
fn body_flushes_rewriter_tail_before_trailers() {
    let mut trailers = crate::HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().expect("header"));
    let inner = TestBody::new(vec![
        Frame::data(Bytes::from_static(b"<body>hello")),
        Frame::trailers(trailers),
    ]);
    let mut body = HtmlRewriteBody::new(inner, &[sel("body")], AppendToBody("!"));

    let first = poll_body(&mut body)
        .expect("first frame")
        .expect("frame ok")
        .into_data()
        .expect("data");
    assert_eq!(&first[..], b"<body>hello");

    let second = poll_body(&mut body)
        .expect("second frame")
        .expect("frame ok")
        .into_data()
        .expect("data");
    assert_eq!(&second[..], b"!");

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

// ---- `on_end` completion hook ------------------------------------------

/// Handler that both mutates (strips `href`) and *accumulates* (records the
/// stripped values) — the shape that motivates recovering the handler at EOF.
#[derive(Default)]
struct LinkStripper {
    stripped: Vec<String>,
}

impl ElementContentHandler for LinkStripper {
    fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
        if let Some(href) = element.attribute("href") {
            self.stripped
                .push(String::from_utf8_lossy(href).into_owned());
        }
        element.remove_attribute("href");
        Ok(())
    }
}

#[tokio::test]
async fn on_end_recovers_handler_state_at_clean_eof() {
    let calls = Arc::new(AtomicUsize::new(0));
    let recovered: Arc<Mutex<Option<LinkStripper>>> = Arc::new(Mutex::new(None));

    let (calls_cb, sink) = (calls.clone(), recovered.clone());
    let body = HtmlRewriteBody::new(
        Body::from(r#"<a href="/a">x</a><a href="/b">y</a>"#),
        &[sel("a")],
        LinkStripper::default(),
    )
    .on_end(move |handler: LinkStripper| {
        calls_cb.fetch_add(1, Ordering::SeqCst);
        *sink.lock() = Some(handler);
    });

    let out = body.collect().await.expect("collect").to_bytes();
    // Mutation still applied: `href` attributes are gone.
    assert_eq!(&out[..], b"<a>x</a><a>y</a>");
    // Hook fired exactly once at the inner-`None` terminal, handing back the
    // handler with its accumulated state.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let handler = recovered.lock().take().expect("on_end fired");
    assert_eq!(handler.stripped, vec!["/a".to_owned(), "/b".to_owned()]);
}

#[tokio::test]
async fn on_end_recovers_handler_state_on_trailers_terminated_body() {
    let calls = Arc::new(AtomicUsize::new(0));
    let recovered: Arc<Mutex<Option<LinkStripper>>> = Arc::new(Mutex::new(None));

    let mut trailers = crate::HeaderMap::new();
    trailers.insert("x-done", "1".parse().expect("header"));
    let inner = TestBody::new(vec![
        Frame::data(Bytes::from_static(
            br#"<a href="/a">x</a><a href="/b">y</a>"#,
        )),
        Frame::trailers(trailers),
    ]);

    let (calls_cb, sink) = (calls.clone(), recovered.clone());
    let mut body = HtmlRewriteBody::new(inner, &[sel("a")], LinkStripper::default()).on_end(
        move |handler: LinkStripper| {
            calls_cb.fetch_add(1, Ordering::SeqCst);
            *sink.lock() = Some(handler);
        },
    );

    // Drain to completion; the trailers frame must still be delivered.
    let mut saw_trailers = false;
    while let Some(frame) = poll_body(&mut body) {
        if frame.expect("frame ok").into_trailers().is_ok() {
            saw_trailers = true;
        }
    }
    assert!(saw_trailers, "trailers frame delivered");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let handler = recovered.lock().take().expect("on_end fired");
    assert_eq!(handler.stripped, vec!["/a".to_owned(), "/b".to_owned()]);
}

#[tokio::test]
async fn on_end_does_not_fire_on_error_path() {
    #[derive(Clone)]
    struct Boom;
    impl ElementContentHandler for Boom {
        fn handle_element(&mut self, _selector: usize, _el: &mut Element<'_>) -> HandlerResult {
            Err("boom".into())
        }
    }

    let fired = Arc::new(AtomicUsize::new(0));
    let flag = fired.clone();
    let body = HtmlRewriteBody::new(Body::from("<body>x</body>"), &[sel("body")], Boom).on_end(
        move |_handler: Boom| {
            flag.fetch_add(1, Ordering::SeqCst);
        },
    );

    body.collect()
        .await
        .expect_err("handler error should surface as a body error");
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "on_end must not fire when the rewrite aborts with an error",
    );
}

#[tokio::test]
async fn on_end_does_not_fire_in_passthrough() {
    let fired = Arc::new(AtomicUsize::new(0));
    let flag = fired.clone();
    let body: HtmlRewriteBody<Body, AppendToBody> = HtmlRewriteBody::passthrough(Body::from(
        "<body>hello</body>",
    ))
    .on_end(move |_handler: AppendToBody| {
        flag.fetch_add(1, Ordering::SeqCst);
    });

    let out = body.collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello</body>");
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "on_end must not fire in passthrough mode (no handler)",
    );
}
