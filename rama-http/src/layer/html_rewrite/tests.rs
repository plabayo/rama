use super::{HtmlRewriteBody, HtmlRewriteLayer};
use crate::protocols::html::rewrite::{Element, ElementContentHandler, HandlerResult};
use crate::protocols::html::selector::Selector;
use crate::{Body, Request, Response, body::util::BodyExt, header};
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use std::convert::Infallible;

/// A plain struct handler (`Clone + Send`): appends text as `<body>`'s last
/// child. No interior-mutability ceremony needed.
#[derive(Clone)]
struct AppendToBody(&'static str);

impl ElementContentHandler for AppendToBody {
    fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
        element.append_text(self.0);
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
                    .body(Body::from("<body>hello</body>"))
                    .expect("response"),
            )
        },
    ));

    let res = svc.serve(Request::new(Body::empty())).await.expect("serve");
    // The stale Content-Length must be gone (the body length changed).
    assert!(res.headers().get(header::CONTENT_LENGTH).is_none());
    let out = res.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(&out[..], b"<body>hello!</body>");
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
