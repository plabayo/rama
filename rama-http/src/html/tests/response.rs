//! Handler-ergonomics — `HtmlBuf` is `IntoResponse` directly with
//! `Content-Type: text/html`, `html!(...)` auto-prepends `<!DOCTYPE html>`,
//! etc.

use crate::html::*;
use crate::service::web::response::IntoResponse;

use super::collect_body;

#[test]
fn html_buf_sets_text_html_utf8_content_type() {
    let resp = div!("hi").into_response();
    let ct = resp
        .headers()
        .get(crate::header::CONTENT_TYPE)
        .expect("content-type set")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(ct.starts_with("text/html"));
    assert!(ct.contains("utf-8"));
}

#[test]
fn html_buf_response_body_is_escaped_html() {
    let resp = div!("a < b").into_response();
    let body = collect_body(resp);
    assert_eq!(body, "<div>a &lt; b</div>");
}

#[test]
fn html_macro_auto_prepends_doctype() {
    let out = html!(body!(p!("ok"))).into_string();
    assert_eq!(out, "<!DOCTYPE html><html><body><p>ok</p></body></html>");
}

#[test]
fn html_macro_supports_attributes() {
    let out = html!(lang = "en", body!()).into_string();
    assert_eq!(
        out,
        r#"<!DOCTYPE html><html lang="en"><body></body></html>"#,
    );
}

#[test]
fn html_macro_is_into_response_directly() {
    // The whole point of the design: returning `html!(...)` from a
    // handler "just works" without any wrapper.
    let resp = html!(body!(p!("ok"))).into_response();
    let body = collect_body(resp);
    assert_eq!(body, "<!DOCTYPE html><html><body><p>ok</p></body></html>");
}
