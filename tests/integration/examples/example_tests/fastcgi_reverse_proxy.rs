//! End-to-end test for the `fastcgi_reverse_proxy` example.
//!
//! The example spawns two services in one binary:
//!   - a FastCGI application server on `127.0.0.1:62054` wrapping an HTTP echo
//!     handler via `FastCgiHttpService` + `FastCgiServer`;
//!   - an HTTP reverse proxy on `127.0.0.1:62053` that forwards via
//!     `FastCgiHttpClient` to the backend.
//!
//! These tests drive the public HTTP entry point (the proxy) and assert that
//! the response body — which is the request as observed by the inner HTTP
//! handler, round-tripped through FastCGI in both directions — contains the
//! expected method, URI, headers, and body.

use super::utils;
use rama::http::BodyExtractExt;
use rama::http::headers::ContentType;
use rama::net::address::HostWithPort;

const PROXY_ADDR: HostWithPort = HostWithPort::local_ipv4(62053);

#[tokio::test]
#[ignore]
async fn test_example_fastcgi_reverse_proxy_get() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("fastcgi_reverse_proxy", Some("fastcgi"));

    let body = runner
        .get(format!("http://{PROXY_ADDR}/hello?foo=bar"))
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    // The inner echo handler dumps the request line + headers. After a full
    // round trip through HTTP → FastCGI client → FastCGI server → HTTP service
    // → CGI stdout → HTTP response, we should still see the original method,
    // path and query.
    assert!(
        body.contains("GET /hello?foo=bar"),
        "expected request line round-trip; body = {body:?}"
    );
}

#[tokio::test]
#[ignore]
async fn test_example_fastcgi_reverse_proxy_post_body_streams_through() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("fastcgi_reverse_proxy", Some("fastcgi"));

    let payload = "name=rama";
    let body = runner
        .post(format!("http://{PROXY_ADDR}/submit"))
        .typed_header(ContentType::form_url_encoded())
        .body(payload.to_owned())
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    // Request line and the form-encoded body should survive the round trip.
    assert!(
        body.contains("POST /submit"),
        "expected POST request line in body; body = {body:?}"
    );
    assert!(
        body.contains(payload),
        "expected request body to be echoed back through FastCGI; body = {body:?}"
    );
}
