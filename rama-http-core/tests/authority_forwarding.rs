#![expect(clippy::unwrap_used, reason = "test fixtures")]

use std::str::from_utf8;

use rama_core::{ServiceInput, extensions::ExtensionsRef as _, graceful::WeakScope};
use rama_http_core::{
    client::conn::{http1, http2},
    h2::{client, server},
};
use rama_http_types::{
    Body, HeaderName, HeaderValue, Request, Response, Version, header, proto::RequestHeaders,
};
use rama_utils::octets::kib;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

fn request(host: &'static str, nominated: bool) -> Request<Body> {
    let mut request = Request::builder()
        .uri("https://gateway.test/")
        .body(Body::empty())
        .unwrap();
    request.headers_mut().append(
        HeaderName::from_static("X-First"),
        HeaderValue::from_static("first"),
    );
    let mut value = HeaderValue::from_static(host);
    value.set_sensitive(true);
    request
        .headers_mut()
        .append(HeaderName::from_static("hOsT"), value);
    request.headers_mut().append(
        HeaderName::from_static("X-Last"),
        HeaderValue::from_static("last"),
    );
    if nominated {
        request
            .headers_mut()
            .append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        request.headers_mut().append(
            HeaderName::from_static("cOnNeCtIoN"),
            HeaderValue::from_static("Host"),
        );
    }
    request
}

#[tokio::test(start_paused = true)]
async fn h1_public_send_uses_a_forwardable_host_in_wire_form() {
    for (host, nominated, expected) in [
        (" \tother.test\t ", false, "other.test"),
        (" 2001:db8::1 ", false, "[2001:db8::1]"),
        ("other.test", true, "gateway.test"),
    ] {
        let (client_io, mut origin) = duplex(kib(64));
        let (mut client, driver) = http1::handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        let driver = tokio::spawn(driver);
        let sent = client.send_request(request(host, nominated));
        let mut wire = Vec::new();
        while !wire.ends_with(b"\r\n\r\n") {
            wire.push(origin.read_u8().await.unwrap());
        }
        let wire = from_utf8(&wire).unwrap();
        let fields: Vec<_> = wire
            .split("\r\n")
            .filter_map(|line| line.split_once(": "))
            .collect();
        let positions: Vec<_> = fields
            .iter()
            .filter(|(name, _)| ["X-First", "hOsT", "X-Last"].contains(name))
            .copied()
            .collect();
        assert_eq!(
            positions,
            [("X-First", "first"), ("hOsT", expected), ("X-Last", "last")]
        );
        origin
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        sent.await.unwrap();
        drop(client);
        drop(origin);
        _ = driver.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn h2_low_level_public_send_accepts_trimmed_and_ip_hosts() {
    for (host, expected) in [
        (" \tother.test\t ", "other.test"),
        (" 2001:db8::1 ", "[2001:db8::1]"),
    ] {
        let (client_io, origin) = duplex(kib(64));
        let origin = tokio::spawn(async move {
            let mut server = server::handshake(ServiceInput::new(origin)).await.unwrap();
            let (request, mut response) = server.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().authority().unwrap().to_string(), expected);
            let fields: Vec<_> = request
                .headers()
                .ordered_iter()
                .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
                .collect();
            let expected_fields = [("x-first", "first"), ("host", expected), ("x-last", "last")];
            assert_eq!(fields, expected_fields);
            assert!(request.headers()[header::HOST].is_sensitive());
            response.send_response(Response::new(()), true).unwrap();
            while server.accept().await.is_some() {}
        });
        let (mut client, driver) = client::handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        let driver = tokio::spawn(driver);
        let (response, _) = client
            .send_request(request(host, false).map(|_| ()), true)
            .unwrap();
        response.await.unwrap();
        drop(client);
        driver.abort();
        origin.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn h2_low_level_rejects_padded_hosts_without_authority_projection() {
    for host in [" other.test", "other.test ", "\tother.test\t"] {
        let (client_io, _origin) = duplex(kib(64));
        let (mut client, _driver) = client::handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        let request = Request::builder()
            .version(Version::HTTP_11)
            .uri("/path")
            .header(header::HOST, host)
            .body(())
            .unwrap();
        client
            .send_request(request, true)
            .expect_err("an unprojected padded Host must be rejected");
    }
}

#[tokio::test(start_paused = true)]
async fn h2_proto_public_send_preserves_the_forwarded_order_and_spelling() {
    let (client_io, origin) = duplex(kib(64));
    let origin = tokio::spawn(async move {
        let mut server = server::handshake(ServiceInput::new(origin)).await.unwrap();
        let (request, mut response) = server.accept().await.unwrap().unwrap();
        assert_eq!(
            request.uri().authority().unwrap().to_string(),
            "gateway.test"
        );
        let fields: Vec<_> = request
            .headers()
            .ordered_iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
            .collect();
        assert_eq!(fields, [("x-first", "first"), ("x-last", "last")]);
        response.send_response(Response::new(()), true).unwrap();
        while server.accept().await.is_some() {}
    });
    let (mut client, driver) = http2::Builder::new(WeakScope::detached())
        .handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let response = client
        .send_request(request("other.test", true))
        .await
        .unwrap();
    let recorded = response.extensions().get_ref::<RequestHeaders>().unwrap();
    let names: Vec<_> = recorded
        .ordered_iter()
        .map(|(name, _)| name.as_original_str())
        .collect();
    assert_eq!(names, ["X-First", "X-Last"]);
    drop(client);
    driver.abort();
    origin.abort();
}
