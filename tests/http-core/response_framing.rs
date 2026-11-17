//! Response framing fields (`Content-Length`, `Transfer-Encoding`) as they reach the wire,
//! checked against one table for HTTP/1.1 and HTTP/2 servers.

use std::{convert::Infallible, time::Duration};

use rama::{
    ServiceInput,
    bytes::Bytes,
    futures::stream,
    graceful::WeakScope,
    http::{
        Body, Method, Request, Response, StatusCode,
        core::{
            client::conn::http2 as client_http2,
            h2,
            server::conn::{http1, http2},
            service::RamaHttpService,
        },
    },
    net::uri::Uri,
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Clone, Copy)]
enum Payload {
    Empty,
    /// A body of known length.
    Known(&'static [u8]),
    /// A body of unknown length.
    Streamed(&'static [u8]),
}

#[derive(Debug, Clone, Copy)]
struct Case {
    method: &'static str,
    status: u16,
    fields: &'static [(&'static str, &'static str)],
    payload: Payload,
    /// `Content-Length` on the wire, for HTTP/1.1 then HTTP/2.
    h1: Option<&'static str>,
    h2: Option<&'static str>,
}

const CASES: &[Case] = &[
    // HEAD describes the GET without inventing a length.
    case("HEAD", 200, &[], Payload::Empty, None, None),
    case(
        "HEAD",
        200,
        &[],
        Payload::Known(b"hello world"),
        Some("11"),
        Some("11"),
    ),
    case(
        "HEAD",
        200,
        &[("content-length", "1234")],
        Payload::Empty,
        Some("1234"),
        Some("1234"),
    ),
    case("HEAD", 404, &[], Payload::Empty, None, None),
    // A known body advertises its length; HTTP/2 frames an empty one by END_STREAM alone.
    case(
        "GET",
        200,
        &[],
        Payload::Known(b"hello"),
        Some("5"),
        Some("5"),
    ),
    case("GET", 200, &[], Payload::Empty, Some("0"), None),
    case("GET", 200, &[], Payload::Streamed(b"hello"), None, None),
    // A known body frames itself: a declared length it does not have is rewritten.
    case(
        "GET",
        200,
        &[("content-length", "10")],
        Payload::Known(b"hello"),
        Some("5"),
        Some("5"),
    ),
    case(
        "GET",
        200,
        &[("content-length", "10")],
        Payload::Empty,
        Some("0"),
        Some("0"),
    ),
    // 204 never carries a length, even one the service set.
    case(
        "GET",
        204,
        &[("content-length", "10")],
        Payload::Empty,
        None,
        None,
    ),
    case(
        "GET",
        204,
        &[("content-length", "10")],
        Payload::Known(b"discard"),
        None,
        None,
    ),
    case(
        "GET",
        304,
        &[("content-length", "1234")],
        Payload::Known(b"discard"),
        Some("1234"),
        Some("1234"),
    ),
    // 304 keeps a declared length (that of the selected representation), never invents one.
    case(
        "GET",
        304,
        &[("content-length", "1234")],
        Payload::Empty,
        Some("1234"),
        Some("1234"),
    ),
    case("GET", 304, &[], Payload::Empty, None, None),
    // A 2xx to CONNECT drops framing fields as a tunnel follows; a rejection keeps them.
    case(
        "CONNECT",
        200,
        &[("content-length", "0")],
        Payload::Empty,
        None,
        None,
    ),
    case(
        "CONNECT",
        200,
        &[("content-length", "5")],
        Payload::Known(b"bytes"),
        None,
        None,
    ),
    case(
        "CONNECT",
        200,
        &[("transfer-encoding", "chunked")],
        Payload::Empty,
        None,
        None,
    ),
    case(
        "CONNECT",
        407,
        &[],
        Payload::Known(b"denied"),
        Some("6"),
        Some("6"),
    ),
];

const fn case(
    method: &'static str,
    status: u16,
    fields: &'static [(&'static str, &'static str)],
    payload: Payload,
    h1: Option<&'static str>,
    h2: Option<&'static str>,
) -> Case {
    Case {
        method,
        status,
        fields,
        payload,
        h1,
        h2,
    }
}

fn response(case: Case) -> Response {
    let body = match case.payload {
        Payload::Empty => Body::empty(),
        Payload::Known(bytes) => Body::from(Bytes::from_static(bytes)),
        Payload::Streamed(bytes) => Body::from_stream(stream::iter([Ok::<_, Infallible>(
            Bytes::from_static(bytes),
        )])),
    };
    let mut builder = Response::builder().status(case.status);
    for (name, value) in case.fields {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap()
}

/// The case for a request: the `case` query parameter of its target, or for CONNECT the
/// port of its authority.
fn case_of(req: &Request) -> Case {
    let index = if req.method() == Method::CONNECT {
        req.uri().port_u16().map(usize::from)
    } else {
        req.uri().query().and_then(|query| {
            query
                .as_encoded_str()
                .strip_prefix("case=")
                .and_then(|index| index.parse().ok())
        })
    };
    CASES[index.expect("request names its case")]
}

fn is_framing(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

async fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return (String::from_utf8(buf).unwrap(), rest);
        }
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response head")
            .unwrap();
        assert_ne!(n, 0, "connection closed before the response head ended");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn http1_response_framing_follows_one_rule() {
    for (index, case) in CASES.iter().copied().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = RamaHttpService::new(service_fn(async |req: Request| {
                Ok::<_, Infallible>(response(case_of(&req)))
            }));
            _ = http1::Builder::new()
                .serve_connection(ServiceInput::new(socket), svc)
                .with_upgrades()
                .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let target = if case.method == "CONNECT" {
            // The case index travels as the port of the authority-form target.
            format!("localhost:{index}")
        } else {
            format!("/?case={index}")
        };
        let request = format!(
            "{} {target} HTTP/1.1\r\nhost: localhost\r\n\r\n",
            case.method
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let (head, rest) = read_head(&mut stream).await;
        let mut lines = head.lines();
        let status_line = lines.next().unwrap();
        assert!(
            status_line.starts_with(&format!("HTTP/1.1 {}", case.status)),
            "{case:?}: {status_line}"
        );
        let framing: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(": "))
            .filter(|(name, _)| is_framing(name))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
            .collect();
        match case.h1 {
            Some(length) => assert_eq!(
                framing,
                [("content-length".to_owned(), length.to_owned())],
                "{case:?}"
            ),
            None => assert!(
                framing.iter().all(|(name, _)| name != "content-length"),
                "{case:?}: {framing:?}"
            ),
        }
        if case.method == "CONNECT" && (200..300).contains(&case.status) {
            assert!(framing.is_empty(), "{case:?}: tunnel without framing");
            assert!(rest.is_empty(), "{case:?}: no body before the tunnel");
        }
        drop(stream);
        server.abort();
    }
}

#[tokio::test]
async fn http2_response_framing_follows_one_rule() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let svc = RamaHttpService::new(service_fn(async |req: Request| {
            Ok::<_, Infallible>(response(case_of(&req)))
        }));
        _ = http2::Builder::new(WeakScope::detached())
            .serve_connection(ServiceInput::new(socket), svc)
            .await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let (client, connection) = h2::client::handshake(ServiceInput::new(tcp)).await.unwrap();
    tokio::spawn(connection);
    let mut client = client.ready().await.unwrap();

    for (index, case) in CASES.iter().copied().enumerate() {
        let request = if case.method == "CONNECT" {
            Request::connect(Uri::parse_authority_form(format!("localhost:{index}")).unwrap())
                .body(())
                .unwrap()
        } else {
            Request::builder()
                .method(Method::from_bytes(case.method.as_bytes()).unwrap())
                .uri(format!("https://localhost/?case={index}"))
                .body(())
                .unwrap()
        };
        let tunnel = case.method == "CONNECT";
        let (response, _send) = client.send_request(request, !tunnel).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("response")
            .unwrap_or_else(|err| panic!("{case:?}: {err}"));
        assert_eq!(
            response.status(),
            StatusCode::from_u16(case.status).unwrap()
        );
        let length = response
            .headers()
            .get("content-length")
            .map(|value| value.to_str().unwrap().to_owned());
        assert_eq!(length.as_deref(), case.h2, "{case:?}");
        assert!(
            !response.headers().contains_key("transfer-encoding"),
            "{case:?}"
        );
        if case.method == "HEAD" || matches!(case.status, 204 | 304) {
            assert!(
                response.body().is_end_stream(),
                "{case:?}: bodyless response must end at headers"
            );
        }
        client = client.ready().await.unwrap();
    }
}

#[tokio::test]
async fn http2_strict_connect_rejects_both_framing_fields() {
    for (name, value) in [("content-length", "0"), ("transfer-encoding", "chunked")] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = RamaHttpService::new(service_fn(move |_: Request| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(name, value)
                        .body(Body::empty())
                        .unwrap(),
                )
            }));
            _ = http2::Builder::new(WeakScope::detached())
                .with_strict_connect_framing(true)
                .serve_connection(ServiceInput::new(socket), svc)
                .await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (client, connection) = h2::client::handshake(ServiceInput::new(tcp)).await.unwrap();
        let driver = tokio::spawn(connection);
        let mut client = client.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::parse_http_request_target("localhost:443", true).unwrap())
            .body(())
            .unwrap();
        let (response, _send) = client.send_request(request, false).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::INTERNAL_ERROR), "{name}");
        driver.abort();
        server.abort();
    }
}

#[tokio::test]
async fn http1_strict_connect_rejects_both_framing_fields() {
    for (name, value) in [("content-length", "0"), ("transfer-encoding", "chunked")] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = RamaHttpService::new(service_fn(move |_: Request| async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(name, value)
                        .body(Body::empty())
                        .unwrap(),
                )
            }));
            http1::Builder::new()
                .with_strict_connect_framing(true)
                .serve_connection(ServiceInput::new(socket), svc)
                .with_upgrades()
                .await
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nhost: localhost:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !response.starts_with(b"HTTP/1.1 200"),
            "{name}: strict mode never opens the tunnel: {}",
            String::from_utf8_lossy(&response)
        );
        let result = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "{name}: the refused framing fails the connection"
        );
    }
}

/// A streamed body of `body` declared as 5 bytes long.
fn streamed_with_length_five(body: &'static [u8]) -> Response {
    Response::builder()
        .header("content-length", "5")
        .body(Body::from_stream(stream::iter([Ok::<_, Infallible>(
            Bytes::from_static(body),
        )])))
        .unwrap()
}

/// A streamed body longer or shorter than its declared length is never sent past it nor
/// ended cleanly: the connection closes and the server reports the error.
#[tokio::test]
async fn http1_streamed_body_not_matching_its_content_length_closes_the_connection() {
    // a chunk past the declared length is not sent at all
    for (body, sent) in [(&b"hello world"[..], &b""[..]), (b"hi", b"hi")] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = RamaHttpService::new(service_fn(async move |_req: Request| {
                Ok::<_, Infallible>(streamed_with_length_five(body))
            }));
            http1::Builder::new()
                .serve_connection(ServiceInput::new(socket), svc)
                .await
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let (head, mut rest) = read_head(&mut stream).await;
        assert!(head.contains("content-length: 5"), "{head}");
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
            .await
            .expect("the connection closes")
            .unwrap();
        assert_eq!(rest, sent);
        let served = server.await.unwrap();
        assert!(served.is_err(), "{body:?}: the mismatch is reported");
    }
}

/// A streamed body longer or shorter than its declared length is never sent past it nor
/// ended cleanly: the stream is reset and the connection serves on.
#[tokio::test]
async fn http2_streamed_body_not_matching_its_content_length_resets_the_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let svc = RamaHttpService::new(service_fn(async |req: Request| {
            let body: &'static [u8] = if req.uri().to_string().ends_with("/long") {
                b"hello world"
            } else {
                b"hi"
            };
            Ok::<_, Infallible>(streamed_with_length_five(body))
        }));
        _ = http2::Builder::new(WeakScope::detached())
            .serve_connection(ServiceInput::new(socket), svc)
            .await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let (client, connection) = h2::client::handshake(ServiceInput::new(tcp)).await.unwrap();
    tokio::spawn(connection);
    let mut client = client.ready().await.unwrap();
    for path in ["/long", "/short", "/long"] {
        let request = Request::builder()
            .uri(format!("https://localhost{path}"))
            .body(())
            .unwrap();
        let (response, _send) = client.send_request(request, true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("response");
        // a reset may overtake the response head that was still queued
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                assert_eq!(error.reason(), Some(h2::Reason::INTERNAL_ERROR), "{path}");
                client = client.ready().await.unwrap();
                continue;
            }
        };
        assert_eq!(response.headers()["content-length"], "5");
        let mut body = response.into_body();
        let mut received = 0;
        let error = loop {
            match body.data().await {
                Some(Ok(chunk)) => {
                    received += chunk.len();
                    _ = body.flow_control().release_capacity(chunk.len());
                }
                Some(Err(error)) => break error,
                None => panic!("{path}: ended cleanly after {received} bytes"),
            }
        };
        assert!(received <= 5, "{path}: {received} bytes");
        assert_eq!(error.reason(), Some(h2::Reason::INTERNAL_ERROR), "{path}");
        client = client.ready().await.unwrap();
    }
}

/// A request body of known length frames itself: a declared length it does not have is
/// rewritten before the head is sent.
#[tokio::test]
async fn http2_request_content_length_follows_a_known_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut conn = h2::server::handshake(ServiceInput::new(socket))
            .await
            .unwrap();
        let (request, mut respond) = conn.accept().await.unwrap().unwrap();
        // The body only makes progress while the connection is polled.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });
        let length = request.headers()["content-length"].clone();
        let mut body = request.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            _ = body.flow_control().release_capacity(chunk.len());
            received.extend_from_slice(&chunk);
        }
        respond.send_response(Response::new(()), true).unwrap();
        (length, received)
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut client, connection) = client_http2::Builder::new(WeakScope::detached())
        .handshake(ServiceInput::new(tcp))
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = Request::builder()
        .method(Method::POST)
        .uri("https://localhost/")
        .header("content-length", "10")
        .body(Body::from(Bytes::from_static(b"hey")))
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (length, received) = origin.await.unwrap();
    assert_eq!(length, "3");
    assert_eq!(received, b"hey");
}
