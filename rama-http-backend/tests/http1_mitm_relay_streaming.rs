//! HTTP/1 relay framing contracts, exercised with raw peers over in-memory IO.
//! The origin deliberately keeps responses open so collecting a body or waiting
//! for TCP EOF cannot accidentally hide a streaming regression. All clocks are
//! paused: timeouts are watchdogs, and pending-read checks take no wall time.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers must fail immediately on invalid wire data, IO errors, or stalled tasks"
)]

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{
    Service, ServiceInput,
    error::BoxError,
    io::BridgeIo,
    layer::{ArcLayer, MapOutputLayer},
    rt::Executor,
};
use rama_http::{HeaderValue, Response, header, layer::map_response_body::MapResponseBodyLayer};
use rama_http_backend::proxy::mitm::HttpMitmRelay;
use rama_net::test_utils::client::MockSocket;
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream, ReadBuf,
    },
    sync::oneshot,
    task::JoinHandle,
    time::{advance, timeout},
};

const WATCHDOG: Duration = Duration::from_secs(2);
const PENDING_WINDOW: Duration = Duration::from_millis(1);

// A read failure differs from a clean FIN for a close-delimited response. The
// signal lets the fixture inject it only after the client has received data.
struct ReadFailureIo {
    inner: DuplexStream,
    fail: oneshot::Receiver<()>,
    failed: bool,
}

impl AsyncRead for ReadFailureIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.failed
            && let Poll::Ready(result) = Pin::new(&mut self.fail).poll(cx)
        {
            result.expect("failure sender dropped before the relay finished");
            self.failed = true;
        }
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected upstream read failure",
            )));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReadFailureIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Relay {
    client: BufReader<DuplexStream>,
    upstream: BufReader<DuplexStream>,
    fail_upstream: Option<oneshot::Sender<()>>,
    done: JoinHandle<Result<(), BoxError>>,
}

impl Relay {
    fn new() -> Self {
        Self::with_response_transform(|resp| resp)
    }

    fn with_response_transform(transform: fn(Response) -> Response) -> Self {
        Self::with_configuration(false, transform)
    }

    fn with_default_middleware() -> Self {
        Self::with_configuration(true, |resp| resp)
    }

    fn with_configuration(default_middleware: bool, transform: fn(Response) -> Response) -> Self {
        let (client, ingress) = tokio::io::duplex(4096);
        let (egress, upstream) = tokio::io::duplex(4096);
        let (fail_upstream, fail) = oneshot::channel();
        let done = tokio::spawn(async move {
            let io = BridgeIo(
                MockSocket::new(ingress),
                ServiceInput::new(ReadFailureIo {
                    inner: egress,
                    fail,
                    failed: false,
                }),
            );
            let relay = HttpMitmRelay::new(Executor::new());
            if default_middleware {
                relay.serve(io).await
            } else {
                // Preserve streaming without replacing egress errors with responses.
                relay
                    .with_http_middleware((
                        MapOutputLayer::new(transform),
                        MapResponseBodyLayer::new_boxed_streaming_body(),
                        ArcLayer::new(),
                    ))
                    .serve(io)
                    .await
            }
        });
        Self {
            client: BufReader::new(client),
            upstream: BufReader::new(upstream),
            fail_upstream: Some(fail_upstream),
            done,
        }
    }

    async fn request(&mut self, version: &str, method: &str, body: &[u8]) {
        let head = format!(
            "{method} / HTTP/{version}\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        write(self.client.get_mut(), head.as_bytes()).await;
        write(self.client.get_mut(), body).await;
        let forwarded = read_head(&mut self.upstream).await;
        assert!(
            forwarded.starts_with(&format!("{method} / HTTP/{version}\r\n")),
            "{forwarded}"
        );
        assert_eq!(read_bytes(&mut self.upstream, body.len()).await, body);
    }

    async fn response_head(&mut self, version: &str, headers: &str) -> String {
        write(
            self.upstream.get_mut(),
            format!("HTTP/{version} 200 OK\r\n{headers}\r\n").as_bytes(),
        )
        .await;
        read_head(&mut self.client).await
    }

    async fn finish(mut self, expect_error: bool) {
        if expect_error {
            // The fault must terminate the relay without fixture teardown causing it.
            timeout(WATCHDOG, &mut self.done)
                .await
                .expect("upstream fault did not terminate the relay")
                .expect("relay task panicked")
                .expect_err("upstream fault was swallowed");
            return;
        }
        drop(self.client);
        drop(self.upstream);
        // Keep the failure sender alive while the connection tasks finish.
        let result = timeout(WATCHDOG, self.done)
            .await
            .expect("relay task hung")
            .expect("relay task panicked");
        assert_eq!(result.is_err(), expect_error, "relay result: {result:?}");
    }
}

async fn write(io: &mut DuplexStream, bytes: &[u8]) {
    timeout(WATCHDOG, io.write_all(bytes))
        .await
        .expect("write stalled")
        .unwrap();
}

async fn read_head(io: &mut BufReader<DuplexStream>) -> String {
    timeout(WATCHDOG, async {
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            assert_ne!(
                io.read_line(&mut head).await.unwrap(),
                0,
                "EOF before complete head: {head:?}"
            );
            assert!(head.len() < 4096, "unexpectedly large head");
        }
        head
    })
    .await
    .expect("head stalled")
}

async fn read_bytes(io: &mut BufReader<DuplexStream>, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    timeout(WATCHDOG, io.read_exact(&mut bytes))
        .await
        .expect("body stalled")
        .unwrap();
    bytes
}

async fn assert_no_output(io: &mut BufReader<DuplexStream>) {
    let mut byte = [0];
    assert!(
        timeout(PENDING_WINDOW, io.read(&mut byte)).await.is_err(),
        "unexpected bytes, EOF, or read error before response completion"
    );
}

fn assert_framing(head: &str, version: &str, chunked: bool, length: Option<usize>) {
    assert!(
        head.starts_with(&format!("HTTP/{version} 200 OK\r\n")),
        "{head:?}"
    );
    let head = head.to_ascii_lowercase();
    assert_eq!(
        head.contains("transfer-encoding: chunked\r\n"),
        chunked,
        "{head:?}"
    );
    match length {
        Some(n) => assert!(
            head.contains(&format!("content-length: {n}\r\n")),
            "{head:?}"
        ),
        None => assert!(!head.contains("content-length:"), "{head:?}"),
    }
}

// Decode the wire ourselves: using Rama as both endpoint parsers could hide a
// shared bug. Chunk boundaries are deliberately not asserted.
async fn assert_payload(io: &mut BufReader<DuplexStream>, expected: &[u8], chunked: bool) {
    if !chunked {
        assert_eq!(read_bytes(io, expected.len()).await, expected);
        return;
    }
    let mut body = Vec::new();
    while body.len() < expected.len() {
        let mut line = String::new();
        timeout(WATCHDOG, io.read_line(&mut line))
            .await
            .expect("chunk size stalled")
            .unwrap();
        assert!(line.ends_with("\r\n"), "invalid chunk-size line: {line:?}");
        let len = usize::from_str_radix(line.trim_end().split(';').next().unwrap(), 16).unwrap();
        assert!(len > 0, "response terminated before the expected payload");
        assert!(
            len <= expected.len() - body.len(),
            "unexpected payload length"
        );
        body.extend(read_bytes(io, len).await);
        assert_eq!(read_bytes(io, 2).await, b"\r\n");
    }
    assert_eq!(body, expected);
}

async fn assert_eof(io: &mut BufReader<DuplexStream>) {
    let mut byte = [0];
    assert_eq!(
        timeout(WATCHDOG, io.read(&mut byte))
            .await
            .expect("EOF stalled")
            .unwrap(),
        0,
        "unexpected trailing bytes"
    );
}

#[tokio::test(start_paused = true)]
async fn close_delimited_response_version_matrix_streams_until_eof() {
    for (client_version, origin_version, connection) in [
        ("1.0", "1.0", ""),
        ("1.0", "1.1", ""),
        ("1.1", "1.0", ""),
        ("1.1", "1.1", ""),
        ("1.1", "1.0", "Connection: keep-alive\r\n"),
        ("1.1", "1.1", "Connection: close\r\n"),
    ] {
        let mut relay = Relay::new();
        relay.request(client_version, "POST", b"PING").await;
        // Headers arrive separately from the payload. Even a response with no
        // body bytes yet must be forwarded without waiting for origin EOF.
        let head = relay.response_head(origin_version, connection).await;
        let downstream_version = if client_version == "1.0" {
            "1.0"
        } else {
            origin_version
        };
        let chunked = false;
        assert_framing(&head, downstream_version, chunked, None);
        if connection.contains("close") {
            assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
        }
        assert_no_output(&mut relay.client).await;
        for fragment in [b"first".as_slice(), b"second".as_slice()] {
            write(relay.upstream.get_mut(), fragment).await;
            assert_payload(&mut relay.client, fragment, chunked).await;
            assert_no_output(&mut relay.client).await;
        }
        // Inactivity cannot manufacture an HTTP message boundary. This is
        // virtual time, not a real 31-second test.
        advance(Duration::from_secs(31)).await;
        assert_no_output(&mut relay.client).await;
        relay.upstream.get_mut().shutdown().await.unwrap();
        assert_eof(&mut relay.client).await;
        relay.finish(false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn length_response_then_close_delimited_response_on_same_connection() {
    let mut relay = Relay::new();
    relay.request("1.1", "POST", b"PING").await;
    let head = relay.response_head("1.1", "Content-Length: 4\r\n").await;
    assert_framing(&head, "1.1", false, Some(4));
    write(relay.upstream.get_mut(), b"PO").await;
    assert_payload(&mut relay.client, b"PO", false).await;
    assert_no_output(&mut relay.client).await;
    write(relay.upstream.get_mut(), b"NG").await;
    assert_payload(&mut relay.client, b"NG", false).await;
    // This request must reach upstream without closing either socket.
    relay.request("1.1", "POST", b"second request").await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", false, None);
    write(relay.upstream.get_mut(), b"second response").await;
    assert_payload(&mut relay.client, b"second response", false).await;
    assert_no_output(&mut relay.client).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    assert_eof(&mut relay.client).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn chunked_response_completes_without_upstream_eof() {
    let mut relay = Relay::new();
    relay.request("1.1", "POST", b"PING").await;
    let head = relay
        .response_head("1.1", "Transfer-Encoding: chunked\r\n")
        .await;
    assert_framing(&head, "1.1", true, None);
    // Split upstream chunk framing across writes as well as body fragments.
    write(relay.upstream.get_mut(), b"4\r").await;
    assert_no_output(&mut relay.client).await;
    write(relay.upstream.get_mut(), b"\nPONG\r\n").await;
    assert_payload(&mut relay.client, b"PONG", true).await;
    assert_no_output(&mut relay.client).await;
    write(relay.upstream.get_mut(), b"0\r\n\r\n").await;
    assert_eq!(read_bytes(&mut relay.client, 5).await, b"0\r\n\r\n");
    // The terminator, not TCP EOF, permits the next exchange.
    relay.request("1.1", "POST", b"next").await;
    let head = relay.response_head("1.1", "Content-Length: 0\r\n").await;
    assert_framing(&head, "1.1", false, Some(0));
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn http10_client_receives_decoded_chunked_origin_body() {
    let mut relay = Relay::new();
    relay.request("1.0", "POST", b"PING").await;
    let head = relay
        .response_head("1.1", "Transfer-Encoding: chunked\r\n")
        .await;
    assert_framing(&head, "1.0", false, None);
    write(relay.upstream.get_mut(), b"4\r\nPONG\r\n").await;
    assert_payload(&mut relay.client, b"PONG", false).await;
    assert_no_output(&mut relay.client).await;
    write(relay.upstream.get_mut(), b"0\r\n\r\n").await;
    assert_eof(&mut relay.client).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn client_write_eof_preserves_pending_response() {
    for before_headers in [true, false] {
        for headers in [
            "",
            "Content-Length: 9\r\n",
            "Transfer-Encoding: chunked\r\n",
        ] {
            let mut relay = Relay::new();
            relay.request("1.1", "POST", b"PING").await;
            if before_headers {
                relay.client.get_mut().shutdown().await.unwrap();
                assert_no_output(&mut relay.client).await;
            }
            let head = relay.response_head("1.1", headers).await;
            let chunked = headers.starts_with("Transfer-Encoding");
            let origin_chunked = headers.starts_with("Transfer-Encoding");
            assert_framing(
                &head,
                "1.1",
                chunked,
                if headers.starts_with("Content-Length") {
                    Some(9)
                } else {
                    None
                },
            );
            write(
                relay.upstream.get_mut(),
                if origin_chunked {
                    b"5\r\nfirst\r\n"
                } else {
                    b"first"
                },
            )
            .await;
            assert_payload(&mut relay.client, b"first", chunked).await;
            if !before_headers {
                relay.client.get_mut().shutdown().await.unwrap();
            }
            assert_no_output(&mut relay.client).await;
            assert!(
                !relay.done.is_finished(),
                "client FIN discarded the pending response"
            );
            write(
                relay.upstream.get_mut(),
                if origin_chunked {
                    b"4\r\nlast\r\n"
                } else {
                    b"last"
                },
            )
            .await;
            assert_payload(&mut relay.client, b"last", chunked).await;
            if headers.is_empty() {
                relay.upstream.get_mut().shutdown().await.unwrap();
            } else if origin_chunked {
                write(relay.upstream.get_mut(), b"0\r\n\r\n").await;
            }
            if chunked {
                assert_eq!(read_bytes(&mut relay.client, 5).await, b"0\r\n\r\n");
            }
            // Length/chunk framing completes even while upstream stays open.
            assert_eof(&mut relay.client).await;
            relay.finish(false).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn upstream_body_errors_terminate_relay_without_extra_bytes() {
    for (headers, prefix, chunked, read_error) in [
        ("Content-Length: 8\r\n", b"PONG".as_slice(), false, false),
        (
            "Transfer-Encoding: chunked\r\n",
            b"4\r\nPONG\r\n".as_slice(),
            true,
            false,
        ),
        ("", b"PONG".as_slice(), false, true),
    ] {
        let mut relay = Relay::new();
        relay.request("1.1", "POST", b"PING").await;
        let head = relay.response_head("1.1", headers).await;
        assert_framing(
            &head,
            "1.1",
            chunked,
            if headers.starts_with("Content-Length") {
                Some(8)
            } else {
                None
            },
        );
        write(relay.upstream.get_mut(), prefix).await;
        assert_payload(&mut relay.client, b"PONG", chunked).await;
        assert_no_output(&mut relay.client).await;
        if read_error {
            relay.fail_upstream.take().unwrap().send(()).unwrap();
        } else {
            relay.upstream.get_mut().shutdown().await.unwrap();
        }
        // No terminal chunk, synthetic second response, or padding to Content-Length.
        // With EOF framing the downstream cannot distinguish truncation from
        // completion, but the relay must still report the upstream read error.
        assert_eof(&mut relay.client).await;
        relay.finish(true).await;
    }
}

#[tokio::test(start_paused = true)]
async fn bodyless_responses_do_not_wait_for_upstream_eof() {
    for (method, status, headers, length) in [
        ("HEAD", "200 OK", "", None),
        ("HEAD", "200 OK", "Content-Length: 42\r\n", Some(42)),
        ("HEAD", "200 OK", "Transfer-Encoding: chunked\r\n", None),
        ("GET", "204 No Content", "", None),
        ("GET", "204 No Content", "Content-Length: 0\r\n", None),
        ("GET", "304 Not Modified", "", None),
        (
            "GET",
            "304 Not Modified",
            "Content-Length: 42\r\n",
            Some(42),
        ),
    ] {
        let mut relay = Relay::new();
        relay.request("1.1", method, b"").await;
        write(
            relay.upstream.get_mut(),
            format!("HTTP/1.1 {status}\r\n{headers}\r\n").as_bytes(),
        )
        .await;
        let head = read_head(&mut relay.client).await;
        assert!(
            head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
            "{head:?}"
        );
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("transfer-encoding:"));
        if let Some(length) = length {
            // HEAD representation metadata is forwarded. For 304, the codec
            // currently omits this optional field; if emitted, it must describe
            // the selected representation rather than this empty message body.
            if method == "HEAD" || lower.contains("content-length:") {
                assert!(
                    lower.contains(&format!("content-length: {length}\r\n")),
                    "{head:?}"
                );
            }
        } else if status.starts_with("204") {
            assert!(!lower.contains("content-length:"));
        }
        assert_no_output(&mut relay.client).await;
        // No body framing is needed to accept the next request on this pair.
        relay.request("1.1", "POST", b"next").await;
        let head = relay.response_head("1.1", "Content-Length: 0\r\n").await;
        assert_framing(&head, "1.1", false, Some(0));
        relay.finish(false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn preserved_close_delimited_responses_stream_until_eof_with_half_close() {
    for (client_version, origin_version) in [
        ("1.0", "1.0"),
        ("1.0", "1.1"),
        ("1.1", "1.0"),
        ("1.1", "1.1"),
    ] {
        for fin in [0, 1, 2] {
            let mut relay = Relay::new();
            relay.request(client_version, "POST", b"PING").await;
            if fin == 1 {
                relay.client.get_mut().shutdown().await.unwrap();
            }
            let head = relay.response_head(origin_version, "").await;
            let downstream_version = if client_version == "1.0" {
                "1.0"
            } else {
                origin_version
            };
            assert_framing(&head, downstream_version, false, None);
            assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
            assert_no_output(&mut relay.client).await;
            write(relay.upstream.get_mut(), b"first").await;
            assert_payload(&mut relay.client, b"first", false).await;
            if fin == 2 {
                relay.client.get_mut().shutdown().await.unwrap();
            }
            advance(Duration::from_secs(31)).await;
            assert_no_output(&mut relay.client).await;
            write(relay.upstream.get_mut(), b"last").await;
            assert_payload(&mut relay.client, b"last", false).await;
            assert_no_output(&mut relay.client).await;
            relay.upstream.get_mut().shutdown().await.unwrap();
            assert_eof(&mut relay.client).await;
            relay.finish(false).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn preserved_close_delimited_response_can_be_empty() {
    let mut relay = Relay::new();
    relay.request("1.1", "GET", b"").await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", false, None);
    assert_no_output(&mut relay.client).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    assert_eof(&mut relay.client).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn preservation_leaves_explicit_framing_reusable_until_close_delimited_response() {
    let mut relay = Relay::new();
    for (headers, wire_body, chunked, length) in [
        ("Content-Length: 4\r\n", b"PONG".as_slice(), false, Some(4)),
        (
            "Transfer-Encoding: chunked\r\n",
            b"4\r\nPONG\r\n".as_slice(),
            true,
            None,
        ),
    ] {
        relay.request("1.1", "POST", b"PING").await;
        let head = relay.response_head("1.1", headers).await;
        assert_framing(&head, "1.1", chunked, length);
        assert!(!head.to_ascii_lowercase().contains("connection: close"));
        write(relay.upstream.get_mut(), wire_body).await;
        assert_payload(&mut relay.client, b"PONG", chunked).await;
        if chunked {
            write(relay.upstream.get_mut(), b"0\r\n\r\n").await;
            assert_eq!(read_bytes(&mut relay.client, 5).await, b"0\r\n\r\n");
        }
    }
    relay.request("1.1", "POST", b"last").await;
    let head = relay
        .response_head("1.1", "Connection: keep-alive\r\n")
        .await;
    assert_framing(&head, "1.1", false, None);
    assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
    // A pipelined request must not be forwarded after this response.
    write(
        relay.client.get_mut(),
        b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    write(relay.upstream.get_mut(), b"last response").await;
    assert_payload(&mut relay.client, b"last response", false).await;
    assert_no_output(&mut relay.upstream).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    assert_eof(&mut relay.client).await;
    assert_eof(&mut relay.upstream).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn preserved_close_delimited_response_propagates_read_failure() {
    let mut relay = Relay::new();
    relay.request("1.1", "GET", b"").await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", false, None);
    write(relay.upstream.get_mut(), b"partial").await;
    assert_payload(&mut relay.client, b"partial", false).await;
    relay.fail_upstream.take().unwrap().send(()).unwrap();
    assert_eof(&mut relay.client).await;
    relay.finish(true).await;
}

#[tokio::test(start_paused = true)]
async fn middleware_can_explicitly_rechunk_close_delimited_response() {
    let mut relay = Relay::with_response_transform(|mut resp| {
        resp.headers_mut().insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        resp
    });
    relay.request("1.1", "GET", b"").await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", true, None);
    write(relay.upstream.get_mut(), b"first").await;
    assert_payload(&mut relay.client, b"first", true).await;
    advance(Duration::from_secs(31)).await;
    assert_no_output(&mut relay.client).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    assert_eq!(read_bytes(&mut relay.client, 5).await, b"0\r\n\r\n");
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn explicit_close_delimited_encoding_closes_for_known_and_empty_bodies() {
    use rama_core::{extensions::ExtensionsRef, service::service_fn};
    use rama_http::{Body, Request, proto::h1::ext::CloseDelimitedResponse};
    use rama_http_backend::server::HttpServer;
    use std::convert::Infallible;

    for payload in ["", "known length"] {
        let body_bytes = rama_core::bytes::Bytes::copy_from_slice(payload.as_bytes());
        let (client, server) = tokio::io::duplex(4096);
        let done = tokio::spawn(async move {
            HttpServer::auto(Executor::new())
                .serve(
                    MockSocket::new(server),
                    service_fn(move |_: Request| {
                        let resp = Response::new(Body::from(body_bytes.clone()));
                        resp.extensions().insert(CloseDelimitedResponse);
                        std::future::ready(Ok::<_, Infallible>(resp))
                    }),
                )
                .await
        });
        let mut client = BufReader::new(client);
        write(
            client.get_mut(),
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )
        .await;
        let head = read_head(&mut client).await;
        assert_framing(&head, "1.1", false, None);
        assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
        assert_eq!(
            read_bytes(&mut client, payload.len()).await,
            payload.as_bytes()
        );
        assert_eof(&mut client).await;
        timeout(WATCHDOG, done).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn middleware_can_replace_eof_framing_with_content_length() {
    let mut relay = Relay::with_response_transform(|mut resp| {
        resp.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        resp
    });
    relay.request("1.1", "GET", b"").await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", false, Some(4));
    write(relay.upstream.get_mut(), b"PONG").await;
    assert_payload(&mut relay.client, b"PONG", false).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn middleware_added_trailers_select_chunked_framing() {
    use rama_http::HeaderMap;
    let mut relay = Relay::with_response_transform(|mut resp| {
        resp.headers_mut()
            .insert(header::TRAILER, HeaderValue::from_static("x-checksum"));
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("test-value"));
        resp.map(|body| body.with_trailer_headers(trailers))
    });
    // Trailer negotiation is hop-local, so originate it explicitly on this hop.
    write(
        relay.client.get_mut(),
        b"GET / HTTP/1.1\r\nHost: example.test\r\nTE: trailers\r\nConnection: TE\r\n\r\n",
    )
    .await;
    read_head(&mut relay.upstream).await;
    let head = relay.response_head("1.1", "").await;
    assert_framing(&head, "1.1", true, None);
    write(relay.upstream.get_mut(), b"PONG").await;
    assert_payload(&mut relay.client, b"PONG", true).await;
    assert_no_output(&mut relay.client).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    let terminal = read_head(&mut relay.client).await;
    assert_eq!(
        terminal.to_ascii_lowercase(),
        "0\r\nx-checksum: test-value\r\n\r\n"
    );
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn default_middleware_streams_close_delimited_response_and_reports_body_error() {
    for fail in [false, true] {
        let mut relay = Relay::with_default_middleware();
        relay.request("1.1", "GET", b"").await;
        let head = relay.response_head("1.1", "").await;
        assert_framing(&head, "1.1", false, None);
        write(relay.upstream.get_mut(), b"first").await;
        assert_payload(&mut relay.client, b"first", false).await;
        advance(Duration::from_secs(31)).await;
        assert_no_output(&mut relay.client).await;
        if fail {
            relay.fail_upstream.take().unwrap().send(()).unwrap();
        } else {
            relay.upstream.get_mut().shutdown().await.unwrap();
        }
        assert_eof(&mut relay.client).await;
        relay.finish(fail).await;
    }
}

#[tokio::test(start_paused = true)]
async fn chunked_request_streams_before_client_finishes() {
    let mut relay = Relay::with_default_middleware();
    write(
        relay.client.get_mut(),
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await;
    let head = read_head(&mut relay.upstream).await;
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked\r\n")
    );
    for fragment in [b"first".as_slice(), b"last".as_slice()] {
        write(
            relay.client.get_mut(),
            format!("{:x}\r\n", fragment.len()).as_bytes(),
        )
        .await;
        write(relay.client.get_mut(), fragment).await;
        write(relay.client.get_mut(), b"\r\n").await;
        assert_payload(&mut relay.upstream, fragment, true).await;
        assert_no_output(&mut relay.upstream).await;
    }
    write(relay.client.get_mut(), b"0\r\n\r\n").await;
    assert_eq!(read_bytes(&mut relay.upstream, 5).await, b"0\r\n\r\n");
    relay.response_head("1.1", "Content-Length: 0\r\n").await;
    relay.request("1.1", "GET", b"").await;
    relay.response_head("1.1", "Content-Length: 0\r\n").await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn client_connection_close_finishes_response_without_upstream_eof() {
    let mut relay = Relay::with_default_middleware();
    write(
        relay.client.get_mut(),
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    read_head(&mut relay.upstream).await;
    let head = relay.response_head("1.1", "Content-Length: 4\r\n").await;
    assert_framing(&head, "1.1", false, Some(4));
    assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
    write(relay.upstream.get_mut(), b"PO").await;
    assert_payload(&mut relay.client, b"PO", false).await;
    assert_no_output(&mut relay.client).await;
    write(relay.upstream.get_mut(), b"NG").await;
    assert_payload(&mut relay.client, b"NG", false).await;
    assert_eof(&mut relay.client).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn default_middleware_replaces_invalid_upstream_length_with_complete_502() {
    let mut relay = Relay::with_default_middleware();
    relay.request("1.1", "GET", b"").await;
    write(
        relay.upstream.get_mut(),
        b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n",
    )
    .await;
    let head = read_head(&mut relay.client).await;
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.starts_with("http/1.1 502 bad gateway\r\n"),
        "{head:?}"
    );
    assert!(lower.contains("content-length: 0\r\n"), "{head:?}");
    assert!(!lower.contains("transfer-encoding:"));
    // The synthetic response is complete without origin EOF. Do not require
    // downstream closure: default error middleware does not currently request it.
    assert_eof(&mut relay.upstream).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn expect_continue_allows_incremental_request_body() {
    let mut relay = Relay::with_default_middleware();
    write(relay.client.get_mut(), b"POST / HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 9\r\n\r\n").await;
    let head = read_head(&mut relay.upstream).await;
    assert!(
        head.to_ascii_lowercase()
            .contains("expect: 100-continue\r\n")
    );
    write(relay.upstream.get_mut(), b"HTTP/1.1 100 Continue\r\n\r\n").await;
    let interim = read_head(&mut relay.client).await;
    assert!(
        interim.starts_with("HTTP/1.1 100 Continue\r\n"),
        "{interim:?}"
    );
    for fragment in [b"first".as_slice(), b"last".as_slice()] {
        write(relay.client.get_mut(), fragment).await;
        assert_payload(&mut relay.upstream, fragment, false).await;
        assert_no_output(&mut relay.upstream).await;
    }
    let head = relay.response_head("1.1", "Content-Length: 0\r\n").await;
    assert_framing(&head, "1.1", false, Some(0));
    relay.request("1.1", "GET", b"").await;
    relay.response_head("1.1", "Content-Length: 0\r\n").await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn middleware_can_upgrade_response_version_without_rechunking() {
    let mut relay = Relay::with_response_transform(|mut resp| {
        *resp.version_mut() = rama_http::Version::HTTP_11;
        resp
    });
    relay.request("1.1", "GET", b"").await;
    let head = relay
        .response_head("1.0", "Connection: keep-alive\r\n")
        .await;
    assert_framing(&head, "1.1", false, None);
    assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
    write(relay.upstream.get_mut(), b"first").await;
    assert_payload(&mut relay.client, b"first", false).await;
    assert_no_output(&mut relay.client).await;
    relay.upstream.get_mut().shutdown().await.unwrap();
    assert_eof(&mut relay.client).await;
    relay.finish(false).await;
}
