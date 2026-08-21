#![cfg(feature = "std")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    io::ErrorKind,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use rama_core::bytes::{Bytes, BytesMut};
use rama_icap::{
    client::{ClientConnection, PreviewOutcome, WriteOutcome},
    codec::{
        ChunkLineError, DEFAULT_MAX_CHUNK_LINE_BYTES, DEFAULT_MAX_HEAD_BYTES, HeadParserConfig,
        Header, ParseError, RequestLine, ResponseLine,
    },
    io::{BodyEnd, ConnectionOptions, Error},
    message::{EncapsulatedParts, Request, Response, TrailerBlock},
    proto::{EncapsulatedKind, Method, MethodKind, Preview, StatusCode, header},
    server::ServerConnection,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

struct OneByteIo<T>(T);

struct BlockPreviewTerminalFlushIo<T> {
    inner: T,
    completed_flushes: u8,
    release: Arc<AtomicBool>,
}

struct BlockPreviewTerminalWriteIo<T> {
    inner: T,
    release: Arc<AtomicBool>,
}

impl<T: AsyncRead + Unpin> AsyncRead for BlockPreviewTerminalWriteIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BlockPreviewTerminalWriteIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if input.starts_with(b"0\r\n") && !self.release.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for BlockPreviewTerminalFlushIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BlockPreviewTerminalFlushIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.completed_flushes == 2 && !self.release.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.completed_flushes = self.completed_flushes.saturating_add(1);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for OneByteIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let filled = {
            let target = output.initialize_unfilled_to(1);
            let mut limited = ReadBuf::new(target);
            match Pin::new(&mut self.0).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => limited.filled().len(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        };
        output.advance(filled);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for OneByteIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, &input[..input.len().min(1)])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn request_parts(body_kind: EncapsulatedKind) -> EncapsulatedParts {
    EncapsulatedParts::new(
        Some(Bytes::from_static(
            b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )),
        None,
        body_kind,
    )
    .unwrap()
}

fn response_parts(body_kind: EncapsulatedKind) -> EncapsulatedParts {
    EncapsulatedParts::new(
        None,
        Some(Bytes::from_static(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n",
        )),
        body_kind,
    )
    .unwrap()
}

fn request(method: Method<'_>, parts: EncapsulatedParts) -> Request {
    let line = RequestLine::new(method, "icap://icap.test/echo").unwrap();
    Request::new(
        line,
        &[Header::new("Host", b"icap.test").unwrap()],
        Some(parts),
    )
    .unwrap()
}

fn request_with_allow(method: Method<'_>, parts: EncapsulatedParts) -> Request {
    let line = RequestLine::new(method, "icap://icap.test/echo").unwrap();
    Request::new(
        line,
        &[
            Header::new("Host", b"icap.test").unwrap(),
            Header::new(header::ALLOW, b"204").unwrap(),
            Header::new(header::ALLOW, b"x-test, 206").unwrap(),
        ],
        Some(parts),
    )
    .unwrap()
}

fn preview_request(limit: u64) -> Request {
    let line = RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap();
    Request::with_preview(
        line,
        &[
            Header::new("Host", b"icap.test").unwrap(),
            Header::new("Allow", b"204, 206").unwrap(),
        ],
        request_parts(EncapsulatedKind::RequestBody),
        Preview::new(limit),
    )
    .unwrap()
}

fn response(
    method: MethodKind,
    status: StatusCode,
    reason: &'static [u8],
    parts: Option<EncapsulatedParts>,
) -> Response {
    let line = ResponseLine::new(status, reason).unwrap();
    let istag = Header::new(header::ISTAG, b"\"rama-test\"").unwrap();
    let fields = if matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
        [Some(istag)]
    } else {
        [None]
    };
    let fields: Vec<_> = fields.into_iter().flatten().collect();
    Response::new(method, line, &fields, parts).unwrap()
}

fn options_request(close: bool) -> Request {
    let line = RequestLine::new(Method::Options, "icap://icap.test/echo").unwrap();
    let host = Header::new("Host", b"icap.test").unwrap();
    let connection = Header::new("Connection", b"keep-alive, Close").unwrap();
    let fields = if close {
        [Some(host), Some(connection)]
    } else {
        [Some(host), None]
    };
    let fields: Vec<_> = fields.into_iter().flatten().collect();
    Request::new(line, &fields, Some(EncapsulatedParts::null())).unwrap()
}

fn options_response(close: bool) -> Response {
    let methods = Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap();
    let istag = Header::new(header::ISTAG, b"\"rama-test\"").unwrap();
    let connection = Header::new("Connection", b"close").unwrap();
    let fields = if close {
        [Some(methods), Some(istag), Some(connection)]
    } else {
        [Some(methods), Some(istag), None]
    };
    let fields: Vec<_> = fields.into_iter().flatten().collect();
    Response::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &fields,
        Some(EncapsulatedParts::null()),
    )
    .unwrap()
}

async fn collect_client_response<IO>(
    response: &mut rama_icap::client::ClientResponse<'_, IO>,
) -> Bytes
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut bytes = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        bytes.extend_from_slice(&data);
    }
    bytes.freeze()
}

fn assert_unexpected_eof(error: Error) {
    assert!(matches!(
        error,
        Error::Io(error) if error.kind() == ErrorKind::UnexpectedEof
    ));
}

async fn read_raw_head<IO>(io: &mut IO) -> Vec<u8>
where
    IO: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        io.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    head
}

#[tokio::test]
async fn streams_request_response_and_trailers() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let request_trailers =
        TrailerBlock::from_bytes(Bytes::from_static(b"X-Request-Digest: abc\r\n\r\n")).unwrap();
    let response_trailers =
        TrailerBlock::from_bytes(Bytes::from_static(b"X-Response-Digest: def\r\n\r\n")).unwrap();

    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.request().method(), MethodKind::Reqmod);
        let mut body = BytesMut::new();
        while let Some(data) = transaction.next_data().await.unwrap() {
            body.extend_from_slice(&data);
        }
        assert_eq!(&body[..], b"hello world");
        assert_eq!(transaction.body_end(), Some(BodyEnd::Complete));
        assert_eq!(
            transaction.trailers().unwrap().as_bytes().as_ref(),
            b"X-Request-Digest: abc\r\n\r\n"
        );

        let response = response(
            MethodKind::Reqmod,
            StatusCode::OK,
            b"OK",
            Some(request_parts(EncapsulatedKind::RequestBody)),
        );
        let mut writer = transaction.respond(response).await.unwrap();
        writer.write_data(b"adapted").await.unwrap();
        writer
            .finish_with_trailers(&response_trailers)
            .await
            .unwrap();
        assert!(connection.is_reusable());
    };

    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let request = request(Method::Reqmod, request_parts(EncapsulatedKind::RequestBody));
        let mut transaction = connection.start(request).await.unwrap();
        assert_eq!(
            transaction.write_data(b"hello ").await.unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(
            transaction.write_data(b"world").await.unwrap(),
            WriteOutcome::Written
        );
        let mut response = transaction
            .finish_with_trailers(&request_trailers)
            .await
            .unwrap();
        assert_eq!(response.response().status(), StatusCode::OK);
        assert_eq!(
            &collect_client_response(&mut response).await[..],
            b"adapted"
        );
        assert_eq!(response.body_end(), Some(BodyEnd::Complete));
        assert_eq!(
            response.trailers().unwrap().as_bytes().as_ref(),
            b"X-Response-Digest: def\r\n\r\n"
        );
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn parses_every_transaction_boundary_one_byte_at_a_time() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let trailers =
        TrailerBlock::from_bytes(Bytes::from_static(b"X-Checksum: abc\r\n\r\n")).unwrap();
    let server = async move {
        let mut connection = ServerConnection::new(OneByteIo(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"a"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Preview));
        transaction.continue_preview().await.unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"b"[..]);
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"c"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        let mut writer = transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::OK,
                b"OK",
                Some(request_parts(EncapsulatedKind::RequestBody)),
            ))
            .await
            .unwrap();
        writer.write_data(b"xyz").await.unwrap();
        writer.finish_with_trailers(&trailers).await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(OneByteIo(client_io));
        let mut transaction = connection.start(preview_request(2)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"a").await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Continue(mut transaction) =
            transaction.finish_preview(false).await.unwrap()
        else {
            panic!("server should continue the fragmented request");
        };
        assert_eq!(
            transaction.write_data(b"bc").await.unwrap(),
            WriteOutcome::Written
        );
        let mut response = transaction.finish().await.unwrap();
        assert_eq!(&collect_client_response(&mut response).await[..], b"xyz");
        assert_eq!(
            response.trailers().unwrap().as_bytes().as_ref(),
            b"X-Checksum: abc\r\n\r\n"
        );
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn zero_byte_preview_accepts_a_negotiated_206() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert!(transaction.request().allows_206());
        assert!(!transaction.request().allows_204());
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Preview));
        let mut writer = transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::PARTIAL_CONTENT,
                b"Partial Content",
                Some(request_parts(EncapsulatedKind::RequestBody)),
            ))
            .await
            .unwrap();
        writer.write_data(b"adapted").await.unwrap();
        writer.finish().await.unwrap();
    };
    let client = async move {
        let line = RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap();
        let request = Request::with_preview(
            line,
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new(header::ALLOW, b"206").unwrap(),
            ],
            request_parts(EncapsulatedKind::RequestBody),
            Preview::new(0),
        )
        .unwrap();
        let mut connection = ClientConnection::new(client_io);
        let transaction = connection.start(request).await.unwrap();
        let PreviewOutcome::Response(mut response) =
            transaction.finish_preview(false).await.unwrap()
        else {
            panic!("zero-byte Preview should receive a final response");
        };
        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            &collect_client_response(&mut response).await[..],
            b"adapted"
        );
        assert_eq!(response.body_end(), Some(BodyEnd::Complete));
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn preview_continue_streams_the_remainder() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"ab"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Preview));
        transaction.continue_preview().await.unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"efgh"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Complete));
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                b"No Content",
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection.start(preview_request(4)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"ab").await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Continue(mut transaction) =
            transaction.finish_preview(false).await.unwrap()
        else {
            panic!("server should continue the request");
        };
        assert_eq!(
            transaction.write_data(b"efgh").await.unwrap(),
            WriteOutcome::Written
        );
        let response = transaction.finish().await.unwrap();
        assert_eq!(
            response.response().status(),
            StatusCode::NO_MODIFICATION_NEEDED
        );
        drop(response);
        assert!(connection.is_reusable());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn accepts_continue_while_the_preview_terminal_flush_is_pending() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let release = Arc::new(AtomicBool::new(false));
    let server_release = Arc::clone(&release);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"ab"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        transaction.continue_preview().await.unwrap();
        server_release.store(true, Ordering::Release);
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"cd"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::OK,
                b"OK",
                Some(EncapsulatedParts::null()),
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };
    let client = async move {
        let io = BlockPreviewTerminalFlushIo {
            inner: client_io,
            completed_flushes: 0,
            release,
        };
        let mut connection = ClientConnection::new(io);
        let mut transaction = connection.start(preview_request(2)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"ab").await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Continue(mut transaction) =
            transaction.finish_preview(false).await.unwrap()
        else {
            panic!("server should continue the request");
        };
        assert_eq!(
            transaction.write_data(b"cd").await.unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(
            transaction.finish().await.unwrap().response().status(),
            StatusCode::OK
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client)
    })
    .await
    .expect("100 Continue lost its terminal-write race");
}

#[tokio::test]
async fn completes_the_preview_terminal_after_a_premature_continue() {
    let (client_io, mut server_io) = tokio::io::duplex(256);
    let release = Arc::new(AtomicBool::new(false));
    let server_release = Arc::clone(&release);
    let server = async move {
        let _icap_head = read_raw_head(&mut server_io).await;
        let _http_head = read_raw_head(&mut server_io).await;
        let mut preview = [0; 7];
        server_io.read_exact(&mut preview).await.unwrap();
        assert_eq!(&preview, b"2\r\nab\r\n");
        server_io
            .write_all(b"ICAP/1.0 100 Continue\r\n\r\n")
            .await
            .unwrap();
        server_release.store(true, Ordering::Release);

        let mut remainder = [0; 17];
        server_io.read_exact(&mut remainder).await.unwrap();
        assert_eq!(&remainder, b"0\r\n\r\n2\r\ncd\r\n0\r\n\r\n");
        server_io
            .write_all(
                b"ICAP/1.0 200 OK\r\n\
                  ISTag: \"rama-test\"\r\n\
                  Encapsulated: null-body=0\r\n\r\n",
            )
            .await
            .unwrap();
    };
    let client = async move {
        let io = BlockPreviewTerminalWriteIo {
            inner: client_io,
            release,
        };
        let mut connection = ClientConnection::new(io);
        let mut transaction = connection.start(preview_request(2)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"ab").await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Continue(mut transaction) =
            transaction.finish_preview(false).await.unwrap()
        else {
            panic!("server should continue the request");
        };
        assert_eq!(
            transaction.write_data(b"cd").await.unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(
            transaction.finish().await.unwrap().response().status(),
            StatusCode::OK
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client)
    })
    .await
    .expect("premature 100 Continue desynchronized the request stream");
}

#[tokio::test]
async fn preview_allows_early_final_and_ieof() {
    for (end_of_body, expected_end) in [(false, BodyEnd::Preview), (true, BodyEnd::Complete)] {
        let (client_io, server_io) = tokio::io::duplex(256);
        let server = async move {
            let mut connection = ServerConnection::new(server_io);
            let mut transaction = connection.accept().await.unwrap().unwrap();
            assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"data"[..]);
            assert!(transaction.next_data().await.unwrap().is_none());
            assert_eq!(transaction.body_end(), Some(expected_end));
            transaction
                .respond(response(
                    MethodKind::Reqmod,
                    StatusCode::NO_MODIFICATION_NEEDED,
                    b"No Content",
                    None,
                ))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
        };
        let client = async move {
            let mut connection = ClientConnection::new(client_io);
            let limit = if end_of_body { 16 } else { 4 };
            let mut transaction = connection.start(preview_request(limit)).await.unwrap();
            assert_eq!(
                transaction.write_data(b"data").await.unwrap(),
                WriteOutcome::Written
            );
            let PreviewOutcome::Response(response) =
                transaction.finish_preview(end_of_body).await.unwrap()
            else {
                panic!("server should return an early final response");
            };
            assert_eq!(
                response.response().status(),
                StatusCode::NO_MODIFICATION_NEEDED
            );
        };
        tokio::join!(server, client);
    }
}

#[tokio::test]
async fn partial_response_exposes_original_body_offset() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        while transaction.next_data().await.unwrap().is_some() {}
        let response = response(
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
            b"Partial Content",
            Some(response_parts(EncapsulatedKind::ResponseBody)),
        );
        let mut writer = transaction.respond(response).await.unwrap();
        writer.write_data(b"changed").await.unwrap();
        writer.finish_partial(3).await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let request = request_with_allow(
            Method::Respmod,
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                Some(Bytes::from_static(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n",
                )),
                EncapsulatedKind::ResponseBody,
            )
            .unwrap(),
        );
        let mut transaction = connection.start(request).await.unwrap();
        assert_eq!(
            transaction.write_data(b"original").await.unwrap(),
            WriteOutcome::Written
        );
        let mut response = transaction.finish().await.unwrap();
        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            &collect_client_response(&mut response).await[..],
            b"changed"
        );
        assert_eq!(
            response.body_end(),
            Some(BodyEnd::PartialContent {
                use_original_body: 3,
            })
        );
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn rejects_an_original_body_offset_at_or_beyond_the_end() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        while transaction.next_data().await.unwrap().is_some() {}
        let mut writer = transaction
            .respond(response(
                MethodKind::Respmod,
                StatusCode::PARTIAL_CONTENT,
                b"Partial Content",
                Some(response_parts(EncapsulatedKind::ResponseBody)),
            ))
            .await
            .unwrap();
        writer.write_data(b"changed").await.unwrap();
        writer.finish_partial(8).await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection
            .start(request_with_allow(
                Method::Respmod,
                response_parts(EncapsulatedKind::ResponseBody),
            ))
            .await
            .unwrap();
        assert_eq!(
            transaction.write_data(b"original").await.unwrap(),
            WriteOutcome::Written
        );
        let mut response = transaction.finish().await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), b"changed"[..]);
        assert!(matches!(
            response.next_data().await,
            Err(Error::InvalidSequence(_))
        ));
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn early_partial_offsets_require_a_declared_original_length() {
    for declared_len in [None, Some(8)] {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut request = request_with_allow(
            Method::Respmod,
            response_parts(EncapsulatedKind::ResponseBody),
        );
        if let Some(len) = declared_len {
            request = request.with_original_body_len(len).unwrap();
        }
        let initial_len = request.head_bytes().len()
            + request
                .encapsulated()
                .and_then(EncapsulatedParts::response_header)
                .map_or(0, Bytes::len);
        let server = async move {
            let mut initial = vec![0; initial_len];
            server_io.read_exact(&mut initial).await.unwrap();
            server_io
                .write_all(
                    b"ICAP/1.0 206 Partial Content\r\n\
                      ISTag: \"rama-test\"\r\n\
                      Connection: close\r\n\
                      Encapsulated: res-hdr=0, res-body=38\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n\
                      1\r\nx\r\n0; use-original-body=3\r\n\r\n",
                )
                .await
                .unwrap();
        };
        let client = async move {
            let mut connection = ClientConnection::new(client_io);
            let mut transaction = connection.start(request).await.unwrap();
            assert_eq!(
                transaction.monitor_response().await.unwrap(),
                WriteOutcome::ResponseAvailable
            );
            let mut response = transaction.finish().await.unwrap();
            assert_eq!(response.next_data().await.unwrap().unwrap(), b"x"[..]);
            let terminal = response.next_data().await;
            if declared_len.is_some() {
                assert!(terminal.unwrap().is_none());
                assert_eq!(
                    response.body_end(),
                    Some(BodyEnd::PartialContent {
                        use_original_body: 3,
                    })
                );
            } else {
                assert!(matches!(terminal, Err(Error::InvalidSequence(_))));
            }
        };
        tokio::join!(server, client);
    }
}

#[tokio::test]
async fn enforces_a_declared_original_body_length() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let request = request_with_allow(
        Method::Respmod,
        response_parts(EncapsulatedKind::ResponseBody),
    )
    .with_original_body_len(3)
    .unwrap();
    let mut connection = ClientConnection::new(client_io);
    let mut transaction = connection.start(request).await.unwrap();
    assert_eq!(
        transaction.write_data(b"abc").await.unwrap(),
        WriteOutcome::Written
    );

    let (client_io, _server_io) = tokio::io::duplex(4096);
    let request = request_with_allow(
        Method::Respmod,
        response_parts(EncapsulatedKind::ResponseBody),
    )
    .with_original_body_len(3)
    .unwrap();
    let mut connection = ClientConnection::new(client_io);
    let mut transaction = connection.start(request).await.unwrap();
    assert!(matches!(
        transaction.write_data(b"four").await,
        Err(Error::InvalidSequence(_))
    ));

    let (client_io, _server_io) = tokio::io::duplex(4096);
    let request = request_with_allow(
        Method::Respmod,
        response_parts(EncapsulatedKind::ResponseBody),
    )
    .with_original_body_len(3)
    .unwrap();
    let mut connection = ClientConnection::new(client_io);
    let mut transaction = connection.start(request).await.unwrap();
    assert_eq!(
        transaction.write_data(b"ab").await.unwrap(),
        WriteOutcome::Written
    );
    assert!(matches!(
        transaction.finish().await,
        Err(Error::InvalidSequence(_))
    ));
}

#[tokio::test]
async fn partial_response_can_supply_the_complete_adapted_body() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        while transaction.next_data().await.unwrap().is_some() {}
        let response = response(
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
            b"Partial Content",
            Some(response_parts(EncapsulatedKind::ResponseBody)),
        );
        let mut writer = transaction.respond(response).await.unwrap();
        writer.write_data(b"fully adapted").await.unwrap();
        writer.finish().await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection
            .start(request_with_allow(
                Method::Respmod,
                EncapsulatedParts::new(
                    None,
                    Some(Bytes::from_static(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n",
                    )),
                    EncapsulatedKind::ResponseBody,
                )
                .unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            transaction.write_data(b"original").await.unwrap(),
            WriteOutcome::Written
        );
        let mut response = transaction.finish().await.unwrap();
        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            &collect_client_response(&mut response).await[..],
            b"fully adapted"
        );
        assert_eq!(response.body_end(), Some(BodyEnd::Complete));
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn parses_partial_content_draft_figure_5() {
    const HTTP_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Date: Thu, 25 Feb 2010 12:17:22 GMT\r\n\
        Server: Testserver/1.0 (Unix)\r\n\
        ETag: \"63840-1ab7-378d415b\"\r\n\
        Via: 1.0 icap.example.org (ICAP Example Respmod Service 1.1)\r\n\
        Content-Type: text/plain\r\n\
        Content-Length: 17\r\n\r\n";
    assert_eq!(HTTP_HEAD.len(), 224);
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = async move {
        server_io
            .write_all(
                b"ICAP/1.0 206 Partial Content\r\n\
                  Date: Thu, 25 Feb 2010 12:17:23 GMT\r\n\
                  Server: ICAP-Server-Software/1.0\r\n\
                  Connection: close\r\n\
                  ISTag: \"W3E4R7U9-L2E4-2\"\r\n\
                  Encapsulated: res-hdr=0, res-body=224\r\n\r\n",
            )
            .await
            .unwrap();
        server_io.write_all(HTTP_HEAD).await.unwrap();
        server_io
            .write_all(b"11\r\nNew content here.\r\n0\r\n\r\n")
            .await
            .unwrap();
        let mut request = [0; 512];
        while server_io.read(&mut request).await.unwrap() != 0 {}
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection
            .start(request_with_allow(
                Method::Respmod,
                response_parts(EncapsulatedKind::ResponseBody),
            ))
            .await
            .unwrap();
        let _outcome = transaction.write_data(b"original body").await.unwrap();
        let mut response = transaction.finish().await.unwrap();
        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .response()
                .encapsulated()
                .and_then(EncapsulatedParts::response_header)
                .unwrap(),
            HTTP_HEAD
        );
        assert_eq!(
            &collect_client_response(&mut response).await[..],
            b"New content here."
        );
        assert_eq!(response.body_end(), Some(BodyEnd::Complete));
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn early_response_is_monitored_without_full_duplex_deadlock() {
    let exchange = async {
        let (client_io, server_io) = tokio::io::duplex(64);
        let server = async move {
            let mut connection = ServerConnection::new(server_io);
            let transaction = connection.accept().await.unwrap().unwrap();
            let response = Response::new(
                MethodKind::Reqmod,
                ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
                &[
                    Header::new(header::ISTAG, b"\"rama-test\"").unwrap(),
                    Header::new(header::CONNECTION, b"close").unwrap(),
                ],
                Some(request_parts(EncapsulatedKind::RequestBody)),
            )
            .unwrap();
            let mut writer = transaction.respond_early(response).await.unwrap();
            writer.write_data(&vec![b'y'; 128 * 1024]).await.unwrap();
            writer.finish().await.unwrap();
            assert!(!connection.is_reusable());
        };
        let client = async move {
            let mut connection = ClientConnection::new(client_io);
            let mut transaction = connection
                .start(request(
                    Method::Reqmod,
                    request_parts(EncapsulatedKind::RequestBody),
                ))
                .await
                .unwrap();
            assert_eq!(
                transaction
                    .write_data(&vec![b'x'; 128 * 1024])
                    .await
                    .unwrap(),
                WriteOutcome::ResponseAvailable
            );
            let mut response = transaction.finish().await.unwrap();
            assert_eq!(response.response().status(), StatusCode::OK);
            assert_eq!(
                collect_client_response(&mut response).await.len(),
                128 * 1024
            );
            drop(response);
            assert!(!connection.is_reusable());
        };
        tokio::join!(server, client);
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), exchange)
        .await
        .expect("early response exchange deadlocked");
}

#[tokio::test]
async fn monitors_an_early_response_while_writing_the_icap_head() {
    let (client_io, mut server_io) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        let mut line = Vec::new();
        let mut byte = [0];
        while !line.ends_with(b"\r\n") {
            server_io.read_exact(&mut byte).await.unwrap();
            line.push(byte[0]);
        }
        server_io
            .write_all(
                b"ICAP/1.0 500 Server Error\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        core::future::pending::<()>().await;
    });
    let client = async move {
        let padding = vec![b'x'; 60 * 1024];
        let request = Request::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new("X-Padding", &padding).unwrap(),
            ],
            Some(request_parts(EncapsulatedKind::RequestBody)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(client_io);
        let transaction = connection.start(request).await.unwrap();
        let response = transaction.finish().await.unwrap();
        assert_eq!(
            response.response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        drop(response);
        assert!(!connection.is_reusable());
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), client)
        .await
        .expect("request-head monitoring deadlocked");
    server.abort();
}

#[tokio::test]
async fn abandons_an_incomplete_prefix_even_without_a_chunk_stream() {
    let (client_io, mut server_io) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        let _head = read_raw_head(&mut server_io).await;
        server_io
            .write_all(b"ICAP/1.0 500 Server Error\r\n\r\n")
            .await
            .unwrap();
        core::future::pending::<()>().await;
    });
    let client = async move {
        let mut http_head = Vec::with_capacity(60 * 1024);
        http_head.extend_from_slice(b"GET / HTTP/1.1\r\nX-Padding: ");
        http_head.resize(60 * 1024 - 4, b'x');
        http_head.extend_from_slice(b"\r\n\r\n");
        let parts = EncapsulatedParts::new(
            Some(Bytes::from(http_head)),
            None,
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        let mut connection = ClientConnection::new(client_io);
        let transaction = connection
            .start(request(Method::Reqmod, parts))
            .await
            .unwrap();
        let response = transaction.finish().await.unwrap();
        assert_eq!(
            response.response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        drop(response);
        assert!(!connection.is_reusable());
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), client)
        .await
        .expect("encapsulated-prefix monitoring deadlocked");
    server.abort();
}

#[tokio::test]
async fn monitors_an_early_response_while_the_body_source_is_idle() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let transaction = connection.accept().await.unwrap().unwrap();
        tokio::task::yield_now().await;
        let response = Response::new(
            MethodKind::Reqmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[
                Header::new(header::ISTAG, b"\"rama-test\"").unwrap(),
                Header::new(header::CONNECTION, b"close").unwrap(),
            ],
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        transaction
            .respond_early(response)
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection
            .start(request(
                Method::Reqmod,
                request_parts(EncapsulatedKind::RequestBody),
            ))
            .await
            .unwrap();
        assert_eq!(
            transaction.monitor_response().await.unwrap(),
            WriteOutcome::ResponseAvailable
        );
        let response = transaction.finish().await.unwrap();
        assert_eq!(response.response().status(), StatusCode::OK);
        drop(response);
        assert!(!connection.is_reusable());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn preserves_a_partially_read_response_across_write_races() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let request = request(
        Method::Respmod,
        response_parts(EncapsulatedKind::ResponseBody),
    );
    let prefix_len = request
        .encapsulated()
        .unwrap()
        .request_header()
        .map_or(0, Bytes::len)
        + request
            .encapsulated()
            .unwrap()
            .response_header()
            .map_or(0, Bytes::len);
    let initial_request_len = request.head_bytes().len() + prefix_len;
    let mut http_head = Vec::with_capacity(20 * 1024);
    http_head.extend_from_slice(b"HTTP/1.1 200 OK\r\nX-Padding: ");
    http_head.resize(20 * 1024 - 4, b'x');
    http_head.extend_from_slice(b"\r\n\r\n");
    let response_head = format!(
        "ICAP/1.0 200 OK\r\nISTag: \"rama-test\"\r\n\
         Encapsulated: res-hdr=0, null-body={}\r\n\r\n",
        http_head.len()
    );
    let (written_tx, written_rx) = tokio::sync::oneshot::channel();
    let server = async move {
        let mut initial = vec![0; initial_request_len];
        server_io.read_exact(&mut initial).await.unwrap();
        server_io.write_all(response_head.as_bytes()).await.unwrap();
        server_io.write_all(&http_head[..8]).await.unwrap();
        written_rx.await.unwrap();
        server_io.write_all(&http_head[8..]).await.unwrap();
        let mut remainder = Vec::new();
        server_io.read_to_end(&mut remainder).await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection.start(request).await.unwrap();
        assert_eq!(
            transaction.write_data(b"original").await.unwrap(),
            WriteOutcome::Written
        );
        written_tx.send(()).unwrap();
        let response = transaction.finish().await.unwrap();
        assert_eq!(response.response().status(), StatusCode::OK);
        assert_eq!(
            response
                .response()
                .encapsulated()
                .and_then(EncapsulatedParts::response_header)
                .unwrap()
                .len(),
            20 * 1024
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client)
    })
    .await
    .expect("response-prefix cancellation lost framing state");
}

#[tokio::test]
async fn rejects_unnegotiated_partial_content() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = async move {
        server_io
            .write_all(
                b"ICAP/1.0 206 Partial Content\r\n\
                  ISTag: \"rama-test\"\r\n\
                  Encapsulated: null-body=0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut request = [0; 512];
        let _read = server_io.read(&mut request).await.unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let result = connection
            .start(request(
                Method::Respmod,
                response_parts(EncapsulatedKind::NullBody),
            ))
            .await;
        match result {
            Err(rama_icap::io::Error::InvalidSequence(_)) => {}
            Ok(transaction) => assert!(matches!(
                transaction.finish().await,
                Err(rama_icap::io::Error::InvalidSequence(_))
            )),
            Err(error) => panic!("unexpected client error: {error}"),
        }
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn server_rejects_unnegotiated_204_and_206() {
    for status in [
        StatusCode::NO_MODIFICATION_NEEDED,
        StatusCode::PARTIAL_CONTENT,
    ] {
        let (mut client_io, server_io) = tokio::io::duplex(4096);
        client_io
            .write_all(
                b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
                  Host: icap.test\r\n\
                  Encapsulated: req-hdr=0, null-body=18\r\n\r\n\
                  GET / HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();

        let mut connection = ServerConnection::new(server_io);
        let transaction = connection.accept().await.unwrap().unwrap();
        let response = response(
            MethodKind::Reqmod,
            status,
            if status == StatusCode::PARTIAL_CONTENT {
                b"Partial Content"
            } else {
                b"No Content"
            },
            (status == StatusCode::PARTIAL_CONTENT)
                .then(|| request_parts(EncapsulatedKind::RequestBody)),
        );
        assert!(matches!(
            transaction.respond(response).await,
            Err(Error::InvalidSequence(_))
        ));
    }
}

#[tokio::test]
async fn allow_206_alone_is_insufficient_outside_preview() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = async move {
        server_io
            .write_all(
                b"ICAP/1.0 206 Partial Content\r\n\
                  ISTag: \"rama-test\"\r\n\
                  Encapsulated: null-body=0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut request = [0; 512];
        let _read = server_io.read(&mut request).await.unwrap();
    };
    let client = async move {
        let line = RequestLine::new(Method::Respmod, "icap://icap.test/echo").unwrap();
        let request = Request::new(
            line,
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new(header::ALLOW, b"206").unwrap(),
            ],
            Some(response_parts(EncapsulatedKind::ResponseBody)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(client_io);
        let result = connection.start(request).await;
        match result {
            Err(Error::InvalidSequence(_)) => {}
            Ok(mut transaction) => match transaction.write_data(b"original").await {
                Err(Error::InvalidSequence(_)) => {}
                Ok(_) => assert!(matches!(
                    transaction.finish().await,
                    Err(Error::InvalidSequence(_))
                )),
                Err(error) => panic!("unexpected client error: {error}"),
            },
            Err(error) => panic!("unexpected client error: {error}"),
        }
    };
    tokio::join!(server, client);

    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Allow: 206\r\n\
              Encapsulated: req-hdr=0, null-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n",
        )
        .await
        .unwrap();
    let mut connection = ServerConnection::new(server_io);
    let transaction = connection.accept().await.unwrap().unwrap();
    assert!(matches!(
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::PARTIAL_CONTENT,
                b"Partial Content",
                Some(request_parts(EncapsulatedKind::RequestBody)),
            ))
            .await,
        Err(Error::InvalidSequence(_))
    ));
}

#[tokio::test]
async fn early_server_responses_preserve_preview_negotiation() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n",
        )
        .await
        .unwrap();
    let mut connection = ServerConnection::new(server_io);
    let transaction = connection.accept().await.unwrap().unwrap();
    let response = Response::new(
        MethodKind::Reqmod,
        ResponseLine::new(StatusCode::NO_MODIFICATION_NEEDED, b"No Content").unwrap(),
        &[Header::new(header::CONNECTION, b"close").unwrap()],
        None,
    )
    .unwrap();
    assert!(matches!(
        transaction.respond_early(response).await,
        Err(Error::InvalidSequence(_))
    ));

    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Allow: 206\r\n\
              Preview: 4\r\n\
              Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n",
        )
        .await
        .unwrap();
    let mut connection = ServerConnection::new(server_io);
    let transaction = connection.accept().await.unwrap().unwrap();
    let response = Response::new(
        MethodKind::Reqmod,
        ResponseLine::new(StatusCode::PARTIAL_CONTENT, b"Partial Content").unwrap(),
        &[
            Header::new(header::ISTAG, b"\"rama-test\"").unwrap(),
            Header::new(header::CONNECTION, b"close").unwrap(),
        ],
        Some(request_parts(EncapsulatedKind::RequestBody)),
    )
    .unwrap();
    let mut response = transaction.respond_early(response).await.unwrap();
    response.write_data(b"adapted").await.unwrap();
    response.finish().await.unwrap();
}

#[tokio::test]
async fn abandoned_client_transaction_poisons_connection() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let mut connection = ClientConnection::new(client_io);
    {
        let _transaction = connection
            .start(request(
                Method::Reqmod,
                request_parts(EncapsulatedKind::RequestBody),
            ))
            .await
            .unwrap();
    }
    assert!(!connection.is_reusable());
    let result = connection
        .start(request(
            Method::Reqmod,
            request_parts(EncapsulatedKind::RequestBody),
        ))
        .await;
    assert!(matches!(result, Err(rama_icap::io::Error::InvalidState(_))));
}

#[tokio::test]
async fn rejects_trailers_on_an_incomplete_preview() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let mut connection = ClientConnection::new(client_io);
    let mut transaction = connection.start(preview_request(4)).await.unwrap();
    assert_eq!(
        transaction.write_data(b"data").await.unwrap(),
        WriteOutcome::Written
    );
    let trailers =
        TrailerBlock::from_bytes(Bytes::from_static(b"X-Checksum: abc\r\n\r\n")).unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        transaction.finish_preview_with_trailers(false, &trailers),
    )
    .await;
    assert!(matches!(
        result,
        Ok(Err(rama_icap::io::Error::InvalidSequence(_)))
    ));
}

#[tokio::test]
async fn preview_final_response_honors_connection_close() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"data"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
        let close = Header::new("Connection", b"close").unwrap();
        let response = Response::new(
            MethodKind::Reqmod,
            ResponseLine::new(StatusCode::NO_MODIFICATION_NEEDED, b"No Content").unwrap(),
            &[close],
            None,
        )
        .unwrap();
        transaction
            .respond(response)
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert!(!connection.is_reusable());
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection.start(preview_request(4)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"data").await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Response(response) = transaction.finish_preview(false).await.unwrap()
        else {
            panic!("server should return an early final response");
        };
        drop(response);
        assert!(!connection.is_reusable());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn rejects_reserved_terminal_extensions_in_request_bodies() {
    for terminal in [
        &b"0; ieof\r\n\r\n"[..],
        &b"0; use-original-body=0\r\n\r\n"[..],
    ] {
        let (mut client_io, server_io) = tokio::io::duplex(4096);
        client_io
            .write_all(
                b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
                  Host: icap.test\r\n\
                  Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
                  GET / HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();
        client_io.write_all(terminal).await.unwrap();

        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert!(matches!(
            transaction.next_data().await,
            Err(rama_icap::io::Error::InvalidSequence(_))
        ));
    }
}

#[tokio::test]
async fn enforces_the_inbound_preview_limit_before_buffering_data() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Preview: 4\r\n\
              Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n\
              5\r\n",
        )
        .await
        .unwrap();

    let mut connection = ServerConnection::new(server_io);
    let mut transaction = connection.accept().await.unwrap().unwrap();
    assert!(matches!(
        transaction.next_data().await,
        Err(rama_icap::io::Error::InvalidSequence(_))
    ));
}

#[tokio::test]
async fn detects_close_across_duplicate_connection_fields() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"OPTIONS icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Connection: keep-alive\r\n\
              Connection: upgrade, close\r\n\
              Encapsulated: null-body=0\r\n\r\n",
        )
        .await
        .unwrap();

    let mut connection = ServerConnection::new(server_io);
    let transaction = connection.accept().await.unwrap().unwrap();
    assert!(transaction.request().should_close());
}

#[tokio::test]
async fn detects_close_across_duplicate_response_fields() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = async move {
        let mut request = [0; 512];
        let _read = server_io.read(&mut request).await.unwrap();
        server_io
            .write_all(
                b"ICAP/1.0 200 OK\r\n\
                  Methods: REQMOD\r\n\
                  ISTag: \"rama-test\"\r\n\
                  Connection: keep-alive\r\n\
                  Connection: upgrade, close\r\n\
                  Encapsulated: null-body=0\r\n\r\n",
            )
            .await
            .unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let response = connection
            .start(options_request(false))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert!(response.response().should_close());
        drop(response);
        assert!(!connection.is_reusable());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn rejects_partial_completion_for_a_non_206_response() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = ClientConnection::new(client_io);
    let _client_transaction = client
        .start(request(
            Method::Reqmod,
            request_parts(EncapsulatedKind::NullBody),
        ))
        .await
        .unwrap();

    let mut server = ServerConnection::new(server_io);
    let transaction = server.accept().await.unwrap().unwrap();
    let writer = transaction
        .respond(response(
            MethodKind::Reqmod,
            StatusCode::OK,
            b"OK",
            Some(request_parts(EncapsulatedKind::RequestBody)),
        ))
        .await
        .unwrap();
    assert!(matches!(
        writer.finish_partial(0).await,
        Err(rama_icap::io::Error::InvalidState(_))
    ));
}

#[tokio::test]
async fn reuses_sequential_transactions_and_honors_close() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        for close in [false, true] {
            let transaction = connection.accept().await.unwrap().unwrap();
            assert_eq!(transaction.request().should_close(), close);
            transaction
                .respond(options_response(false))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(connection.is_reusable(), !close);
        }
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        for close in [false, true] {
            let response = connection
                .start(options_request(close))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(response.response().status(), StatusCode::OK);
            drop(response);
            assert_eq!(connection.is_reusable(), !close);
        }
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn splits_a_large_wire_chunk_without_buffering_it_whole() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        let mut segments = 0;
        let mut received = 0;
        while let Some(data) = transaction.next_data().await.unwrap() {
            segments += 1;
            received += data.len();
        }
        assert!(segments > 1);
        assert_eq!(received, 128 * 1024);
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::OK,
                b"OK",
                Some(EncapsulatedParts::null()),
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };
    let client = async move {
        let mut connection = ClientConnection::new(client_io);
        let mut transaction = connection
            .start(request(
                Method::Reqmod,
                request_parts(EncapsulatedKind::RequestBody),
            ))
            .await
            .unwrap();
        assert_eq!(
            transaction
                .write_data(&vec![b'x'; 128 * 1024])
                .await
                .unwrap(),
            WriteOutcome::Written
        );
        transaction.finish().await.unwrap();
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn applies_every_configured_async_framing_bound() {
    let cases = [
        (
            ConnectionOptions::new().with_head_parser(HeadParserConfig::new().with_max_bytes(32)),
            b"OPTIONS icap://icap.test/echo ICAP/1.0\r\n\r\n".as_slice(),
            "head",
        ),
        (
            ConnectionOptions::new().with_max_headers(1),
            b"OPTIONS icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Encapsulated: null-body=0\r\n\r\n"
                .as_slice(),
            "headers",
        ),
        (
            ConnectionOptions::new().with_max_encapsulated_header_bytes(17),
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Encapsulated: req-hdr=0, null-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n"
                .as_slice(),
            "encapsulated",
        ),
    ];

    for (options, wire, expected) in cases {
        let (mut client_io, server_io) = tokio::io::duplex(4096);
        client_io.write_all(wire).await.unwrap();
        let mut connection = ServerConnection::with_options(server_io, options);
        let Err(error) = connection.accept().await else {
            panic!("{expected} bound was not enforced");
        };
        if expected == "head" {
            assert!(matches!(error, Error::Head(ParseError::HeadTooLarge)));
        } else if expected == "headers" {
            assert!(matches!(error, Error::Head(ParseError::TooManyHeaders)));
        } else {
            assert_eq!(expected, "encapsulated");
            assert!(matches!(error, Error::InvalidSequence(_)));
        }
    }

    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n\r\n\
              123",
        )
        .await
        .unwrap();
    let options = ConnectionOptions::new().with_max_chunk_line_bytes(3);
    let mut connection = ServerConnection::with_options(server_io, options);
    let mut transaction = connection.accept().await.unwrap().unwrap();
    assert!(matches!(
        transaction.next_data().await,
        Err(Error::ChunkLine(ChunkLineError::LineTooLong))
    ));
}

#[tokio::test]
async fn reports_eof_at_each_incomplete_transaction_boundary() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(b"OPTIONS icap://icap.test/echo ICAP/1.0\r\nHost")
        .await
        .unwrap();
    client_io.shutdown().await.unwrap();
    let mut connection = ServerConnection::new(server_io);
    let Err(error) = connection.accept().await else {
        panic!("partial ICAP head was accepted");
    };
    assert_unexpected_eof(error);

    let (mut client_io, server_io) = tokio::io::duplex(4096);
    client_io
        .write_all(
            b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
              Host: icap.test\r\n\
              Encapsulated: req-hdr=0, null-body=18\r\n\r\n\
              GET / HTTP/1.1\r\n",
        )
        .await
        .unwrap();
    client_io.shutdown().await.unwrap();
    let mut connection = ServerConnection::new(server_io);
    let Err(error) = connection.accept().await else {
        panic!("partial encapsulated head was accepted");
    };
    assert_unexpected_eof(error);

    for suffix in [
        b"a".as_slice(),
        b"4\r\nab".as_slice(),
        b"1\r\na\r".as_slice(),
        b"0\r\nX-Trailer: value\r\n".as_slice(),
    ] {
        let (mut client_io, server_io) = tokio::io::duplex(4096);
        client_io
            .write_all(
                b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
                  Host: icap.test\r\n\
                  Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
                  GET / HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();
        client_io.write_all(suffix).await.unwrap();
        client_io.shutdown().await.unwrap();

        let mut connection = ServerConnection::new(server_io);
        let mut transaction = connection.accept().await.unwrap().unwrap();
        let error = loop {
            match transaction.next_data().await {
                Ok(Some(_)) => {}
                Ok(None) => panic!("incomplete body suffix was accepted: {suffix:?}"),
                Err(error) => break error,
            }
        };
        assert_unexpected_eof(error);
    }
}

#[tokio::test]
async fn scans_near_limit_frames_linearly_one_byte_at_a_time() {
    let exercise = async {
        let start = b"OPTIONS icap://icap.test/echo ICAP/1.0\r\nX-Pad: ";
        let end = b"\r\nEncapsulated: null-body=0\r\n\r\n";
        let mut wire = Vec::with_capacity(DEFAULT_MAX_HEAD_BYTES);
        wire.extend_from_slice(start);
        wire.resize(DEFAULT_MAX_HEAD_BYTES - end.len(), b'x');
        wire.extend_from_slice(end);
        assert_eq!(wire.len(), DEFAULT_MAX_HEAD_BYTES);
        let (mut client_io, server_io) = tokio::io::duplex(wire.len() + 1);
        client_io.write_all(&wire).await.unwrap();
        let mut connection = ServerConnection::new(OneByteIo(server_io));
        assert!(connection.accept().await.unwrap().is_some());

        let request = b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
            Host: icap.test\r\n\
            Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
            GET / HTTP/1.1\r\n\r\n\
            0\r\n";
        let trailer_start = b"X-Pad: ";
        let trailer_end = b"\r\n\r\n";
        let mut wire = Vec::with_capacity(request.len() + DEFAULT_MAX_HEAD_BYTES);
        wire.extend_from_slice(request);
        wire.extend_from_slice(trailer_start);
        wire.resize(
            request.len() + DEFAULT_MAX_HEAD_BYTES - trailer_end.len(),
            b'x',
        );
        wire.extend_from_slice(trailer_end);
        let (mut client_io, server_io) = tokio::io::duplex(wire.len() + 1);
        client_io.write_all(&wire).await.unwrap();
        let mut connection = ServerConnection::new(OneByteIo(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(
            transaction.trailers().unwrap().as_bytes().len(),
            DEFAULT_MAX_HEAD_BYTES
        );

        let request = b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
            Host: icap.test\r\n\
            Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
            GET / HTTP/1.1\r\n\r\n";
        let line_start = b"1;x=";
        let line_end = b"\r\n";
        let mut wire = Vec::with_capacity(request.len() + DEFAULT_MAX_CHUNK_LINE_BYTES + 8);
        wire.extend_from_slice(request);
        wire.extend_from_slice(line_start);
        wire.resize(
            request.len() + DEFAULT_MAX_CHUNK_LINE_BYTES - line_end.len(),
            b'x',
        );
        wire.extend_from_slice(line_end);
        wire.extend_from_slice(b"z\r\n0\r\n\r\n");
        let (mut client_io, server_io) = tokio::io::duplex(wire.len() + 1);
        client_io.write_all(&wire).await.unwrap();
        let mut connection = ServerConnection::new(OneByteIo(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), b"z"[..]);
        assert!(transaction.next_data().await.unwrap().is_none());
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), exercise)
        .await
        .expect("near-limit incremental scanning was not linear");
}
