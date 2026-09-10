//! Empty DATA must be harmless through inspection and re-encoding, including
//! when the decoder reaches EOF before the transport delivers END_STREAM.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail immediately on unexpected setup, transport, or body errors"
)]

#[path = "support/body.rs"]
mod body_fixture;

use body_fixture::{EndStreamFraming, Frames};
use parking_lot::Mutex;
use rama_core::telemetry::tracing::{self, Instrument as _};
use rama_core::{Service, ServiceInput, bytes::Bytes, rt::Executor, service::service_fn};
use rama_http::{
    Body, Request, Response,
    body::{Frame, util::BodyExt},
    layer::{
        compression::{predicate::Always, stream::StreamCompression},
        decompression::{Decompression, DecompressionBody, RequestDecompression},
        map_response_body::MapResponseBody,
    },
};
use rama_http_core::{client::conn, h2, server, service::RamaHttpService};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

const PAYLOAD: &[u8] = b"data: first event\n\ndata: second event\n\n";
const ENCODINGS: [&str; 5] = ["gzip", "deflate", "br", "zstd", "identity"];

// Abort connection drivers even if a regression panics or times out.
#[derive(Default)]
struct Tasks(Vec<tokio::task::JoinHandle<()>>);
impl Tasks {
    fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.0.push(tokio::spawn(future.in_current_span()));
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

fn response(body: Body, encoding: &str) -> Response {
    let mut response = Response::builder().header("content-type", "text/event-stream");
    if encoding != "identity" {
        response = response.header("content-encoding", encoding);
    }
    response.body(body).unwrap()
}

fn request(accept: Option<&str>, body: Body) -> Request {
    let mut request = Request::builder().uri("http://localhost/");
    if let Some(accept) = accept {
        request = request.header("accept-encoding", accept);
    }
    request.body(body).unwrap()
}

async fn encoded(encoding: &str) -> Bytes {
    let service = StreamCompression::new(service_fn(|_: Request| async {
        Ok::<_, Infallible>(response(Body::from(PAYLOAD), "identity"))
    }))
    .with_compress_predicate(Always::new());
    let response = service
        .serve(request(Some(encoding), Body::empty()))
        .await
        .unwrap();
    response.into_body().collect().await.unwrap().to_bytes()
}

async fn decoded(response: Response) -> Bytes {
    let response = Mutex::new(Some(response));
    let service = Decompression::new(service_fn(move |_: Request| {
        let response = response.lock().take().unwrap();
        async { Ok::<_, Infallible>(response) }
    }));
    service
        .serve(request(None, Body::empty()))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
}

// This is an actual response-body mapping layer between decoder and encoder.
fn inspect(body: DecompressionBody<Body>, count: Arc<AtomicUsize>) -> Body {
    Body::new(body.inspect_frame(move |frame| {
        if frame.data_ref().is_some_and(Bytes::is_empty) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }))
}

async fn recompress(
    source: Response,
    accept: Option<&str>,
    inspection: bool,
    count: Arc<AtomicUsize>,
) -> Response {
    let source = Mutex::new(Some(source));
    let origin = service_fn(move |_: Request| {
        let source = source.lock().take().unwrap();
        async { Ok::<_, Infallible>(source) }
    });
    let decompression = Decompression::new(origin);
    if inspection {
        let mapped = MapResponseBody::new(decompression, move |body| inspect(body, count.clone()));
        StreamCompression::new(mapped)
            .with_compress_predicate(Always::new())
            .serve(request(accept, Body::empty()))
            .await
            .unwrap()
            .map(Body::new)
    } else {
        StreamCompression::new(decompression)
            .with_compress_predicate(Always::new())
            .serve(request(accept, Body::empty()))
            .await
            .unwrap()
            .map(Body::new)
    }
}

#[tokio::test]
async fn decompress_inspect_recompress_empty_frames() {
    for encoding in ENCODINGS {
        let compressed = encoded(encoding).await;
        for inspection in [false, true] {
            for with_trailers in [false, true] {
                let mut source = EndStreamFraming::EmptyData.body(compressed.clone());
                let mut trailers = rama_http::HeaderMap::new();
                trailers.insert("x-checksum", "abc123".parse().unwrap());
                if with_trailers {
                    source.0.push_back(Frame::trailers(trailers.clone()));
                }
                let count = Arc::new(AtomicUsize::new(0));
                let output = recompress(
                    response(Body::new(source), encoding),
                    Some(encoding),
                    inspection,
                    count.clone(),
                )
                .await;
                let (parts, body) = output.into_parts();
                let collected = body.collect().await.unwrap();
                assert_eq!(collected.trailers(), with_trailers.then_some(&trailers));
                assert_eq!(
                    decoded(Response::from_parts(
                        parts,
                        Body::from(collected.to_bytes())
                    ))
                    .await,
                    PAYLOAD
                );
                // zstd reads through transport EOF to support multiple members;
                // the other decoders finish before the trailing empty frame.
                if inspection && encoding != "zstd" {
                    assert_eq!(
                        count.load(Ordering::Relaxed),
                        1,
                        "{encoding}: did not exercise post-decoder EOF frame"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn async_codecs_and_request_decompression_skip_empty_chunks() {
    use rama_http::layer::compression::Compression;

    for encoding in ENCODINGS {
        let data = encoded(encoding).await;
        // Real input is split down to single bytes to exercise decoder calls
        // that consume input without yet producing any output.
        let frames = || {
            let mut frames = std::collections::VecDeque::new();
            for byte in &data {
                frames.push_back(Frame::data(Bytes::new()));
                frames.push_back(Frame::data(Bytes::copy_from_slice(&[*byte])));
            }
            frames.push_back(Frame::data(Bytes::new()));
            Body::new(Frames(frames))
        };
        let service = RequestDecompression::new(service_fn(
            |request: Request<DecompressionBody<Body>>| async {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, PAYLOAD);
                Ok::<_, Infallible>(Response::new(Body::from(body)))
            },
        ));
        let mut req = request(None, frames());
        if encoding != "identity" {
            req.headers_mut()
                .insert("content-encoding", encoding.parse().unwrap());
        }
        service.serve(req).await.unwrap();

        let source = Mutex::new(Some(response(frames(), encoding)));
        let service = Compression::new(Decompression::new(service_fn(move |_: Request| {
            let source = source.lock().take().unwrap();
            async { Ok::<_, Infallible>(source) }
        })))
        .with_compress_predicate(Always::new());
        let output = service
            .serve(request(Some(encoding), Body::empty()))
            .await
            .unwrap();
        assert_eq!(decoded(output.map(Body::new)).await, PAYLOAD);
    }
}

#[tokio::test]
async fn upstream_body_error_after_empty_frame_is_preserved() {
    use rama_core::futures::stream;
    let source = Body::from_frame_stream(stream::iter([
        Ok(Frame::data(encoded("gzip").await)),
        Ok(Frame::data(Bytes::new())),
        Err(std::io::Error::other("origin body failed")),
    ]));
    let output = recompress(response(source, "gzip"), Some("gzip"), true, Arc::default()).await;
    let err = output.into_body().collect().await.unwrap_err();
    assert!(err.to_string().contains("origin body failed"), "{err}");
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    H1,
    H2,
}

// Record the server's writes to verify the actual HTTP/2 flags and resets.
struct RecordIo {
    inner: DuplexStream,
    written: Arc<Mutex<Vec<u8>>>,
}
impl AsyncRead for RecordIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for RecordIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.written.lock().extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn assert_h2_frames(written: &[u8], framing: Option<EndStreamFraming>) {
    let mut bytes = written;
    let mut end_data = None;
    while bytes.len() >= 9 {
        let len =
            (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
        assert!(bytes.len() >= 9 + len, "incomplete frame");
        assert_ne!(bytes[3], 3, "unexpected RST_STREAM");
        if bytes[3] == 0 && bytes[4] & 1 != 0 {
            end_data = Some(len);
        }
        bytes = &bytes[9 + len..];
    }
    assert!(bytes.is_empty());
    if let Some(framing) = framing {
        let len = end_data.expect("missing DATA with END_STREAM");
        assert_eq!(
            len == 0,
            framing == EndStreamFraming::EmptyData,
            "wrong wire framing"
        );
    }
}

// The fixture parameter is reusable for any body-layer test. It sends exact
// DATA/END_STREAM flags with the low-level h2 API, then receives a real IncomingBody.
async fn origin_h2(
    data: Bytes,
    encoding: &'static str,
    framing: EndStreamFraming,
    tasks: &mut Tasks,
) -> (Response, Arc<Mutex<Vec<u8>>>) {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let written = Arc::new(Mutex::new(Vec::new()));
    let io = RecordIo {
        inner: server_io,
        written: written.clone(),
    };
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(ServiceInput::new(io)).await.unwrap();
        while let Some(stream) = connection.accept().await {
            let (_, mut respond) = stream.unwrap();
            let head = response(Body::empty(), encoding).map(|_| ());
            let mut send = respond.send_response(head, false).unwrap();
            send.send_data(data.clone(), framing == EndStreamFraming::LastData)
                .unwrap();
            if framing == EndStreamFraming::EmptyData {
                send.send_data(Bytes::new(), true).unwrap();
            }
        }
    });
    let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
        .handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    tasks.spawn(async move {
        connection.await.unwrap();
    });
    let response = sender
        .send_request(request(None, Body::empty()))
        .await
        .unwrap()
        .map(Body::new);
    (response, written)
}

async fn exchange<S>(
    protocol: Protocol,
    service: S,
    request: Request,
    tasks: &mut Tasks,
) -> (Response, Arc<Mutex<Vec<u8>>>)
where
    S: Service<Request, Output = Response>,
    S::Error: std::fmt::Debug,
{
    let service = Arc::new(service);
    let service = service_fn(move |request: Request| {
        let service = service.clone();
        async move { Ok::<_, Infallible>(service.serve(request).await.unwrap()) }
    });
    let (client_io, server_io) = tokio::io::duplex(65536);
    let written = Arc::new(Mutex::new(Vec::new()));
    let io = ServiceInput::new(RecordIo {
        inner: server_io,
        written: written.clone(),
    });
    tasks.spawn(async move {
        match protocol {
            Protocol::H1 => server::conn::http1::Builder::new()
                .serve_connection(io, RamaHttpService::new(service))
                .await
                .unwrap(),
            Protocol::H2 => server::conn::http2::Builder::new(Executor::new())
                .serve_connection(io, RamaHttpService::new(service))
                .await
                .unwrap(),
        }
    });
    let response = match protocol {
        Protocol::H1 => {
            let (mut sender, connection) = conn::http1::handshake(ServiceInput::new(client_io))
                .await
                .unwrap();
            tasks.spawn(async move {
                connection.await.unwrap();
            });
            sender.send_request(request).await.unwrap().map(Body::new)
        }
        Protocol::H2 => {
            let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
                .handshake(ServiceInput::new(client_io))
                .await
                .unwrap();
            tasks.spawn(async move {
                connection.await.unwrap();
            });
            sender.send_request(request).await.unwrap().map(Body::new)
        }
    };
    (response, written)
}

#[tokio::test]
async fn streaming_proxy_transport_matrix() {
    for encoding in ENCODINGS {
        let data = encoded(encoding).await;
        for framing in EndStreamFraming::ALL {
            let accepts: &[Option<&str>] = if encoding == "identity" {
                // Cover both passthrough and encoding an uncompressed origin.
                &[None, Some("identity"), Some("gzip")]
            } else {
                &[None, Some(encoding)]
            };
            for &accept in accepts {
                for inspection in [false, true] {
                    for protocol in [Protocol::H2, Protocol::H1] {
                        tokio::time::timeout(Duration::from_secs(5), async {
                            let mut tasks = Tasks::default();
                            let (source, origin_wire) =
                                origin_h2(data.clone(), encoding, framing, &mut tasks).await;
                            let count = Arc::new(AtomicUsize::new(0));
                            let output =
                                recompress(source, accept, inspection, count.clone()).await;
                            let output = Mutex::new(Some(output));
                            let service = service_fn(move |_: Request| {
                                let output = output.lock().take().unwrap();
                                async { Ok::<_, Infallible>(output) }
                            });
                            let (response, wire) = exchange(
                                protocol,
                                service,
                                request(accept, Body::empty()),
                                &mut tasks,
                            )
                            .await;
                            assert_eq!(
                                response
                                    .headers()
                                    .get("content-encoding")
                                    .map(|v| v.to_str().unwrap()),
                                accept.filter(|v| *v != "identity")
                            );
                            assert_eq!(
                                decoded(response).await,
                                PAYLOAD,
                                "{encoding}, {framing:?}, {protocol:?}"
                            );
                            assert_h2_frames(&origin_wire.lock(), Some(framing));
                            if matches!(protocol, Protocol::H2) {
                                assert_h2_frames(&wire.lock(), None);
                            }
                            if inspection
                                && framing == EndStreamFraming::EmptyData
                                && encoding != "zstd"
                            {
                                assert_eq!(
                                    count.load(Ordering::Relaxed),
                                    1,
                                    "missing trailing empty frame for {encoding}"
                                );
                            }
                        })
                        .await
                        .expect("proxy stream stalled");
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn request_decompression_empty_frames_transport_matrix() {
    for encoding in ENCODINGS {
        let data = encoded(encoding).await;
        for framing in EndStreamFraming::ALL {
            for protocol in [Protocol::H2, Protocol::H1] {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let mut tasks = Tasks::default();
                    let service = RequestDecompression::new(service_fn(
                        |request: Request<DecompressionBody<Body>>| async {
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            assert_eq!(bytes, PAYLOAD);
                            Ok::<_, Infallible>(Response::new(Body::from(bytes)))
                        },
                    ));
                    // Also cover leading and interleaved empty application frames.
                    let mut frames = framing.body(data.slice(data.len() / 2..));
                    frames.0.push_front(Frame::data(Bytes::new()));
                    frames
                        .0
                        .push_front(Frame::data(data.slice(..data.len() / 2)));
                    frames.0.push_front(Frame::data(Bytes::new()));
                    let mut req = request(None, Body::new(Frames(frames.0)));
                    *req.method_mut() = rama_http::Method::POST;
                    if encoding != "identity" {
                        req.headers_mut()
                            .insert("content-encoding", encoding.parse().unwrap());
                    }
                    let (response, wire) = exchange(protocol, service, req, &mut tasks).await;
                    assert_eq!(decoded(response).await, PAYLOAD);
                    if matches!(protocol, Protocol::H2) {
                        assert_h2_frames(&wire.lock(), None);
                    }
                })
                .await
                .expect("request stream stalled");
            }
        }
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn mid_body_failure_warns_before_reset() {
    use rama_core::futures::{StreamExt, stream};

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut tasks = Tasks::default();
        let fail = Arc::new(tokio::sync::Notify::new());
        let failed = fail.clone();
        let body = Body::from_stream(
            stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(PAYLOAD))]).chain(
                stream::once(async move {
                    failed.notified().await;
                    Err(std::io::Error::other("deliberate mid-body failure"))
                }),
            ),
        );
        let body = Mutex::new(Some(body));
        let service = service_fn(move |_: Request| {
            let body = body.lock().take().unwrap();
            async { Ok::<_, Infallible>(response(body, "identity")) }
        });
        let (mut response, _) = exchange(
            Protocol::H2,
            service,
            request(None, Body::empty()),
            &mut tasks,
        )
        .await;
        // Release the error only after headers and real data reached the client.
        let first = response.body_mut().frame().await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), PAYLOAD);
        fail.notify_one();
        response.into_body().collect().await.unwrap_err();
    })
    .await
    .expect("mid-body error was not delivered");
    // HTTP request spans are roots, so select the library target instead of
    // the test span and match this test's unique error message.
    tracing_test::internal::logs_assert("rama_http_core::proto::h2", |lines| {
        if lines.iter().any(|line| {
            line.contains("WARN")
                && line.contains("send body user stream error")
                && line.contains("deliberate mid-body failure")
        }) {
            Ok(())
        } else {
            Err("missing warning for the body error that resets the stream".into())
        }
    })
    .unwrap();
}
