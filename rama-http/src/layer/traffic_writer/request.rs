use super::{
    PerMessageFileWriter, WriterMode, capture_body_channel, ensure_traffic_writer_id,
    write_headers_body_flags,
};
use crate::io::write_http_request_streaming;
use crate::{Body, Request, StreamingBody, body::util::BodyExt as _};
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Layer, Service};
use rama_http_types::CaptureBody;
use std::{fmt::Debug, io, path::PathBuf, sync::Arc};
use tokio::io::{AsyncWrite, AsyncWriteExt, stderr, stdout};
use tokio::sync::mpsc::{Sender, UnboundedSender, channel, unbounded_channel};

/// Write a single request entry (request followed by a `\r\n` separator) to the writer.
async fn write_request_entry<W>(writer: &mut W, req: Request, write_headers: bool, write_body: bool)
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    if let Err(err) = write_http_request_streaming(writer, req, write_headers, write_body).await {
        tracing::error!("failed to write http request to writer: {err:?}")
    }
    if let Err(err) = writer.write_all(b"\r\n").await {
        tracing::error!("failed to write separator to writer: {err:?}")
    }
}

/// A trait for writing http requests.
pub trait RequestWriter: Send + Sync + 'static {
    /// Write the HTTP request while its body is streaming.
    ///
    /// Implementations must consume or deliberately drop the body while this
    /// future runs. Retaining it for later applies backpressure once its
    /// single-frame observational capture queue is full.
    fn write_request(&self, req: Request) -> impl Future<Output = ()> + Send + '_;
}

/// Marker struct to indicate that the request should not be printed.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub struct DoNotWriteRequest;

impl DoNotWriteRequest {
    /// Create a new [`DoNotWriteRequest`] marker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Clone)]
/// Middleware to print Http request in std format.
///
/// Request bodies are observed while they stream to the inner service. The
/// writer receives an owned body stream and processes frames concurrently.
///
/// See the [module docs](super) for more details.
pub struct RequestWriterService<S, W> {
    inner: S,
    writer: Arc<W>,
    executor: Executor,
}

impl<S, W> RequestWriterService<S, W> {
    /// Create a new [`RequestWriterService`] with a custom [`RequestWriter`].
    ///
    /// Use [`Self::new_with_executor`] when streaming writer tasks must
    /// participate in graceful shutdown.
    pub fn new(inner: S, writer: W) -> Self {
        Self::new_with_executor(inner, writer, Executor::new())
    }

    /// Create a new [`RequestWriterService`] with a custom [`RequestWriter`]
    /// and executor for streaming writer tasks.
    pub fn new_with_executor(inner: S, writer: W, executor: Executor) -> Self {
        Self {
            inner,
            writer: Arc::new(writer),
            executor,
        }
    }
}

impl<S: Debug, W> Debug for RequestWriterService<S, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestWriterService")
            .field("inner", &self.inner)
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<S> RequestWriterService<S, UnboundedSender<Request>> {
    /// Create a new [`RequestWriterService`] that prints requests to an [`AsyncWrite`]r
    /// over an unbounded channel
    pub fn writer_unbounded<W>(
        inner: S,
        executor: &Executor,
        mut writer: W,
        mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_headers, write_body) = write_headers_body_flags(mode);

        let span =
            tracing::trace_root_span!("TrafficWriter::request::unbounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    write_request_entry(&mut writer, req, write_headers, write_body).await;
                }
            }
            .instrument(span),
        );
        Self {
            writer: Arc::new(tx),
            inner,
            executor: executor.clone(),
        }
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(inner: S, executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(inner, executor, stdout(), mode)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(inner: S, executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(inner, executor, stderr(), mode)
    }
}

impl<S> RequestWriterService<S, PerMessageFileWriter> {
    /// Create a service that streams every request into a unique file below
    /// `directory` using the portable filename `prefix`.
    pub async fn file_per_request(
        inner: S,
        executor: &Executor,
        directory: impl Into<PathBuf>,
        prefix: impl AsRef<str>,
        mode: Option<WriterMode>,
    ) -> io::Result<Self> {
        let writer = PerMessageFileWriter::try_new(directory, prefix)
            .await?
            .with_request_mode(mode)
            .with_response_mode(None);
        Ok(Self::new_with_executor(inner, writer, executor.clone()))
    }
}

impl<S> RequestWriterService<S, Sender<Request>> {
    /// Create a new [`RequestWriterService`] that prints requests to an [`AsyncWrite`]r
    /// over a bounded channel with a fixed buffer size.
    pub fn writer<W>(
        inner: S,
        executor: &Executor,
        mut writer: W,
        buffer_size: usize,
        mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(buffer_size);
        let (write_headers, write_body) = write_headers_body_flags(mode);

        let span =
            tracing::trace_root_span!("TrafficWriter::request::bounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    write_request_entry(&mut writer, req, write_headers, write_body).await;
                }
            }
            .instrument(span),
        );
        Self {
            writer: Arc::new(tx),
            inner,
            executor: executor.clone(),
        }
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stdout(
        inner: S,
        executor: &Executor,
        buffer_size: usize,
        mode: Option<WriterMode>,
    ) -> Self {
        Self::writer(inner, executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stderr(
        inner: S,
        executor: &Executor,
        buffer_size: usize,
        mode: Option<WriterMode>,
    ) -> Self {
        Self::writer(inner, executor, stderr(), buffer_size, mode)
    }
}

impl<S, W, ReqBody> Service<Request<ReqBody>> for RequestWriterService<S, W>
where
    S: Service<Request, Error: Into<BoxError>>,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    W: RequestWriter,
{
    type Error = BoxError;
    type Output = S::Output;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if req.extensions().get_ref::<DoNotWriteRequest>().is_some() {
            self.inner.serve(req.map(Body::new)).await.into_box_error()
        } else {
            ensure_traffic_writer_id(req.extensions());
            let (parts, body) = req.into_parts();
            let (capture, captured_body) = capture_body_channel();
            let captured_parts = parts.clone();
            let captured_request = Request::from_parts(captured_parts, captured_body);
            let request = Request::from_parts(
                parts,
                Body::new(CaptureBody::new(body.map_err(Into::into), capture)),
            );
            let writer = Arc::clone(&self.writer);
            self.executor.spawn_task(async move {
                writer.write_request(captured_request).await;
            });
            self.inner.serve(request).await.into_box_error()
        }
    }
}

impl RequestWriter for Sender<Request> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.send(req).await {
            tracing::error!("failed to send request to channel: {err:?}")
        }
    }
}

impl RequestWriter for UnboundedSender<Request> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.send(req) {
            tracing::error!("failed to send request to unbounded channel: {err:?}")
        }
    }
}

impl<F, Fut> RequestWriter for F
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    async fn write_request(&self, req: Request) {
        self(req).await
    }
}

#[derive(Clone)]
/// Middleware to print Http request in std format.
///
/// Request bodies are observed while they stream to the inner service. The
/// writer receives an owned body stream and processes frames concurrently.
///
/// See the [module docs](super) for more details.
pub struct RequestWriterLayer<W> {
    writer: W,
    executor: Executor,
}

impl<W> RequestWriterLayer<W> {
    /// Create a new [`RequestWriterLayer`] with a custom [`RequestWriter`].
    ///
    /// Use [`Self::new_with_executor`] when streaming writer tasks must
    /// participate in graceful shutdown.
    pub const fn new(writer: W) -> Self {
        Self::new_with_executor(writer, Executor::new())
    }

    /// Create a new [`RequestWriterLayer`] with a custom [`RequestWriter`] and
    /// executor for streaming writer tasks.
    pub const fn new_with_executor(writer: W, executor: Executor) -> Self {
        Self { writer, executor }
    }
}

impl<W> Debug for RequestWriterLayer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestWriterLayer")
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl RequestWriterLayer<UnboundedSender<Request>> {
    /// Create a new [`RequestWriterLayer`] that prints requests to an [`AsyncWrite`]r
    /// over an unbounded channel
    pub fn writer_unbounded<W>(executor: &Executor, mut writer: W, mode: Option<WriterMode>) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_headers, write_body) = write_headers_body_flags(mode);

        let span =
            tracing::trace_root_span!("TrafficWriter::request::unbounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    write_request_entry(&mut writer, req, write_headers, write_body).await;
                }
            }
            .instrument(span),
        );
        Self {
            writer: tx,
            executor: executor.clone(),
        }
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stdout(), mode)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stderr(), mode)
    }
}

impl RequestWriterLayer<PerMessageFileWriter> {
    /// Create a layer that streams every request into a unique file below
    /// `directory` using the portable filename `prefix`.
    pub async fn file_per_request(
        executor: &Executor,
        directory: impl Into<PathBuf>,
        prefix: impl AsRef<str>,
        mode: Option<WriterMode>,
    ) -> io::Result<Self> {
        let writer = PerMessageFileWriter::try_new(directory, prefix)
            .await?
            .with_request_mode(mode)
            .with_response_mode(None);
        Ok(Self::new_with_executor(writer, executor.clone()))
    }
}

impl RequestWriterLayer<Sender<Request>> {
    /// Create a new [`RequestWriterLayer`] that prints requests to an [`AsyncWrite`]r
    /// over a bounded channel with a fixed buffer size.
    pub fn writer<W>(
        executor: &Executor,
        mut writer: W,
        buffer_size: usize,
        mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(buffer_size);
        let (write_headers, write_body) = write_headers_body_flags(mode);

        let span =
            tracing::trace_root_span!("TrafficWriter::request::bounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    write_request_entry(&mut writer, req, write_headers, write_body).await;
                }
            }
            .instrument(span),
        );
        Self {
            writer: tx,
            executor: executor.clone(),
        }
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stdout(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stderr(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode)
    }
}

impl<S, W: Clone> Layer<S> for RequestWriterLayer<W> {
    type Service = RequestWriterService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestWriterService {
            inner,
            writer: Arc::new(self.writer.clone()),
            executor: self.executor.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        RequestWriterService {
            inner,
            writer: Arc::new(self.writer),
            executor: self.executor,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rama_core::{Layer as _, Service as _, service::service_fn};
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::Response;
    use crate::layer::traffic_writer::TrafficWriterId;

    #[tokio::test]
    async fn file_constructors_only_enable_request_capture() {
        let temp = tempfile::tempdir().unwrap();
        let executor = Executor::new();
        let layer = RequestWriterLayer::file_per_request(
            &executor,
            temp.path(),
            "requests",
            Some(WriterMode::Headers),
        )
        .await
        .unwrap();
        assert_eq!(layer.writer.request_mode(), Some(WriterMode::Headers));
        assert_eq!(layer.writer.response_mode(), None);

        let service = RequestWriterService::file_per_request(
            (),
            &executor,
            temp.path(),
            "requests",
            Some(WriterMode::Body),
        )
        .await
        .unwrap();
        assert_eq!(service.writer.request_mode(), Some(WriterMode::Body));
        assert_eq!(service.writer.response_mode(), None);
    }

    #[tokio::test]
    async fn request_writer_shares_private_id_with_inner_request() {
        let (writer, mut captured_requests) = tokio::sync::mpsc::unbounded_channel();
        let (seen_id, mut seen_ids) = tokio::sync::mpsc::unbounded_channel();
        let inner = service_fn(move |request: Request| {
            let seen_id = seen_id.clone();
            async move {
                seen_id
                    .send(*request.extensions().get_ref::<TrafficWriterId>().unwrap())
                    .unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });
        let service = RequestWriterLayer::new(writer).into_layer(inner);

        service.serve(Request::new(Body::empty())).await.unwrap();
        let captured = tokio::time::timeout(Duration::from_secs(1), captured_requests.recv())
            .await
            .unwrap()
            .unwrap();
        let request_id = tokio::time::timeout(Duration::from_secs(1), seen_ids.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            captured.extensions().get_ref::<TrafficWriterId>(),
            Some(&request_id)
        );
    }

    #[tokio::test]
    async fn writer_observes_request_without_collecting_before_inner_service() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body_polls = Arc::clone(&polls);
        let body = Body::from_stream(rama_core::futures::stream::once(async move {
            body_polls.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Infallible>(Bytes::from_static(b"streamed request"))
        }));
        let (writer, mut written) = tokio::sync::mpsc::unbounded_channel();
        let inner_polls = Arc::clone(&polls);
        let service =
            RequestWriterLayer::new(writer).into_layer(service_fn(move |request: Request| {
                let polls = Arc::clone(&inner_polls);
                async move {
                    assert_eq!(polls.load(Ordering::Relaxed), 0);
                    assert_eq!(
                        request.into_body().collect().await.unwrap().to_bytes(),
                        Bytes::from_static(b"streamed request")
                    );
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }));

        let serve = service.serve(Request::new(body));
        let observe = async {
            let request = written.recv().await.unwrap();
            request.into_body().collect().await.unwrap().to_bytes()
        };
        let (result, captured) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(serve, observe)
        })
        .await
        .expect("request capture should finish promptly");
        result.unwrap();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(captured, Bytes::from_static(b"streamed request"));
    }

    #[tokio::test]
    async fn retained_request_body_does_not_delay_the_response() {
        let (held_body, mut held_bodies) = tokio::sync::mpsc::unbounded_channel();
        let inner = service_fn(move |request: Request| {
            let held_body = held_body.clone();
            async move {
                held_body.send(request.into_body()).unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });
        let (writer_done, mut writer_completions) = tokio::sync::mpsc::unbounded_channel();
        let writer = move |request: Request| {
            let writer_done = writer_done.clone();
            async move {
                request.into_body().collect().await.unwrap();
                writer_done.send(()).unwrap();
            }
        };
        let service = RequestWriterLayer::new(writer).into_layer(inner);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            service.serve(Request::new(Body::from("retained"))),
        )
        .await
        .expect("the response must not wait for the request writer")
        .unwrap();

        let body = held_bodies.recv().await.unwrap();
        assert_eq!(
            body.collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"retained")
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), writer_completions.recv())
            .await
            .expect("the request writer should finish after the body is consumed")
            .unwrap();
    }

    #[tokio::test]
    async fn built_in_writer_emits_the_streaming_request_entry() {
        let inner = service_fn(|request: Request| async move {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                Bytes::from_static(b"payload")
            );
            Ok::<_, Infallible>(Response::new(Body::empty()))
        });
        let executor = Executor::new();
        let (writer, mut output) = tokio::io::duplex(256);
        let service =
            RequestWriterLayer::writer_unbounded(&executor, writer, Some(WriterMode::All))
                .into_layer(inner);

        service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("/upload")
                    .header("x-test", "yes")
                    .body(Body::from("payload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        drop(service);

        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), output.read_to_end(&mut written))
            .await
            .expect("the request writer should shut down promptly")
            .unwrap();
        let written = String::from_utf8(written).unwrap();
        assert!(written.starts_with("POST /upload HTTP/1.1\r\n"));
        assert!(written.contains("x-test: yes\r\n"));
        assert!(written.ends_with("\r\npayload\r\n"));
    }
}
