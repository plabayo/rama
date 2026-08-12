use super::{PerMessageFileWriter, WriterMode, capture_body_channel, write_headers_body_flags};
use crate::io::write_http_response_streaming;
use crate::{Body, Request, Response, StreamingBody, body::util::BodyExt as _};
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Layer, Service};
use rama_http_types::CaptureBody;
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt::Debug, io, path::PathBuf, sync::Arc};
use tokio::io::{AsyncWrite, stderr, stdout};
use tokio::sync::mpsc::{Sender, UnboundedSender, channel, unbounded_channel};

/// Layer that applies [`ResponseWriterService`] which prints the http response in std format.
///
/// Response bodies are observed while they stream to the caller. The writer
/// receives an owned body stream and processes frames concurrently.
#[derive(Clone)]
pub struct ResponseWriterLayer<W> {
    writer: W,
    executor: Executor,
}

impl<W> Debug for ResponseWriterLayer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseWriterLayer")
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<W> ResponseWriterLayer<W> {
    /// Create a new [`ResponseWriterLayer`] with a custom [`ResponseWriter`].
    ///
    /// Use [`Self::new_with_executor`] when streaming writer tasks must participate
    /// in graceful shutdown.
    pub const fn new(writer: W) -> Self {
        Self::new_with_executor(writer, Executor::new())
    }

    /// Create a new [`ResponseWriterLayer`] with a custom [`ResponseWriter`]
    /// and executor for streaming writer tasks.
    pub const fn new_with_executor(writer: W, executor: Executor) -> Self {
        Self { writer, executor }
    }
}

/// A trait for writing http responses.
pub trait ResponseWriter: Send + Sync + 'static {
    /// Write the HTTP response while its body is streaming.
    ///
    /// Implementations must consume or deliberately drop the body while this
    /// future runs. Retaining it for later applies backpressure once its
    /// single-frame observational capture queue is full.
    fn write_response(&self, res: Response) -> impl Future<Output = ()> + Send + '_;
}

/// Marker struct to indicate that the response should not be printed.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub struct DoNotWriteResponse;

impl DoNotWriteResponse {
    /// Create a new [`DoNotWriteResponse`] marker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ResponseWriterLayer<UnboundedSender<Response>> {
    /// Create a new [`ResponseWriterLayer`] that prints responses to an [`AsyncWrite`]r
    /// over an unbounded channel
    pub fn writer_unbounded<W>(executor: &Executor, mut writer: W, mode: Option<WriterMode>) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_headers, write_body) = write_headers_body_flags(mode);

        let span =
            tracing::trace_root_span!("TrafficWriter::response::unbounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(res) = rx.recv().await {
                    if let Err(err) =
                        write_http_response_streaming(&mut writer, res, write_headers, write_body)
                            .await
                    {
                        tracing::error!("failed to write http response to writer: {err:?}")
                    }
                }
            }
            .instrument(span),
        );

        Self {
            writer: tx,
            executor: executor.clone(),
        }
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stdout(), mode)
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stderr(), mode)
    }
}

impl ResponseWriterLayer<PerMessageFileWriter> {
    /// Create a layer that streams every response into a unique file below
    /// `directory` using the portable filename `prefix`.
    pub async fn file_per_response(
        executor: &Executor,
        directory: impl Into<PathBuf>,
        prefix: impl AsRef<str>,
        mode: Option<WriterMode>,
    ) -> io::Result<Self> {
        let writer = PerMessageFileWriter::try_new(directory, prefix)
            .await?
            .with_request_mode(None)
            .with_response_mode(mode);
        Ok(Self::new_with_executor(writer, executor.clone()))
    }
}

impl ResponseWriterLayer<Sender<Response>> {
    /// Create a new [`ResponseWriterLayer`] that prints responses to an [`AsyncWrite`]r
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
            tracing::trace_root_span!("TrafficWriter::response::bounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(res) = rx.recv().await {
                    if let Err(err) =
                        write_http_response_streaming(&mut writer, res, write_headers, write_body)
                            .await
                    {
                        tracing::error!("failed to write http response to writer: {err:?}")
                    }
                }
            }
            .instrument(span),
        );
        Self {
            writer: tx,
            executor: executor.clone(),
        }
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stdout
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stdout(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stderr
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stderr(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode)
    }
}

impl<S, W: Clone> Layer<S> for ResponseWriterLayer<W> {
    type Service = ResponseWriterService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseWriterService {
            inner,
            writer: Arc::new(self.writer.clone()),
            executor: self.executor.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ResponseWriterService {
            inner,
            writer: Arc::new(self.writer),
            executor: self.executor,
        }
    }
}

/// Middleware to print Http responses in std format.
///
/// Response bodies are observed while they stream to the caller. The writer
/// receives an owned body stream and processes frames concurrently.
///
/// See the [module docs](super) for more details.
#[derive(Clone)]
pub struct ResponseWriterService<S, W> {
    inner: S,
    writer: Arc<W>,
    executor: Executor,
}

impl<S, W> ResponseWriterService<S, W> {
    /// Create a new [`ResponseWriterService`] with a custom [`ResponseWriter`].
    ///
    /// Use [`Self::new_with_executor`] when streaming writer tasks must participate
    /// in graceful shutdown.
    pub fn new(writer: W, inner: S) -> Self {
        Self::new_with_executor(writer, inner, Executor::new())
    }

    /// Create a new [`ResponseWriterService`] with a custom [`ResponseWriter`]
    /// and executor for streaming writer tasks.
    pub fn new_with_executor(writer: W, inner: S, executor: Executor) -> Self {
        Self {
            inner,
            writer: Arc::new(writer),
            executor,
        }
    }

    define_inner_service_accessors!();
}

impl<S: Debug, W> Debug for ResponseWriterService<S, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseWriterService")
            .field("inner", &self.inner)
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<S> ResponseWriterService<S, UnboundedSender<Response>> {
    /// Create a new [`ResponseWriterService`] that prints responses to an [`AsyncWrite`]r
    /// over an unbounded channel
    pub fn writer_unbounded<W>(
        executor: &Executor,
        writer: W,
        mode: Option<WriterMode>,
        inner: S,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let layer = ResponseWriterLayer::writer_unbounded(executor, writer, mode);
        layer.into_layer(inner)
    }

    /// Create a new [`ResponseWriterService`] that prints responses to stdout
    /// over an unbounded channel.
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>, inner: S) -> Self {
        Self::writer_unbounded(executor, stdout(), mode, inner)
    }

    /// Create a new [`ResponseWriterService`] that prints responses to stderr
    /// over an unbounded channel.
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>, inner: S) -> Self {
        Self::writer_unbounded(executor, stderr(), mode, inner)
    }
}

impl<S> ResponseWriterService<S, PerMessageFileWriter> {
    /// Create a service that streams every response into a unique file below
    /// `directory` using the portable filename `prefix`.
    pub async fn file_per_response(
        executor: &Executor,
        directory: impl Into<PathBuf>,
        prefix: impl AsRef<str>,
        mode: Option<WriterMode>,
        inner: S,
    ) -> io::Result<Self> {
        let layer =
            ResponseWriterLayer::file_per_response(executor, directory, prefix, mode).await?;
        Ok(layer.into_layer(inner))
    }
}

impl<S> ResponseWriterService<S, Sender<Response>> {
    /// Create a new [`ResponseWriterService`] that prints responses to an [`AsyncWrite`]r
    /// over a bounded channel with a fixed buffer size.
    pub fn writer<W>(
        executor: &Executor,
        writer: W,
        buffer_size: usize,
        mode: Option<WriterMode>,
        inner: S,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let layer = ResponseWriterLayer::writer(executor, writer, buffer_size, mode);
        layer.into_layer(inner)
    }

    /// Create a new [`ResponseWriterService`] that prints responses to stdout
    /// over a bounded channel with a fixed buffer size.
    pub fn stdout(
        executor: &Executor,
        buffer_size: usize,
        mode: Option<WriterMode>,
        inner: S,
    ) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode, inner)
    }

    /// Create a new [`ResponseWriterService`] that prints responses to stderr
    /// over a bounded channel with a fixed buffer size.
    pub fn stderr(
        executor: &Executor,
        buffer_size: usize,
        mode: Option<WriterMode>,
        inner: S,
    ) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode, inner)
    }
}

impl<S, W> ResponseWriterService<S, W> {}

impl<S, W, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseWriterService<S, W>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    W: ResponseWriter,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let do_not_print_response: Option<Arc<DoNotWriteResponse>> = req.extensions().get_arc();
        let resp = self.inner.serve(req).await.into_box_error()?;
        let resp = if do_not_print_response.is_some() {
            resp.map(Body::new)
        } else {
            let (parts, body) = resp.into_parts();
            let (capture, captured_body) = capture_body_channel();
            let captured_parts = parts.clone();
            let writer = Arc::clone(&self.writer);
            self.executor.spawn_task(async move {
                writer
                    .write_response(Response::from_parts(captured_parts, captured_body))
                    .await;
            });
            Response::from_parts(
                parts,
                Body::new(CaptureBody::new(body.map_err(Into::into), capture)),
            )
        };
        Ok(resp)
    }
}

impl ResponseWriter for Sender<Response> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.send(res).await {
            tracing::error!("failed to send response to channel: {err:?}")
        }
    }
}

impl ResponseWriter for UnboundedSender<Response> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.send(res) {
            tracing::error!("failed to send response to unbounded channel: {err:?}")
        }
    }
}

impl<F, Fut> ResponseWriter for F
where
    F: Fn(Response) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    async fn write_response(&self, res: Response) {
        self(res).await
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

    #[tokio::test]
    async fn file_constructors_only_enable_response_capture() {
        let temp = tempfile::tempdir().unwrap();
        let executor = Executor::new();
        let layer = ResponseWriterLayer::file_per_response(
            &executor,
            temp.path(),
            "responses",
            Some(WriterMode::Headers),
        )
        .await
        .unwrap();
        assert_eq!(layer.writer.request_mode(), None);
        assert_eq!(layer.writer.response_mode(), Some(WriterMode::Headers));

        let service = ResponseWriterService::file_per_response(
            &executor,
            temp.path(),
            "responses",
            Some(WriterMode::Body),
            (),
        )
        .await
        .unwrap();
        assert_eq!(service.writer.request_mode(), None);
        assert_eq!(service.writer.response_mode(), Some(WriterMode::Body));
    }

    #[tokio::test]
    async fn writer_observes_response_as_the_caller_streams_it() {
        let polls = Arc::new(AtomicUsize::new(0));
        let response_polls = Arc::clone(&polls);
        let (writer, mut written) = tokio::sync::mpsc::unbounded_channel();
        let service =
            ResponseWriterLayer::new(writer).into_layer(service_fn(move |_request: Request| {
                let polls = Arc::clone(&response_polls);
                async move {
                    let body = Body::from_stream(rama_core::futures::stream::once(async move {
                        polls.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, Infallible>(Bytes::from_static(b"streamed response"))
                    }));
                    Ok::<_, Infallible>(Response::new(body))
                }
            }));

        let response = service.serve(Request::new(Body::empty())).await.unwrap();
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        written.try_recv().unwrap_err();

        let written_response =
            tokio::time::timeout(std::time::Duration::from_secs(1), written.recv())
                .await
                .expect("response capture should arrive promptly")
                .unwrap();
        let (response, captured) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(
                response.into_body().collect(),
                written_response.into_body().collect(),
            )
        })
        .await
        .expect("response streams should finish promptly");
        assert_eq!(
            response.unwrap().to_bytes(),
            Bytes::from_static(b"streamed response")
        );
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(
            captured.unwrap().to_bytes(),
            Bytes::from_static(b"streamed response")
        );
    }

    #[tokio::test]
    async fn shared_writer_backpressures_later_response_without_interleaving() {
        let (first_sender, first_receiver) = tokio::sync::mpsc::unbounded_channel();
        let first_receiver = Arc::new(tokio::sync::Mutex::new(Some(first_receiver)));
        let inner_receiver = Arc::clone(&first_receiver);
        let inner = service_fn(move |request: Request| {
            let first_receiver = Arc::clone(&inner_receiver);
            async move {
                let body = if request.headers().contains_key("x-long-lived") {
                    let receiver = first_receiver
                        .lock()
                        .await
                        .take()
                        .expect("the long-lived response is requested once");
                    Body::from_stream(rama_core::futures::stream::unfold(
                        receiver,
                        |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
                    ))
                } else {
                    Body::from("second")
                };
                Ok::<_, Infallible>(Response::new(body))
            }
        });
        let executor = Executor::new();
        let (writer, mut output) = tokio::io::duplex(64);
        let service =
            ResponseWriterLayer::writer_unbounded(&executor, writer, Some(WriterMode::Body))
                .into_layer(inner);

        let first_request = Request::builder()
            .header("x-long-lived", "true")
            .body(Body::empty())
            .unwrap();
        let first_response = service.serve(first_request).await.unwrap();
        let mut first_body = first_response.into_body();
        first_sender
            .send(Ok::<_, Infallible>(Bytes::from_static(b"first")))
            .unwrap();
        assert_eq!(
            first_body
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "first"
        );

        let mut first_output = [0; 7];
        tokio::time::timeout(Duration::from_secs(1), output.read_exact(&mut first_output))
            .await
            .expect("the writer should start draining the first response")
            .unwrap();
        assert_eq!(&first_output, b"\r\nfirst");

        let second_response = service.serve(Request::new(Body::empty())).await.unwrap();
        let mut second = Box::pin(second_response.into_body().collect());
        tokio::time::timeout(Duration::from_millis(50), &mut second)
            .await
            .expect_err("the shared writer must backpressure a later body");

        drop(first_body);
        drop(first_sender);
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("the later body should resume when the first capture ends")
            .unwrap();
        assert_eq!(second.to_bytes(), Bytes::from_static(b"second"));

        let mut second_output = [0; 8];
        tokio::time::timeout(
            Duration::from_secs(1),
            output.read_exact(&mut second_output),
        )
        .await
        .expect("the second response should be written after the first")
        .unwrap();
        assert_eq!(&second_output, b"\r\nsecond");
    }

    #[tokio::test]
    async fn headers_only_writer_does_not_consume_or_stall_live_body() {
        let inner = service_fn(|_request: Request| async {
            Ok::<_, Infallible>(
                Response::builder()
                    .header("x-written", "yes")
                    .body(Body::from("live payload"))
                    .unwrap(),
            )
        });
        let executor = Executor::new();
        let (writer, mut output) = tokio::io::duplex(128);
        let service =
            ResponseWriterLayer::writer_unbounded(&executor, writer, Some(WriterMode::Headers))
                .into_layer(inner);

        let response = service.serve(Request::new(Body::empty())).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"live payload")
        );
        drop(service);

        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), output.read_to_end(&mut written))
            .await
            .expect("the headers-only writer should shut down promptly")
            .unwrap();
        let written = String::from_utf8(written).unwrap();
        assert!(written.contains("HTTP/1.1 200 OK\r\n"));
        assert!(written.contains("x-written: yes\r\n"));
        assert!(!written.contains("live payload"));
    }
}
