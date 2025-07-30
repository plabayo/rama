use super::WriterMode;
use crate::dep::http_body;
use crate::dep::http_body_util::BodyExt;
use crate::io::write_http_request;
use crate::{Body, Request};
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorExt, OpaqueError};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_core::{Context, Service};
use std::fmt::Debug;
use tokio::io::{AsyncWrite, AsyncWriteExt, stderr, stdout};
use tokio::sync::mpsc::{Sender, UnboundedSender, channel, unbounded_channel};

/// A trait for writing http requests.
pub trait RequestWriter: Send + Sync + 'static {
    /// Write the http request.
    fn write_request(&self, req: Request) -> impl Future<Output = ()> + Send + '_;
}

/// Marker struct to indicate that the request should not be printed.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DoNotWriteRequest;

impl DoNotWriteRequest {
    /// Create a new [`DoNotWriteRequest`] marker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Middleware to print Http request in std format.
///
/// See the [module docs](super) for more details.
pub struct RequestWriterInspector<W> {
    writer: W,
}

impl<W> RequestWriterInspector<W> {
    /// Create a new [`RequestWriterInspector`] with a custom [`RequestWriter`].
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W> Debug for RequestWriterInspector<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestWriterInspector")
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<W: Clone> Clone for RequestWriterInspector<W> {
    fn clone(&self) -> Self {
        Self {
            writer: self.writer.clone(),
        }
    }
}

impl RequestWriterInspector<UnboundedSender<Request>> {
    /// Create a new [`RequestWriterInspector`] that prints requests to an [`AsyncWrite`]r
    /// over an unbounded channel
    pub fn writer_unbounded<W>(executor: &Executor, mut writer: W, mode: Option<WriterMode>) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        let span =
            tracing::trace_root_span!("TrafficWriter::request::unbounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    if let Err(err) =
                        write_http_request(&mut writer, req, write_headers, write_body).await
                    {
                        tracing::error!("failed to write http request to writer: {err:?}")
                    }
                    if let Err(err) = writer.write_all(b"\r\n").await {
                        tracing::error!("failed to write separator to writer: {err:?}")
                    }
                }
            }
            .instrument(span),
        );
        Self { writer: tx }
    }

    /// Create a new [`RequestWriterInspector`] that prints requests to stdout
    /// over an unbounded channel.
    #[must_use]
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stdout(), mode)
    }

    /// Create a new [`RequestWriterInspector`] that prints requests to stderr
    /// over an unbounded channel.
    #[must_use]
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stderr(), mode)
    }
}

impl RequestWriterInspector<Sender<Request>> {
    /// Create a new [`RequestWriterInspector`] that prints requests to an [`AsyncWrite`]r
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
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        let span =
            tracing::trace_root_span!("TrafficWriter::request::bounded", otel.kind = "consumer");

        executor.spawn_task(
            async move {
                while let Some(req) = rx.recv().await {
                    if let Err(err) =
                        write_http_request(&mut writer, req, write_headers, write_body).await
                    {
                        tracing::error!("failed to write http request to writer: {err:?}")
                    }
                    if let Err(err) = writer.write_all(b"\r\n").await {
                        tracing::error!("failed to write separator to writer: {err:?}")
                    }
                }
            }
            .instrument(span),
        );
        Self { writer: tx }
    }

    /// Create a new [`RequestWriterInspector`] that prints requests to stdout
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stdout(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`RequestWriterInspector`] that prints requests to stderr
    /// over a bounded channel with a fixed buffer size.
    #[must_use]
    pub fn stderr(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode)
    }
}

impl<State, W, ReqBody> Service<State, Request<ReqBody>> for RequestWriterInspector<W>
where
    State: Clone + Send + Sync + 'static,
    W: RequestWriter,
    ReqBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Error = BoxError;
    type Response = (Context<State>, Request);

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<(Context<State>, Request), Self::Error> {
        let req = if ctx.get::<DoNotWriteRequest>().is_some() {
            req.map(Body::new)
        } else {
            let (parts, body) = req.into_parts();
            let body_bytes = body
                .collect()
                .await
                .map_err(|err| {
                    OpaqueError::from_boxed(err.into())
                        .context("printer prepare: collect request body")
                })?
                .to_bytes();
            let req = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));
            self.writer.write_request(req).await;
            Request::from_parts(parts, Body::from(body_bytes))
        };
        Ok((ctx, req))
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
