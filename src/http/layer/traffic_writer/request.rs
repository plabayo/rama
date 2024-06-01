use super::WriterMode;
use crate::error::{BoxError, ErrorExt, OpaqueError};
use crate::http::dep::http_body;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::io::write_http_request;
use crate::http::{Body, Request, Response};
use crate::rt::Executor;
use crate::service::{Context, Layer, Service};
use bytes::Bytes;
use std::fmt::Debug;
use std::future::Future;
use tokio::io::{stderr, stdout, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{channel, unbounded_channel, Sender, UnboundedSender};

/// Layer that applies [`RequestWriterService`] which prints the http request in std format.
pub struct RequestWriterLayer<W> {
    writer: W,
}

impl<W> Debug for RequestWriterLayer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestWriterLayer")
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<W: Clone> Clone for RequestWriterLayer<W> {
    fn clone(&self) -> Self {
        Self {
            writer: self.writer.clone(),
        }
    }
}

impl<W> RequestWriterLayer<W> {
    /// Create a new [`RequestWriterLayer`] with a custom [`RequestWriter`].
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

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
    pub fn new() -> Self {
        Self
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
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };
        executor.spawn_task(async move {
            while let Some(req) = rx.recv().await {
                if let Err(err) =
                    write_http_request(&mut writer, req, write_headers, write_body).await
                {
                    tracing::error!(err = %err, "failed to write http request to writer")
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }
        });
        Self { writer: tx }
    }

    /// Create a new [`RequestWriterLayer`] that prints requests to stdout
    /// over an unbounded channel.
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stdout(), mode)
    }

    /// Create a new [`RequestWriterLayer`] that prints requests to stderr
    /// over an unbounded channel.
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stderr(), mode)
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
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };
        executor.spawn_task(async move {
            while let Some(req) = rx.recv().await {
                if let Err(err) =
                    write_http_request(&mut writer, req, write_headers, write_body).await
                {
                    tracing::error!(err = %err, "failed to write http request to writer")
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }
        });
        Self { writer: tx }
    }

    /// Create a new [`RequestWriterLayer`] that prints requests to stdout
    /// over a bounded channel with a fixed buffer size.
    pub fn stdout(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`RequestWriterLayer`] that prints requests to stderr
    /// over a bounded channel with a fixed buffer size.
    pub fn stderr(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode)
    }
}

impl<S, W: Clone> Layer<S> for RequestWriterLayer<W> {
    type Service = RequestWriterService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestWriterService {
            inner,
            writer: self.writer.clone(),
        }
    }
}

/// Middleware to print Http request in std format.
///
/// See the [module docs](super) for more details.
pub struct RequestWriterService<S, W> {
    inner: S,
    writer: W,
}

impl<S, W> RequestWriterService<S, W> {
    /// Create a new [`RequestWriterService`] with a custom [`RequestWriter`].
    pub fn new(writer: W, inner: S) -> Self {
        Self { inner, writer }
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

impl<S: Clone, W: Clone> Clone for RequestWriterService<S, W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl<S> RequestWriterService<S, UnboundedSender<Request>> {
    /// Create a new [`RequestWriterService`] that prints requests to an [`AsyncWrite`]r
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
        let layer = RequestWriterLayer::writer_unbounded(executor, writer, mode);
        layer.layer(inner)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over an unbounded channel.
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>, inner: S) -> Self {
        Self::writer_unbounded(executor, stdout(), mode, inner)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
    /// over an unbounded channel.
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>, inner: S) -> Self {
        Self::writer_unbounded(executor, stderr(), mode, inner)
    }
}

impl<S> RequestWriterService<S, Sender<Request>> {
    /// Create a new [`RequestWriterService`] that prints requests to an [`AsyncWrite`]r
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
        let layer = RequestWriterLayer::writer(executor, writer, buffer_size, mode);
        layer.layer(inner)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stdout
    /// over a bounded channel with a fixed buffer size.
    pub fn stdout(
        executor: &Executor,
        buffer_size: usize,
        mode: Option<WriterMode>,
        inner: S,
    ) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode, inner)
    }

    /// Create a new [`RequestWriterService`] that prints requests to stderr
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

impl<S, W> RequestWriterService<S, W> {}

impl<State, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>> for RequestWriterService<S, W>
where
    State: Send + Sync + 'static,
    S: Service<State, Request, Response = Response<ResBody>>,
    S::Error: Into<BoxError>,
    W: RequestWriter,
    ReqBody: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = match ctx.get::<DoNotWriteRequest>() {
            Some(_) => req.map(Body::new),
            None => {
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
            }
        };
        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

impl RequestWriter for Sender<Request> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.send(req).await {
            tracing::error!(err = %err, "failed to send request to channel")
        }
    }
}

impl RequestWriter for UnboundedSender<Request> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.send(req) {
            tracing::error!(err = %err, "failed to send request to unbounded channel")
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
