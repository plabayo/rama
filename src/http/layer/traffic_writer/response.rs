use super::WriterMode;
use crate::error::{BoxError, ErrorContext, OpaqueError};
use crate::http::dep::http_body;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::io::write_http_response;
use crate::http::{Body, Request, Response};
use crate::rt::Executor;
use crate::service::{Context, Layer, Service};
use bytes::Bytes;
use std::fmt::Debug;
use std::future::Future;
use tokio::io::{stderr, stdout, AsyncWrite};
use tokio::sync::mpsc::{channel, unbounded_channel, Sender, UnboundedSender};

/// Layer that applies [`ResponseWriterService`] which prints the http response in std format.
pub struct ResponseWriterLayer<W> {
    writer: W,
}

impl<W> Debug for ResponseWriterLayer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseWriterLayer")
            .field("writer", &format_args!("{}", std::any::type_name::<W>()))
            .finish()
    }
}

impl<W: Clone> Clone for ResponseWriterLayer<W> {
    fn clone(&self) -> Self {
        Self {
            writer: self.writer.clone(),
        }
    }
}

impl<W> ResponseWriterLayer<W> {
    /// Create a new [`ResponseWriterLayer`] with a custom [`ResponseWriter`].
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

/// A trait for writing http responses.
pub trait ResponseWriter: Send + Sync + 'static {
    /// Write the http response.
    fn write_response(&self, res: Response) -> impl Future<Output = ()> + Send + '_;
}

/// Marker struct to indicate that the response should not be printed.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DoNotWriteResponse;

impl DoNotWriteResponse {
    /// Create a new [`DoNotWriteResponse`] marker.
    pub fn new() -> Self {
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
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };
        executor.spawn_task(async move {
            while let Some(res) = rx.recv().await {
                if let Err(err) =
                    write_http_response(&mut writer, res, write_headers, write_body).await
                {
                    tracing::error!(err = %err, "failed to write http response to writer")
                }
            }
        });
        Self { writer: tx }
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stdout
    /// over an unbounded channel.
    pub fn stdout_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stdout(), mode)
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stderr
    /// over an unbounded channel.
    pub fn stderr_unbounded(executor: &Executor, mode: Option<WriterMode>) -> Self {
        Self::writer_unbounded(executor, stderr(), mode)
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
        let (write_headers, write_body) = match mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };
        executor.spawn_task(async move {
            while let Some(res) = rx.recv().await {
                if let Err(err) =
                    write_http_response(&mut writer, res, write_headers, write_body).await
                {
                    tracing::error!(err = %err, "failed to write http response to writer")
                }
            }
        });
        Self { writer: tx }
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stdout
    /// over a bounded channel with a fixed buffer size.
    pub fn stdout(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stdout(), buffer_size, mode)
    }

    /// Create a new [`ResponseWriterLayer`] that prints responses to stderr
    /// over a bounded channel with a fixed buffer size.
    pub fn stderr(executor: &Executor, buffer_size: usize, mode: Option<WriterMode>) -> Self {
        Self::writer(executor, stderr(), buffer_size, mode)
    }
}

impl<S, W: Clone> Layer<S> for ResponseWriterLayer<W> {
    type Service = ResponseWriterService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseWriterService {
            inner,
            writer: self.writer.clone(),
        }
    }
}

/// Middleware to print Http request in std format.
///
/// See the [module docs](super) for more details.
pub struct ResponseWriterService<S, W> {
    inner: S,
    writer: W,
}

impl<S, W> ResponseWriterService<S, W> {
    /// Create a new [`ResponseWriterService`] with a custom [`ResponseWriter`].
    pub fn new(writer: W, inner: S) -> Self {
        Self { inner, writer }
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

impl<S: Clone, W: Clone> Clone for ResponseWriterService<S, W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            writer: self.writer.clone(),
        }
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
        layer.layer(inner)
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
        layer.layer(inner)
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

impl<State, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>> for ResponseWriterService<S, W>
where
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Into<BoxError>,
    W: ResponseWriter,
    ReqBody: Send + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let do_not_print_response: Option<DoNotWriteResponse> = ctx.get().cloned();
        let resp = self.inner.serve(ctx, req).await.map_err(Into::into)?;
        let resp = match do_not_print_response {
            Some(_) => resp.map(Body::new),
            None => {
                let (parts, body) = resp.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map_err(|err| OpaqueError::from_boxed(err.into()))
                    .context("printer prepare: collect response body")?
                    .to_bytes();
                let resp: http::Response<Body> =
                    Response::from_parts(parts.clone(), Body::from(body_bytes.clone()));
                self.writer.write_response(resp).await;
                Response::from_parts(parts, Body::from(body_bytes))
            }
        };
        Ok(resp)
    }
}

impl ResponseWriter for Sender<Response> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.send(res).await {
            tracing::error!(err = %err, "failed to send response to channel")
        }
    }
}

impl ResponseWriter for UnboundedSender<Response> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.send(res) {
            tracing::error!(err = %err, "failed to send response to unbounded channel")
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
