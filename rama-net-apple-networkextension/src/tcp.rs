use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    ServiceInput,
    extensions::{Extensions, ExtensionsRef},
    rt::Executor,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

pin_project! {
    /// A per-flow stream presented to the Rama user.
    ///
    /// This behaves like a normal bidirectional byte stream and implements
    /// tokio [`AsyncRead`] + [`AsyncWrite`] + Rama [`Extensions`].
    pub struct TcpFlow {
        #[pin]
        inner: DuplexStream,
        extensions: Extensions,
        executor: Option<Executor>,
    }
}

impl TcpFlow {
    #[must_use]
    pub(crate) fn new(inner: DuplexStream, executor: Option<Executor>) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
            executor,
        }
    }

    /// Consume the [`TcpFlow`] by mapping the input and
    /// returning this as a new generic [`ServiceInput`].
    pub fn map_input<Input>(self, map: impl FnOnce(DuplexStream) -> Input) -> ServiceInput<Input> {
        let Self {
            inner: duplex_stream,
            extensions,
            executor: _,
        } = self;

        ServiceInput {
            input: map(duplex_stream),
            extensions,
        }
    }

    #[must_use]
    pub fn executor(&self) -> Option<&Executor> {
        self.executor.as_ref()
    }
}

impl ExtensionsRef for TcpFlow {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for TcpFlow {
    #[inline(always)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpFlow {
    #[inline(always)]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline(always)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline(always)]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
