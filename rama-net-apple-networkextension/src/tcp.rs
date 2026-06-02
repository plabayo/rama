use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    rt::Executor,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tproxy::engine::ffi_stream::FfiBridgeStream;

pin_project! {
    /// A per-flow stream presented to the Rama user.
    ///
    /// This behaves like a normal bidirectional byte stream and implements
    /// tokio [`AsyncRead`] + [`AsyncWrite`] + Rama [`Extensions`]. The read
    /// side drains the client→service channel; the write side hands
    /// service→client bytes straight to the Swift response sink.
    pub struct TcpFlow {
        #[pin]
        inner: FfiBridgeStream,
        extensions: Extensions,
        executor: Option<Executor>,
    }
}

impl TcpFlow {
    #[must_use]
    pub(crate) fn new(inner: FfiBridgeStream, executor: Option<Executor>) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
            executor,
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
