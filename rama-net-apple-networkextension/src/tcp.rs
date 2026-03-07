use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extensions, ExtensionsMut, ExtensionsRef};
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
    }
}

impl TcpFlow {
    #[must_use]
    /// Create a new [`TcpFlow`].
    pub(crate) fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
        }
    }
}

impl ExtensionsRef for TcpFlow {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for TcpFlow {
    #[inline(always)]
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
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
