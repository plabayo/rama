use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extensions, ExtensionsRef};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

pin_project! {
    /// Egress TCP stream backed by a pre-established `NWConnection`.
    ///
    /// Unlike [`crate::TcpFlow`], this type carries no intercepted-flow metadata.
    /// It wraps the Rust side of a `tokio::io::duplex` pair whose other half is
    /// bridged to a Swift-managed `NWConnection`.
    pub struct NwTcpStream {
        #[pin]
        inner: DuplexStream,
        extensions: Extensions,
    }
}

impl NwTcpStream {
    #[must_use]
    pub(crate) fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
        }
    }
}

impl ExtensionsRef for NwTcpStream {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for NwTcpStream {
    #[inline(always)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for NwTcpStream {
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
