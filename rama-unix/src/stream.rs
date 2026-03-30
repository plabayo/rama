use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use tokio::net::UnixStream as TokioUnixStream;

pin_project! {
    #[derive(Debug)]
    /// A stream which can be either a secure or a plain stream.
    pub struct UnixStream {
        #[pin]
        pub stream: TokioUnixStream,
        pub extensions: Extensions
    }
}

impl UnixStream {
    pub fn new(stream: TokioUnixStream) -> Self {
        Self {
            stream,
            extensions: Extensions::new(),
        }
    }
}

impl From<TokioUnixStream> for UnixStream {
    fn from(value: TokioUnixStream) -> Self {
        Self::new(value)
    }
}

impl From<UnixStream> for TokioUnixStream {
    fn from(value: UnixStream) -> Self {
        value.stream
    }
}

impl ExtensionsRef for UnixStream {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for UnixStream {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncWrite for UnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}
