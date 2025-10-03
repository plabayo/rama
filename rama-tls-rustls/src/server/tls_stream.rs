use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub use crate::dep::tokio_rustls::server::TlsStream as RustlsTlsStream;
use pin_project_lite::pin_project;
use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    #[derive(Debug)]
    pub struct TlsStream<IO> {
        #[pin]
        pub(super) stream: RustlsTlsStream<IO>,
    }
}

impl<IO: ExtensionsMut> TlsStream<IO> {
    pub fn new(stream: RustlsTlsStream<IO>) -> Self {
        Self { stream }
    }
}

impl<IO: ExtensionsMut> From<RustlsTlsStream<IO>> for TlsStream<IO> {
    fn from(value: RustlsTlsStream<IO>) -> Self {
        Self::new(value)
    }
}

impl<IO> From<TlsStream<IO>> for RustlsTlsStream<IO> {
    fn from(value: TlsStream<IO>) -> Self {
        value.stream
    }
}

impl<IO: ExtensionsRef> ExtensionsRef for TlsStream<IO> {
    fn extensions(&self) -> &Extensions {
        self.stream.get_ref().0.extensions()
    }
}

impl<IO: ExtensionsMut> ExtensionsMut for TlsStream<IO> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.stream.get_mut().0.extensions_mut()
    }
}

#[warn(clippy::missing_trait_methods)]
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
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
