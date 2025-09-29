use std::fmt;

use pin_project_lite::pin_project;
use rama_boring::ssl::SslRef;
use rama_boring_tokio::SslStream;
use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
    stream::Stream,
};
use tokio::io::{AsyncRead, AsyncWrite};

pin_project! {
    pub struct TlsStream<S> {
        #[pin]
        pub inner: SslStream<S>,
    }
}

impl<S: ExtensionsMut> TlsStream<S> {
    #[must_use]
    pub fn new(inner: SslStream<S>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn ssl_ref(&self) -> &SslRef {
        self.inner.ssl()
    }
}

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: ExtensionsRef> ExtensionsRef for TlsStream<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.get_ref().extensions()
    }
}

impl<S: ExtensionsMut> ExtensionsMut for TlsStream<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.inner.get_mut().extensions_mut()
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
