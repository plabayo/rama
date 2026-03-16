use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::extensions::{Extensions, ExtensionsMut, ExtensionsRef};

pin_project! {
    /// An I/O wrapper that stops reading and writing once the cancel future resolves.
    ///
    /// Reads complete as EOF after cancellation. Writes fail with `BrokenPipe`.
    #[derive(Debug)]
    #[must_use = "I/O wrappers do nothing unless polled"]
    pub struct GracefulIo<F, S> {
        #[pin]
        cancel: F,

        #[pin]
        inner: S,

        done: bool,
    }
}

impl<F, S> GracefulIo<F, S> {
    pub fn new(cancel: F, inner: S) -> Self {
        Self {
            cancel,
            inner,
            done: false,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<F, S: ExtensionsRef> ExtensionsRef for GracefulIo<F, S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<F, S: ExtensionsMut> ExtensionsMut for GracefulIo<F, S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.inner.extensions_mut()
    }
}

impl<F, S> GracefulIo<F, S>
where
    F: Future,
{
    fn poll_cancel(self: Pin<&mut Self>, cx: &mut Context<'_>) -> bool {
        let mut this = self.project();

        if *this.done {
            return true;
        }

        if this.cancel.as_mut().poll(cx).is_ready() {
            *this.done = true;
            return true;
        }

        false
    }
}

#[warn(clippy::missing_trait_methods)]
impl<F, S> AsyncRead for GracefulIo<F, S>
where
    F: Future,
    S: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.as_mut().poll_cancel(cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<F, S> AsyncWrite for GracefulIo<F, S>
where
    F: Future,
    S: AsyncWrite,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.as_mut().poll_cancel(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }

        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.as_mut().poll_cancel(cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.as_mut().poll_cancel(cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.as_mut().poll_cancel(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }

        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::GracefulIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn graceful_io_returns_eof_after_cancel() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let cancel = async move {
            let _ = cancel_rx.await;
        };

        let mut io = std::pin::pin!(GracefulIo::new(cancel, rx));
        tx.write_all(b"abc").await.unwrap();

        let mut buf = [0_u8; 3];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");

        let _ = cancel_tx.send(());

        let mut eof_buf = [0_u8; 1];
        let n = io.read(&mut eof_buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn graceful_io_fails_writes_after_cancel() {
        let (tx, _rx) = tokio::io::duplex(64);
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let cancel = async move {
            let _ = cancel_rx.await;
        };

        let mut io = std::pin::pin!(GracefulIo::new(cancel, tx));
        let _ = cancel_tx.send(());

        let err = io.write_all(b"abc").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
