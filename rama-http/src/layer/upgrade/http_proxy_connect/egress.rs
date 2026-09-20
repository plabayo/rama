//! Preserve CONNECT transport failure semantics while reusing ordinary I/O relays.

use crate::io::upgrade::{OnUpstreamError, Upgraded};
use rama_core::extensions::{Extensions, ExtensionsRef};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Egress I/O used by the eager CONNECT service.
/// Reports upstream I/O failures before a relay can gracefully close the tunnel.
/// H3 then sends H3_CONNECT_ERROR; H1/H2 retain their existing behavior.
#[derive(Debug)]
pub struct ConnectEgress<T> {
    inner: T,
    on_error: Option<OnUpstreamError>,
}
impl<T> ConnectEgress<T> {
    /// Wrap an upstream connection with the upgraded transport's failure hook.
    pub fn new(inner: T, upgraded: &Upgraded) -> Self {
        Self {
            inner,
            on_error: upgraded.extensions().get_ref::<OnUpstreamError>().cloned(),
        }
    }
    fn observed<R>(&self, result: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        if matches!(&result, Poll::Ready(Err(_)))
            && let Some(on_error) = &self.on_error
        {
            on_error.call();
        }
        result
    }
}
impl<T: ExtensionsRef> ExtensionsRef for ConnectEgress<T> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for ConnectEgress<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.observed(result)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ConnectEgress<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.observed(result)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.observed(result)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.observed(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.observed(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn upstream_failures_notify_before_returning_to_the_relay() {
        for reading in [false, true] {
            let notified = Arc::new(AtomicUsize::new(0));
            let mut mock = tokio_test::io::Builder::new();
            if reading {
                mock.read_error(io::Error::from(io::ErrorKind::ConnectionReset));
            } else {
                mock.write(b"ok")
                    .write_error(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let inner = mock.build();
            drop(mock);
            let mut upstream = ConnectEgress {
                inner,
                on_error: Some(OnUpstreamError::new({
                    let notified = notified.clone();
                    move || {
                        notified.fetch_add(1, Ordering::SeqCst);
                    }
                })),
            };
            if reading {
                assert_eq!(
                    upstream.read(&mut [0; 8]).await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
            } else {
                upstream.write_all(b"ok").await.unwrap();
                assert_eq!(notified.load(Ordering::SeqCst), 0);
                assert_eq!(
                    upstream.write_all(b"failed").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
            }
            assert_eq!(notified.load(Ordering::SeqCst), 1);
        }
    }
}
