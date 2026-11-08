use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    extensions::ExtensionsRef,
    graceful::{Aborted, Scope},
};

pin_project! {
    /// An I/O wrapper that stops reading and writing once its [`Scope`] is aborted, and holds
    /// that scope for as long as it exists.
    ///
    /// Reads complete as EOF after the abort. Writes fail with `BrokenPipe`.
    ///
    /// Reading and writing each observe the abort on their own, so the halves of a split
    /// wrapper, polled by different tasks, are both woken.
    #[derive(Debug, ExtensionsRef)]
    #[must_use = "I/O wrappers do nothing unless polled"]
    pub struct AbortableIo<S> {
        scope: Scope,
        read_abort: Aborted,
        write_abort: Aborted,

        #[pin]
        inner: S,

        done: bool,
    }
}

impl<S> AbortableIo<S> {
    pub fn new(scope: &Scope, inner: S) -> Self {
        Self {
            scope: scope.clone(),
            read_abort: scope.aborted(),
            write_abort: scope.aborted(),
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

    fn poll_aborted(self: Pin<&mut Self>, write: bool, cx: &mut Context<'_>) -> bool {
        let this = self.project();
        if *this.done {
            return true;
        }
        let abort = if write {
            this.write_abort
        } else {
            this.read_abort
        };
        if Pin::new(abort).poll(cx).is_ready() {
            *this.done = true;
            return true;
        }
        false
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncRead for AbortableIo<S>
where
    S: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.as_mut().poll_aborted(false, cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncWrite for AbortableIo<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.as_mut().poll_aborted(true, cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }

        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.as_mut().poll_aborted(true, cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.as_mut().poll_aborted(true, cx) {
            return Poll::Ready(Ok(()));
        }

        self.project().inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.as_mut().poll_aborted(true, cx) {
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
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::AbortableIo;
    use crate::graceful::{Cause, Scope};

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        (count.clone(), Waker::from(count))
    }

    #[tokio::test]
    async fn abortable_io_returns_eof_after_abort() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let scope = Scope::new();

        let mut io = core::pin::pin!(AbortableIo::new(&scope, rx));
        tx.write_all(b"abc").await.unwrap();

        let mut buf = [0_u8; 3];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");

        scope.abort(Cause::Owner);

        let mut eof_buf = [0_u8; 1];
        let n = io.read(&mut eof_buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn abortable_io_fails_writes_after_abort() {
        let (tx, _rx) = tokio::io::duplex(64);
        let scope = Scope::new();

        let mut io = core::pin::pin!(AbortableIo::new(&scope, tx));
        scope.abort(Cause::Owner);

        let err = io.write_all(b"abc").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// A pending read and a pending write, polled with different wakers in either order,
    /// are both woken by the abort.
    #[test]
    fn abort_wakes_a_pending_read_and_a_pending_write() {
        for read_first in [true, false] {
            // One byte of room, filled: writing is pending, and nothing comes in to read.
            let (_peer, local) = tokio::io::duplex(1);
            let scope = Scope::new();
            let mut io = Box::pin(AbortableIo::new(&scope, local));
            let mut full = Context::from_waker(Waker::noop());
            assert!(matches!(
                io.as_mut().poll_write(&mut full, b"x"),
                Poll::Ready(Ok(1))
            ));

            let (reads, read_waker) = counting_waker();
            let (writes, write_waker) = counting_waker();
            let poll_read = |io: &mut Pin<Box<AbortableIo<tokio::io::DuplexStream>>>| {
                let mut buf = [0_u8; 1];
                let mut buf = ReadBuf::new(&mut buf);
                io.as_mut()
                    .poll_read(&mut Context::from_waker(&read_waker), &mut buf)
                    .is_pending()
            };
            let poll_write = |io: &mut Pin<Box<AbortableIo<tokio::io::DuplexStream>>>| {
                io.as_mut()
                    .poll_write(&mut Context::from_waker(&write_waker), b"y")
                    .is_pending()
            };
            if read_first {
                assert!(poll_read(&mut io));
                assert!(poll_write(&mut io));
            } else {
                assert!(poll_write(&mut io));
                assert!(poll_read(&mut io));
            }

            scope.abort(Cause::Owner);
            assert!(reads.0.load(Ordering::SeqCst) > 0, "read woken");
            assert!(writes.0.load(Ordering::SeqCst) > 0, "write woken");
            assert!(!poll_read(&mut io));
            assert!(!poll_write(&mut io));
        }
    }

    #[tokio::test]
    async fn split_halves_in_different_tasks_both_end_at_the_abort() {
        let (_peer, local) = tokio::io::duplex(1);
        let scope = Scope::new();
        let (mut read_half, mut write_half) = tokio::io::split(AbortableIo::new(&scope, local));
        let reader = tokio::spawn(async move {
            let mut buf = [0_u8; 1];
            read_half.read(&mut buf).await.unwrap()
        });
        let writer = tokio::spawn(async move { write_half.write_all(b"xy").await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        scope.abort(Cause::Owner);
        let limit = std::time::Duration::from_secs(5);
        assert_eq!(
            tokio::time::timeout(limit, reader).await.unwrap().unwrap(),
            0
        );
        let err = tokio::time::timeout(limit, writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
