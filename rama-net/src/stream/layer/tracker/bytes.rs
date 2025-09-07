//! Provides [`BytesRWTracker`] which wraps a [`AsyncRead`] and/or [`AsyncWrite`]
//! in order to track the number of bytes read and/or written.
//!
//! Use [`BytesRWTracker::handle`] to get a [`BytesRWTrackerHandle`], a requirement
//! to get the number of bytes read and/or written even though the [`BytesRWTracker`]
//! is consumed by a protocol consumer, which is for example the case when you wish
//! to track the bytes read and/or written for a Tcp stream that is owned by a Tls stream.
//!
//! [`AsyncRead`]: crate::stream::AsyncRead
//! [`AsyncWrite`]: crate::stream::AsyncWrite

use pin_project_lite::pin_project;
use rama_core::telemetry::tracing;
use std::{
    fmt, io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// A wrapper around a [`AsyncRead`] and/or [`AsyncWrite`] that tracks the number
    /// of bytes read and/or written.
    ///
    /// Use [`BytesRWTracker::handle`] to get a [`BytesRWTrackerHandle`] in order
    /// to get the number of bytes read and/or written even though the [`BytesRWTracker`]
    /// is consumed by a protocol consumer.
    ///
    /// [`AsyncRead`]: crate::stream::AsyncRead
    /// [`AsyncWrite`]: crate::stream::AsyncWrite
    pub struct BytesRWTracker<S> {
        read: Arc<AtomicUsize>,
        written: Arc<AtomicUsize>,
        #[pin]
        stream: S,
    }
}

impl<S: fmt::Debug> fmt::Debug for BytesRWTracker<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BytesRWTracker")
            .field("read", &self.read)
            .field("written", &self.written)
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S> BytesRWTracker<S> {
    /// Create a new [`BytesRWTracker`] that wraps the
    /// given [`AsyncRead`] and/or [`AsyncWrite`].
    ///
    /// [`AsyncRead`]: crate::stream::AsyncRead
    /// [`AsyncWrite`]: crate::stream::AsyncWrite
    pub fn new(stream: S) -> Self {
        Self {
            read: Arc::new(AtomicUsize::new(0)),
            written: Arc::new(AtomicUsize::new(0)),
            stream,
        }
    }

    /// Get the number of bytes read (so far).
    pub fn read(&self) -> usize {
        self.read.load(Ordering::Acquire)
    }

    /// Get the number of bytes written (so far).
    pub fn written(&self) -> usize {
        self.written.load(Ordering::Acquire)
    }

    /// Get a [`BytesRWTrackerHandle`] that can be used to get the number of bytes
    /// read and/or written even though the tracker is consumed by a protocol
    /// consumer in a later stage.
    pub fn handle(&self) -> BytesRWTrackerHandle {
        BytesRWTrackerHandle {
            read: self.read.clone(),
            written: self.written.clone(),
        }
    }

    /// Get the inner [`AsyncRead`] and/or [`AsyncWrite`] stream.
    /// Dropping the tracking info and capabilities for this stream.
    ///
    /// Any previously obtained [`BytesRWTrackerHandle`] will no longer
    /// be updated but will still report the number of bytes read and/or
    /// written up to the point where this method was called.
    ///
    /// [`AsyncRead`]: crate::stream::AsyncRead
    /// [`AsyncWrite`]: crate::stream::AsyncWrite
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for BytesRWTracker<S>
where
    S: AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().project();
        let size = buf.filled().len();
        let res: Poll<Result<(), io::Error>> = this.stream.poll_read(cx, buf);
        if let Poll::Ready(Ok(_)) = res {
            let new_size = buf.filled().len();
            match new_size.cmp(&size) {
                std::cmp::Ordering::Greater => {
                    let bytes_read = new_size - size;
                    this.read.fetch_add(bytes_read, Ordering::AcqRel);
                }
                std::cmp::Ordering::Less => {
                    tracing::error!(
                        "BytesRWTracker: poll_read returned Ok(()) with filled buffer smaller then before"
                    );
                }
                std::cmp::Ordering::Equal => {
                    tracing::trace!("BytesRWTracker: poll_read returned Ok(()) with nothing read");
                }
            }
        }
        res
    }
}

impl<S> AsyncWrite for BytesRWTracker<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.as_mut().project();
        let res: Poll<Result<usize, io::Error>> = this.stream.poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes_written)) = res {
            this.written.fetch_add(bytes_written, Ordering::AcqRel);
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.as_mut().project();
        let res: Poll<Result<usize, io::Error>> = this.stream.poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(bytes_written)) = res {
            this.written.fetch_add(bytes_written, Ordering::AcqRel);
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// A handle to a tracker that can be used to get the number of bytes
/// read and/or written even though the tracker is consumed by a protocol
/// consumer.
#[derive(Debug, Clone)]
pub struct BytesRWTrackerHandle {
    read: Arc<AtomicUsize>,
    written: Arc<AtomicUsize>,
}

impl BytesRWTrackerHandle {
    /// Get the number of bytes read (so far).
    #[must_use]
    pub fn read(&self) -> usize {
        self.read.load(Ordering::Acquire)
    }

    /// Get the number of bytes written (so far).
    #[must_use]
    pub fn written(&self) -> usize {
        self.written.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_read_tracker() {
        let stream = Builder::new()
            .read(b"foo")
            .read(b"bar")
            .read(b"baz")
            .build();

        let mut tracker = BytesRWTracker::new(stream);
        let mut buf = [0u8; 3];

        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 0);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 3);
        assert_eq!(tracker.written(), 0);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 6);
        assert_eq!(tracker.written(), 0);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 9);
        assert_eq!(tracker.written(), 0);
    }

    #[tokio::test]
    async fn test_written_tracker() {
        let stream = Builder::new()
            .write(b"foo")
            .write(b"bar")
            .write(b"baz")
            .build();

        let mut tracker = BytesRWTracker::new(stream);

        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 0);
        tracker.write_all(b"foo").await.unwrap();
        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 3);
        tracker.write_all(b"bar").await.unwrap();
        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 6);
        tracker.write_all(b"baz").await.unwrap();
        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 9);
    }

    #[tokio::test]
    async fn test_rw_tracker() {
        let stream = Builder::new()
            .read(b"foo")
            .write(b"foo")
            .read(b"bar")
            .write(b"bar")
            .read(b"baz")
            .write(b"baz")
            .build();

        let mut tracker = BytesRWTracker::new(stream);
        let mut buf = [0u8; 3];

        assert_eq!(tracker.read(), 0);
        assert_eq!(tracker.written(), 0);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 3);
        assert_eq!(tracker.written(), 0);
        tracker.write_all(b"foo").await.unwrap();
        assert_eq!(tracker.read(), 3);
        assert_eq!(tracker.written(), 3);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 6);
        assert_eq!(tracker.written(), 3);
        tracker.write_all(b"bar").await.unwrap();
        assert_eq!(tracker.read(), 6);
        assert_eq!(tracker.written(), 6);
        tracker.read_exact(&mut buf).await.unwrap();
        assert_eq!(tracker.read(), 9);
        assert_eq!(tracker.written(), 6);
        tracker.write_all(b"baz").await.unwrap();
        assert_eq!(tracker.read(), 9);
        assert_eq!(tracker.written(), 9);
    }

    #[tokio::test]
    async fn test_rw_handle_tracker() {
        let stream = Builder::new()
            .read(b"foo")
            .write(b"foo")
            .read(b"bar")
            .write(b"bar")
            .read(b"baz")
            .write(b"baz")
            .build();

        let tracker = BytesRWTracker::new(stream);
        let handle = tracker.handle();

        assert_eq!(handle.read(), 0);
        assert_eq!(handle.written(), 0);

        let (action_tx, mut action_rx) = tokio::sync::mpsc::channel(1);
        let (check_tx, mut check_rx) = tokio::sync::broadcast::channel(1);
        let check_rx_2 = check_tx.subscribe();

        let task_1 = tokio::spawn(async move {
            let mut tracker = tracker;
            let mut buf = [0u8; 3];

            action_rx.recv().await;
            tracker.read_exact(&mut buf).await.unwrap();
            check_tx.send(()).unwrap();

            action_rx.recv().await;
            tracker.write_all(b"foo").await.unwrap();
            check_tx.send(()).unwrap();

            action_rx.recv().await;
            tracker.read_exact(&mut buf).await.unwrap();
            check_tx.send(()).unwrap();

            action_rx.recv().await;
            tracker.write_all(b"bar").await.unwrap();
            check_tx.send(()).unwrap();

            action_rx.recv().await;
            tracker.read_exact(&mut buf).await.unwrap();
            check_tx.send(()).unwrap();

            action_rx.recv().await;
            tracker.write_all(b"baz").await.unwrap();
            check_tx.send(()).unwrap();
        });

        let task_2 = {
            let handle = handle.clone();
            let mut check_rx = check_rx_2;
            tokio::spawn(async move {
                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 3);
                assert_eq!(handle.written(), 0);

                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 3);
                assert_eq!(handle.written(), 3);

                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 6);
                assert_eq!(handle.written(), 3);

                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 6);
                assert_eq!(handle.written(), 6);

                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 9);
                assert_eq!(handle.written(), 6);

                check_rx.recv().await.unwrap();

                assert_eq!(handle.read(), 9);
                assert_eq!(handle.written(), 9)
            })
        };

        assert_eq!(handle.read(), 0);
        assert_eq!(handle.written(), 0);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 3);
        assert_eq!(handle.written(), 0);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 3);
        assert_eq!(handle.written(), 3);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 6);
        assert_eq!(handle.written(), 3);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 6);
        assert_eq!(handle.written(), 6);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 9);
        assert_eq!(handle.written(), 6);

        action_tx.send(()).await.unwrap();
        check_rx.recv().await.unwrap();

        assert_eq!(handle.read(), 9);
        assert_eq!(handle.written(), 9);

        let (t1, t2) = rama_core::futures::zip(task_1, task_2).await;
        t1.unwrap();
        t2.unwrap();
    }
}
