use std::{
    fmt,
    io::{IoSlice, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// a stream which has peeked some data of the inner stream,
    /// to be read first prior to any other reading
    ///
    /// It's similar to `ChainReader`, except that writing is also
    /// supported and happening directly in function of the inner stream.
    pub struct PeekStream<P, S> {
        done_peek: bool,
        #[pin]
        peek: P,
        #[pin]
        inner: S,
    }
}

impl<P, S> PeekStream<P, S> {
    /// Create a new [`PeekStream`] for the given
    /// peek [`AsyncRead`] and inner [`Stream`].
    ///
    /// [`Stream`]: super::Stream
    pub fn new(peek: P, inner: S) -> Self {
        Self {
            done_peek: false,
            peek,
            inner,
        }
    }
}

impl<P, S> fmt::Debug for PeekStream<P, S>
where
    P: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeekStream")
            .field("done_peek", &self.done_peek)
            .field("peek", &self.peek)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<P, S> Clone for PeekStream<P, S>
where
    P: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            done_peek: self.done_peek,
            peek: self.peek.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<P, S> AsyncRead for PeekStream<P, S>
where
    P: AsyncRead,
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();

        if !*me.done_peek {
            let rem = buf.remaining();
            ready!(me.peek.poll_read(cx, buf))?;
            if buf.remaining() == rem {
                *me.done_peek = true;
            } else {
                return Poll::Ready(Ok(()));
            }
        }
        me.inner.poll_read(cx, buf)
    }
}

impl<P, S> AsyncBufRead for PeekStream<P, S>
where
    P: AsyncBufRead,
    S: AsyncBufRead,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let me = self.project();

        if !*me.done_peek {
            match ready!(me.peek.poll_fill_buf(cx)?) {
                [] => {
                    *me.done_peek = true;
                }
                buf => return Poll::Ready(Ok(buf)),
            }
        }
        me.inner.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        if !*me.done_peek {
            me.peek.consume(amt)
        } else {
            me.inner.consume(amt)
        }
    }
}

impl<P, S> Read for PeekStream<P, S>
where
    P: Read,
    S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.done_peek {
            let n = self.peek.read(buf)?;
            if n == 0 {
                self.done_peek = true;
            } else {
                return Ok(n);
            }
        }
        self.inner.read(buf)
    }
}

impl<P, S> AsyncWrite for PeekStream<P, S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        me.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let me = self.project();
        me.inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<P, S> Write for PeekStream<P, S>
where
    S: Write,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_multi_read_async<const N: usize>(
        mut stream: impl AsyncRead + Unpin,
        cases: &[&str],
    ) {
        let mut buf = [0u8; N];

        for (i, case) in cases.iter().enumerate() {
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(
                n,
                case.len(),
                "[{N}][async] step #{} for cases: {:?}",
                i + 1,
                cases
            );
            assert_eq!(
                &buf[..n],
                case.as_bytes(),
                "[{N}][async] step #{} for cases: {:?}",
                i + 1,
                cases
            );
        }
    }

    fn test_multi_read_sync<const N: usize>(mut stream: impl Read, cases: &[&str]) {
        let mut buf = [0u8; N];

        for (i, case) in cases.iter().enumerate() {
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(
                n,
                case.len(),
                "[{N}][sync] step #{} for cases: {:?}",
                i + 1,
                cases
            );
            assert_eq!(
                &buf[..n],
                case.as_bytes(),
                "[{N}][sync] step #{} for cases: {:?}",
                i + 1,
                cases
            );
        }
    }

    #[tokio::test]
    async fn test_peek_stream_read() {
        #[derive(Debug)]
        struct TestCase<const N: usize> {
            peek_data: &'static str,
            inner_data: &'static str,
            expected_reads: &'static [&'static str],
        }

        impl<const N: usize> TestCase<N> {
            async fn test_sync_and_async(&self) {
                let new_stream = || {
                    let peek_data = Cursor::new(self.peek_data);
                    let inner_data = Cursor::new(self.inner_data);
                    PeekStream::new(peek_data, inner_data)
                };

                test_multi_read_async::<N>(&mut new_stream(), self.expected_reads).await;
                test_multi_read_sync::<N>(&mut new_stream(), self.expected_reads);
            }
        }

        TestCase::<10> {
            peek_data: "hello",
            inner_data: " world",
            expected_reads: &["hello", " world", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5> {
            peek_data: "hello world",
            inner_data: "next data",
            expected_reads: &["hello", " worl", "d", "next ", "data", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<2> {
            peek_data: "peek",
            inner_data: "inner",
            expected_reads: &["pe", "ek", "in", "ne", "r", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<8> {
            peek_data: "",
            inner_data: "inner data",
            expected_reads: &["inner da", "ta", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<10> {
            peek_data: "",
            inner_data: "inner data",
            expected_reads: &["inner data", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<12> {
            peek_data: "",
            inner_data: "inner data",
            expected_reads: &["inner data", ""],
        }
        .test_sync_and_async()
        .await;
    }

    fn new_peek_write_stream() -> PeekStream<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
        let peek_data = Cursor::new(Vec::new());
        let inner_data = Cursor::new(Vec::new());
        PeekStream::new(peek_data, inner_data)
    }

    async fn test_multi_write_async(mut stream: impl AsyncWrite + Unpin, cases: &[&str]) {
        for case in cases {
            stream.write_all(case.as_bytes()).await.unwrap();
        }
    }

    fn test_multi_write_sync(mut stream: impl Write, cases: &[&str]) {
        for case in cases {
            stream.write_all(case.as_bytes()).unwrap();
        }
    }

    #[tokio::test]
    async fn test_peek_stream_write() {
        #[derive(Debug)]
        struct TestCase<'a> {
            writes: &'a [&'static str],
        }

        impl TestCase<'_> {
            async fn test_sync_and_async(&self) {
                let mut stream = new_peek_write_stream();
                test_multi_write_async(&mut stream, self.writes).await;

                assert!(!stream.done_peek, "[async] writes: {:?}", self.writes);
                assert_eq!(
                    stream.peek.position(),
                    0,
                    "[async] writes: {:?}",
                    self.writes
                );
                assert!(
                    stream.peek.into_inner().is_empty(),
                    "[async] writes: {:?}",
                    self.writes
                );

                assert_eq!(
                    self.writes.join(""),
                    String::from_utf8(stream.inner.into_inner()).unwrap(),
                    "[async] writes: {:?}",
                    self.writes,
                );

                let mut stream = new_peek_write_stream();
                test_multi_write_sync(&mut stream, self.writes);

                assert!(!stream.done_peek, "[sync] writes: {:?}", self.writes);
                assert_eq!(
                    stream.peek.position(),
                    0,
                    "[sync] writes: {:?}",
                    self.writes
                );
                assert!(
                    stream.peek.into_inner().is_empty(),
                    "[sync] writes: {:?}",
                    self.writes,
                );

                assert_eq!(
                    self.writes.join(""),
                    String::from_utf8(stream.inner.into_inner()).unwrap(),
                    "[sync] writes: {:?}",
                    self.writes
                );
            }
        }

        for writes in [
            vec![],
            vec![""],
            vec!["test", " ", "data"],
            vec!["test data"],
        ] {
            TestCase {
                writes: writes.as_slice(),
            }
            .test_sync_and_async()
            .await;
        }
    }
}
