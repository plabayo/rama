use pin_project_lite::pin_project;
use std::{
    fmt,
    io::{Cursor, Read},
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

use crate::bytes::{Buf, Bytes};

pin_project! {
    /// Reader for reading from a heap-allocated bytes buffer.
    #[derive(Debug, Clone)]
    pub struct HeapReader {
        #[pin]
        inner: Cursor<Vec<u8>>,
    }
}

impl HeapReader {
    /// Creates a new `HeapReader` with the specified bytes data.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(data),
        }
    }

    /// How many bytes are there remaining
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Returns true if there are any more bytes to consume
    #[must_use]
    pub fn has_remaining(&self) -> bool {
        self.inner.has_remaining()
    }
}

impl From<Vec<u8>> for HeapReader {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for HeapReader {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl From<&str> for HeapReader {
    fn from(data: &str) -> Self {
        Self::new(data.as_bytes().to_vec())
    }
}

impl Default for HeapReader {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl From<Bytes> for HeapReader {
    fn from(data: Bytes) -> Self {
        Self::new(data.to_vec())
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncRead for HeapReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncBufRead for HeapReader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.project().inner.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().inner.consume(amt);
    }
}

impl Read for HeapReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact(buf)
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.inner.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.inner.read_to_string(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.inner.read_vectored(bufs)
    }
}

/// Reader for reading from a stack buffer
#[derive(Debug, Clone)]
pub struct StackReader<const N: usize> {
    data: [u8; N],
    offset: usize,
}

impl<const N: usize> StackReader<N> {
    /// Creates a new `StackReader` with the specified bytes data.
    #[must_use]
    pub const fn new(data: [u8; N]) -> Self {
        Self { data, offset: 0 }
    }

    /// Skip up to n bytes, less if n < m
    pub fn skip(&mut self, n: usize) {
        self.offset = (self.offset + n).min(N);
    }

    /// How many bytes are there remaining
    #[must_use]
    pub fn remaining(&self) -> usize {
        N - self.offset
    }

    /// Returns true if there are any more bytes to consume
    #[must_use]
    pub fn has_remaining(&self) -> bool {
        self.remaining() == 0
    }
}

impl<const N: usize> From<[u8; N]> for StackReader<N> {
    #[inline]
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

impl<const N: usize> AsyncRead for StackReader<N> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < N {
            let remaining = &self.data[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());

            if to_copy > 0 {
                buf.put_slice(&remaining[..to_copy]);
                self.offset += to_copy;
            }
        }

        // done
        Poll::Ready(Ok(()))
    }
}

impl<const N: usize> AsyncBufRead for StackReader<N> {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.get_mut();
        Poll::Ready(Ok(if me.offset < N {
            &me.data[me.offset..]
        } else {
            &[]
        }))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().skip(amt)
    }
}

impl<const N: usize> Read for StackReader<N> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.offset < N {
            let remaining = &self.data[self.offset..];
            let to_copy = remaining.len().min(buf.len());

            if to_copy > 0 {
                buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
                self.offset += to_copy;
                return Ok(to_copy);
            }
        }

        // done
        Ok(0)
    }
}

pin_project! {
    /// Reader that can be used to chain two readers together.
    #[must_use = "streams do nothing unless polled"]
    #[cfg_attr(docsrs, doc(cfg(feature = "io-util")))]
    pub struct ChainReader<T, U> {
        #[pin]
        first: T,
        #[pin]
        second: U,
        done_first: bool,
    }
}

impl<T, U> ChainReader<T, U>
where
    T: AsyncRead,
    U: AsyncRead,
{
    /// Creates a new `ChainReader` with the specified readers.
    pub const fn new(first: T, second: U) -> Self {
        Self {
            first,
            second,
            done_first: false,
        }
    }

    /// Gets references to the underlying readers in this `ChainReader`.
    pub fn get_ref(&self) -> (&T, &U) {
        (&self.first, &self.second)
    }

    /// Gets mutable references to the underlying readers in this `ChainReader`.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying readers as doing so may corrupt the internal state of this
    /// `ChainReader`.
    pub fn get_mut(&mut self) -> (&mut T, &mut U) {
        (&mut self.first, &mut self.second)
    }

    /// Gets pinned mutable references to the underlying readers in this `ChainReader`.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying readers as doing so may corrupt the internal state of this
    /// `ChainReader`.
    #[must_use]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> (Pin<&mut T>, Pin<&mut U>) {
        let me = self.project();
        (me.first, me.second)
    }

    /// Consumes the `ChainReader`, returning the wrapped readers.
    pub fn into_inner(self) -> (T, U) {
        (self.first, self.second)
    }
}

impl<T, U> fmt::Debug for ChainReader<T, U>
where
    T: fmt::Debug,
    U: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainReader")
            .field("done_first", &self.done_first)
            .field("first", &self.first)
            .field("second", &self.second)
            .finish()
    }
}

impl<T, U> Clone for ChainReader<T, U>
where
    T: Clone,
    U: Clone,
{
    fn clone(&self) -> Self {
        Self {
            done_first: self.done_first,
            first: self.first.clone(),
            second: self.second.clone(),
        }
    }
}

impl<T, U> AsyncRead for ChainReader<T, U>
where
    T: AsyncRead,
    U: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();

        if !*me.done_first {
            let rem = buf.remaining();
            ready!(me.first.poll_read(cx, buf))?;
            if buf.remaining() == rem {
                *me.done_first = true;
            } else {
                return Poll::Ready(Ok(()));
            }
        }
        me.second.poll_read(cx, buf)
    }
}

impl<T, U> Read for ChainReader<T, U>
where
    T: Read,
    U: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.done_first {
            let n = self.first.read(buf)?;
            if n == 0 {
                self.done_first = true;
            } else {
                return Ok(n);
            }
        }
        self.second.read(buf)
    }
}

impl<T, U> AsyncBufRead for ChainReader<T, U>
where
    T: AsyncBufRead,
    U: AsyncBufRead,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.project();

        if !*me.done_first {
            match ready!(me.first.poll_fill_buf(cx)?) {
                [] => {
                    *me.done_first = true;
                }
                buf => return Poll::Ready(Ok(buf)),
            }
        }
        me.second.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        if !*me.done_first {
            me.first.consume(amt)
        } else {
            me.second.consume(amt)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use tokio::io::AsyncReadExt;

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

    #[derive(Debug)]
    struct TestCase<const N: usize, R> {
        reader: R,
        expected_reads: &'static [&'static str],
    }

    impl<const N: usize, R: AsyncRead + Clone + Unpin + Read> TestCase<N, R> {
        async fn test_sync_and_async(&self) {
            let new_stream = || self.reader.clone();

            test_multi_read_async::<N>(&mut new_stream(), self.expected_reads).await;
            test_multi_read_sync::<N>(&mut new_stream(), self.expected_reads);
        }
    }

    #[tokio::test]
    async fn test_heap_reader() {
        TestCase::<5, _> {
            reader: HeapReader::from(""),
            expected_reads: &[""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5, _> {
            reader: HeapReader::from("hello world"),
            expected_reads: &["hello", " worl", "d", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<10, _> {
            reader: HeapReader::from("hello world"),
            expected_reads: &["hello worl", "d", ""],
        }
        .test_sync_and_async()
        .await;
    }

    #[tokio::test]
    async fn test_stack_reader() {
        TestCase::<5, _> {
            reader: StackReader::new(*b""),
            expected_reads: &[""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5, _> {
            reader: StackReader::new(*b"hello world"),
            expected_reads: &["hello", " worl", "d", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<10, _> {
            reader: StackReader::from(*b"hello world"),
            expected_reads: &["hello worl", "d", ""],
        }
        .test_sync_and_async()
        .await;
    }

    #[tokio::test]
    async fn test_chain_reader() {
        TestCase::<5, _> {
            reader: ChainReader::new(Cursor::new(""), Cursor::new("")),
            expected_reads: &[""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5, _> {
            reader: ChainReader::new(Cursor::new("hello world"), Cursor::new("")),
            expected_reads: &["hello", " worl", "d", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5, _> {
            reader: ChainReader::new(Cursor::new("hello "), Cursor::new("world")),
            expected_reads: &["hello", " ", "world", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5, _> {
            reader: ChainReader::new(Cursor::new(""), Cursor::new("hello world")),
            expected_reads: &["hello", " worl", "d", ""],
        }
        .test_sync_and_async()
        .await;
    }
}
