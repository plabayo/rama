use bytes::Bytes;
use pin_project_lite::pin_project;
use std::{
    fmt,
    io::Cursor,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

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
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(data),
        }
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

impl AsyncRead for HeapReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
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
    pub fn new(first: T, second: U) -> Self {
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
            .field("t", &self.first)
            .field("u", &self.second)
            .finish()
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
