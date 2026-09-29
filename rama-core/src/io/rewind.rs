use crate::bytes::{Buf, Bytes};
use crate::extensions::{Extensions, ExtensionsRef};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::{cmp, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Combine a buffer with an IO, rewinding reads to use the buffer.
///
/// The read that drains the buffer also tries one inner read
/// when there is room left, so the buffer need not be a short
/// read of its own.
#[derive(Debug)]
pub struct Rewind<T> {
    pre: Option<Bytes>,
    // inner error hit after buffered bytes were read
    deferred_err: Option<io::Error>,
    inner: T,
}

impl<T> Rewind<T> {
    #[cfg(test)]
    pub fn new(io: T) -> Self {
        Self {
            pre: None,
            deferred_err: None,
            inner: io,
        }
    }

    pub fn new_buffered(io: T, buf: Bytes) -> Self {
        Self {
            pre: Some(buf),
            deferred_err: None,
            inner: io,
        }
    }

    #[cfg(test)]
    pub fn rewind(&mut self, bs: Bytes) {
        debug_assert!(self.pre.is_none());
        self.pre = Some(bs);
    }

    // drops a deferred read error, if any
    pub fn into_inner(self) -> (T, Bytes) {
        (self.inner, self.pre.unwrap_or_default())
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Clone> Clone for Rewind<T> {
    fn clone(&self) -> Self {
        Self {
            pre: self.pre.clone(),
            // io::Error is not Clone, keep the OS code if any
            deferred_err: self.deferred_err.as_ref().map(|err| {
                err.raw_os_error().map_or_else(
                    || io::Error::new(err.kind(), err.to_string()),
                    io::Error::from_raw_os_error,
                )
            }),
            inner: self.inner.clone(),
        }
    }
}

impl<T: ExtensionsRef> ExtensionsRef for Rewind<T> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T> AsyncRead for Rewind<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // an empty buf must not take a deferred error
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(err) = this.deferred_err.take() {
            return Poll::Ready(Err(err));
        }

        if let Some(mut prefix) = this.pre.take() {
            // If there are no remaining bytes, let the bytes get dropped.
            if !prefix.is_empty() {
                let copy_len = cmp::min(prefix.len(), buf.remaining());
                buf.put_slice(&prefix[..copy_len]);
                prefix.advance(copy_len);
                if !prefix.is_empty() {
                    // Put back what's left
                    this.pre = Some(prefix);
                } else if buf.remaining() > 0
                    && let Poll::Ready(Err(err)) = Pin::new(&mut this.inner).poll_read(cx, buf)
                {
                    // Returned next call: some sockets report a
                    // reset only once and read EOF after that.
                    this.deferred_err = Some(err);
                }

                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T> AsyncWrite for Rewind<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::test_util::{ScriptReader, Step, poll_read_once};

    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn partial_rewind() {
        let underlying = [104, 101, 108, 108, 111];

        let mock = tokio_test::io::Builder::new().read(&underlying).build();

        let mut stream = Rewind::new(mock);

        // Read off some bytes, ensure we filled o1
        let mut buf = [0; 2];
        stream.read_exact(&mut buf).await.expect("read1");

        // Rewind the stream so that it is as if we never read in the first place.
        stream.rewind(Bytes::copy_from_slice(&buf[..]));

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read1");

        // At this point we should have read everything that was in the MockStream
        assert_eq!(&buf, &underlying);
    }

    #[tokio::test]
    async fn full_rewind() {
        let underlying = [104, 101, 108, 108, 111];

        let mock = tokio_test::io::Builder::new().read(&underlying).build();

        let mut stream = Rewind::new(mock);

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read1");

        // Rewind the stream so that it is as if we never read in the first place.
        stream.rewind(Bytes::copy_from_slice(&buf[..]));

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read1");

        assert_eq!(&buf, &underlying);
    }

    fn buffered(pre: &'static [u8], steps: impl IntoIterator<Item = Step>) -> Rewind<ScriptReader> {
        Rewind::new_buffered(ScriptReader::new(steps), Bytes::from_static(pre))
    }

    #[tokio::test]
    async fn read_joins_buffer_with_ready_inner_data() {
        let mut stream = buffered(b"ab", [Step::Data(b"cd")]);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[test]
    fn read_does_not_wait_for_inner() {
        let mut stream = buffered(b"ab", [Step::Pending, Step::Data(b"cd")]);
        let mut buf = [0u8; 16];
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("buffered read must not wait on the inner stream");
        };
        assert_eq!(&buf[..n], b"ab");
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("expected inner data");
        };
        assert_eq!(&buf[..n], b"cd");
    }

    #[tokio::test]
    async fn read_defers_inner_error_once() {
        let mut stream = buffered(b"ab", [Step::Err(io::ErrorKind::ConnectionReset)]);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        // the script is done, so the inner stream now reads EOF
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn empty_read_keeps_deferred_error() {
        let mut stream = buffered(b"ab", [Step::Err(io::ErrorKind::ConnectionReset)]);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn empty_read_keeps_buffer() {
        let mut stream = buffered(b"ab", [Step::Data(b"cd")]);
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
    }

    #[tokio::test]
    async fn small_buf_keeps_order() {
        let mut stream = buffered(b"abcd", [Step::Data(b"ef")]);
        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abc");
        // buffer drained on this read, so it tops up
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"def");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn read_with_inner_eof() {
        let mut stream = buffered(b"ab", []);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn empty_buffer_reads_inner() {
        let mut stream = buffered(b"", [Step::Data(b"cd")]);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"cd");
    }

    #[test]
    fn read_appends_to_prefilled_buf() {
        let mut stream = buffered(b"ab", [Step::Data(b"cd")]);
        let mut storage = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut storage);
        read_buf.put_slice(b"xx");
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok(())) = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) else {
            panic!("expected a ready read");
        };
        assert_eq!(read_buf.filled(), b"xxabcd");
    }

    #[tokio::test]
    async fn read_limit_across_buffer_boundary() {
        let mut stream = buffered(b"ab", [Step::Data(b"cdef")]);
        let mut head = Vec::new();
        (&mut stream).take(3).read_to_end(&mut head).await.unwrap();
        assert_eq!(head, b"abc");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"def");
    }

    #[tokio::test]
    async fn into_inner_returns_unread_buffer() {
        let mut stream = buffered(b"abcd", [Step::Data(b"ef")]);
        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abc");
        let (_, rest) = stream.into_inner();
        assert_eq!(rest, &b"d"[..]);
    }

    #[test]
    fn clone_keeps_os_error_code() {
        let mut stream = Rewind::new_buffered(std::io::Cursor::new(Vec::<u8>::new()), Bytes::new());
        stream.deferred_err = Some(io::Error::from_raw_os_error(10054));
        let clone = stream.clone();
        for copy in [stream, clone] {
            assert_eq!(
                copy.deferred_err.and_then(|err| err.raw_os_error()),
                Some(10054)
            );
        }
    }
}
