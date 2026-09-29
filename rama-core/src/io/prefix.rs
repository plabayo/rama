use std::{
    fmt,
    io::{IoSlice, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use crate::extensions::{Extensions, ExtensionsRef};
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// a stream which has some data prefixed
    /// to be read first prior to any other reading.
    ///
    /// The source of that prefix data is often the result
    /// of data which was "peeked" from the inner I/O,
    /// although that is not required.
    ///
    /// It's similar to `ChainReader`, except that writing is also
    /// supported and happening directly in function of the inner stream.
    ///
    /// Once the prefix is drained, that same async read also
    /// tries one inner read when the buf has room left, so a
    /// peeked prefix need not be a short read of its own.
    /// Sync reads never do this.
    #[derive(Debug)]
    pub struct PrefixedIo<P, S> {
        prefix_eof: bool,
        // error hit after bytes were already read
        deferred_err: Option<std::io::Error>,
        #[pin]
        prefix: P,
        #[pin]
        inner: S,
    }
}

impl<P, S> PrefixedIo<P, S> {
    /// Create a new [`PrefixedIo`] for the given prefix
    /// [`AsyncRead`] and inner [`Io`] which implements [`ExtensionsRef`].
    ///
    /// [`Io`]: super::Io
    pub fn new(prefix: P, inner: S) -> Self {
        Self {
            prefix_eof: false,
            deferred_err: None,
            prefix,
            inner,
        }
    }
}

impl<P: Clone, S: Clone> Clone for PrefixedIo<P, S> {
    fn clone(&self) -> Self {
        Self {
            prefix_eof: self.prefix_eof,
            // io::Error is not Clone, keep the OS code if any
            deferred_err: self.deferred_err.as_ref().map(|err| {
                err.raw_os_error().map_or_else(
                    || std::io::Error::new(err.kind(), err.to_string()),
                    std::io::Error::from_raw_os_error,
                )
            }),
            prefix: self.prefix.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<P, S: ExtensionsRef> ExtensionsRef for PrefixedIo<P, S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

#[warn(clippy::missing_trait_methods)]
impl<P, S> AsyncRead for PrefixedIo<P, S>
where
    P: AsyncRead,
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut me = self.project();

        // an empty buf would look like prefix EOF
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(err) = me.deferred_err.take() {
            return Poll::Ready(Err(err));
        }

        if !*me.prefix_eof {
            let start = buf.filled().len();
            // Only an empty read proves the prefix is drained;
            // topping up before that would reorder bytes.
            while buf.remaining() > 0 {
                let before = buf.filled().len();
                match me.prefix.as_mut().poll_read(cx, buf) {
                    Poll::Ready(Ok(())) if buf.filled().len() == before => {
                        *me.prefix_eof = true;
                        break;
                    }
                    Poll::Ready(Ok(())) => {}
                    // never hide bytes already in buf
                    Poll::Pending if buf.filled().len() > start => {
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) if buf.filled().len() > start => {
                        *me.deferred_err = Some(err);
                        return Poll::Ready(Ok(()));
                    }
                    other => return other,
                }
            }

            if buf.filled().len() > start {
                if *me.prefix_eof
                    && buf.remaining() > 0
                    && let Poll::Ready(Err(err)) = me.inner.poll_read(cx, buf)
                {
                    // Returned next call: some sockets report a
                    // reset only once and read EOF after that.
                    *me.deferred_err = Some(err);
                }
                return Poll::Ready(Ok(()));
            }
        }
        me.inner.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<P, S> AsyncBufRead for PrefixedIo<P, S>
where
    P: AsyncBufRead,
    S: AsyncBufRead,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let me = self.project();

        if let Some(err) = me.deferred_err.take() {
            return Poll::Ready(Err(err));
        }

        if !*me.prefix_eof {
            match ready!(me.prefix.poll_fill_buf(cx)?) {
                [] => {
                    *me.prefix_eof = true;
                }
                buf => return Poll::Ready(Ok(buf)),
            }
        }
        me.inner.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        if !*me.prefix_eof {
            me.prefix.consume(amt)
        } else {
            me.inner.consume(amt)
        }
    }
}

impl<P, S> Read for PrefixedIo<P, S>
where
    P: Read,
    S: Read,
{
    // No top-up here: a blocking inner read could stall bytes
    // the prefix already produced.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // an empty buf would look like prefix EOF
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(err) = self.deferred_err.take() {
            return Err(err);
        }
        if !self.prefix_eof {
            let n = self.prefix.read(buf)?;
            if n == 0 {
                self.prefix_eof = true;
            } else {
                return Ok(n);
            }
        }
        self.inner.read(buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<P, S> AsyncWrite for PrefixedIo<P, S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        me.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let me = self.project();
        me.inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<P, S> Write for PrefixedIo<P, S>
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

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> std::io::Result<()> {
        self.inner.write_fmt(args)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.inner.write_vectored(bufs)
    }
}

#[cfg(test)]
mod tests {
    use crate::ServiceInput;

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
    async fn test_prefix_stream_read() {
        #[derive(Debug)]
        struct TestCase<const N: usize> {
            prefix_data: &'static str,
            inner_data: &'static str,
            // async reads top up, sync reads don't
            expected_async_reads: &'static [&'static str],
            expected_sync_reads: &'static [&'static str],
        }

        impl<const N: usize> TestCase<N> {
            async fn test_sync_and_async(&self) {
                let new_stream = || {
                    let prefix_data = Cursor::new(self.prefix_data);
                    let inner_data = Cursor::new(self.inner_data);
                    PrefixedIo::new(prefix_data, ServiceInput::new(inner_data))
                };

                test_multi_read_async::<N>(&mut new_stream(), self.expected_async_reads).await;
                test_multi_read_sync::<N>(&mut new_stream(), self.expected_sync_reads);
            }
        }

        TestCase::<10> {
            prefix_data: "hello",
            inner_data: " world",
            expected_async_reads: &["hello worl", "d", ""],
            expected_sync_reads: &["hello", " world", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<5> {
            prefix_data: "hello world",
            inner_data: "next data",
            expected_async_reads: &["hello", " worl", "dnext", " data", ""],
            expected_sync_reads: &["hello", " worl", "d", "next ", "data", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<2> {
            prefix_data: "peek",
            inner_data: "inner",
            expected_async_reads: &["pe", "ek", "in", "ne", "r", ""],
            expected_sync_reads: &["pe", "ek", "in", "ne", "r", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<8> {
            prefix_data: "",
            inner_data: "inner data",
            expected_async_reads: &["inner da", "ta", ""],
            expected_sync_reads: &["inner da", "ta", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<10> {
            prefix_data: "",
            inner_data: "inner data",
            expected_async_reads: &["inner data", ""],
            expected_sync_reads: &["inner data", ""],
        }
        .test_sync_and_async()
        .await;

        TestCase::<12> {
            prefix_data: "",
            inner_data: "inner data",
            expected_async_reads: &["inner data", ""],
            expected_sync_reads: &["inner data", ""],
        }
        .test_sync_and_async()
        .await;
    }

    enum Step {
        Data(&'static [u8]),
        Pending,
        Err(std::io::ErrorKind),
    }

    /// Reader that plays back a script, then reads EOF.
    struct ScriptReader(std::collections::VecDeque<Step>);

    impl ScriptReader {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self(steps.into_iter().collect())
        }
    }

    impl AsyncRead for ScriptReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.0.pop_front() {
                None => Poll::Ready(Ok(())),
                Some(Step::Pending) => Poll::Pending,
                Some(Step::Err(kind)) => Poll::Ready(Err(kind.into())),
                Some(Step::Data(data)) => {
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.0.push_front(Step::Data(&data[n..]));
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    fn poll_read_once<R: AsyncRead + Unpin>(
        reader: &mut R,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut read_buf = ReadBuf::new(buf);
        Pin::new(reader)
            .poll_read(&mut cx, &mut read_buf)
            .map_ok(|()| read_buf.filled().len())
    }

    #[tokio::test]
    async fn test_prefix_read_joins_ready_inner_data() {
        // kerberos-like: length header split by a 2 byte peek
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"\x00\x00"[..]),
            ScriptReader::new([Step::Data(b"\x00\x05hello")]),
        );
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"\x00\x00\x00\x05hello");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[test]
    fn test_prefix_read_does_not_wait_for_inner() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            ScriptReader::new([Step::Pending, Step::Data(b"cd")]),
        );
        let mut buf = [0u8; 8];
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("prefix read must not wait on the inner stream");
        };
        assert_eq!(&buf[..n], b"ab");
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("expected inner data");
        };
        assert_eq!(&buf[..n], b"cd");
    }

    #[tokio::test]
    async fn test_prefix_read_defers_inner_error() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            ScriptReader::new([Step::Err(std::io::ErrorKind::ConnectionReset)]),
        );
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        // the script is done, so the inner stream now reads EOF
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_prefix_read_keeps_order_for_trickling_prefix() {
        let mut stream = PrefixedIo::new(
            ScriptReader::new([Step::Data(b"a"), Step::Data(b"b"), Step::Data(b"c")]),
            ScriptReader::new([Step::Data(b"def")]),
        );
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcdef");
    }

    #[test]
    fn test_prefix_read_returns_bytes_before_pending_prefix() {
        let mut stream = PrefixedIo::new(
            ScriptReader::new([Step::Data(b"ab"), Step::Pending, Step::Data(b"c")]),
            ScriptReader::new([Step::Data(b"inner")]),
        );
        let mut buf = [0u8; 16];
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("bytes already read must be returned");
        };
        assert_eq!(&buf[..n], b"ab");
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("expected the rest of the prefix");
        };
        assert_eq!(&buf[..n], b"cinner");
    }

    #[tokio::test]
    async fn test_prefix_read_defers_prefix_error_after_bytes() {
        let mut stream = PrefixedIo::new(
            ScriptReader::new([
                Step::Data(b"ab"),
                Step::Err(std::io::ErrorKind::Other),
                Step::Data(b"c"),
            ]),
            ScriptReader::new([Step::Data(b"inner")]),
        );
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        // the prefix resumes after its error
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"cinner");
    }

    #[tokio::test]
    async fn test_prefix_read_defers_inner_error_to_fill_buf() {
        use tokio::io::AsyncBufReadExt;

        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            tokio::io::BufReader::new(ScriptReader::new([Step::Err(
                std::io::ErrorKind::ConnectionReset,
            )])),
        );
        let mut buf = [0u8; 8];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        let err = stream.fill_buf().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        // delivered once
        assert!(stream.fill_buf().await.unwrap().is_empty());
    }

    /// [`ScriptReader`] that can also be read sync.
    struct SyncScriptReader(ScriptReader);

    impl AsyncRead for SyncScriptReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl Read for SyncScriptReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match poll_read_once(&mut self.0, buf) {
                Poll::Ready(result) => result,
                Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
            }
        }
    }

    #[tokio::test]
    async fn test_prefix_read_defers_inner_error_to_sync_read() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            SyncScriptReader(ScriptReader::new([Step::Err(
                std::io::ErrorKind::ConnectionReset,
            )])),
        );
        let mut buf = [0u8; 8];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        let err = Read::read(&mut stream, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        // delivered once
        assert_eq!(Read::read(&mut stream, &mut buf).unwrap(), 0);
    }

    #[tokio::test]
    async fn test_prefix_empty_read_keeps_deferred_error() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            ScriptReader::new([Step::Err(std::io::ErrorKind::ConnectionReset)]),
        );
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn test_prefix_read_with_inner_eof() {
        let mut stream = PrefixedIo::new(Cursor::new(&b"ab"[..]), ScriptReader::new([]));
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ab");
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[test]
    fn test_prefix_read_pending_before_any_prefix_bytes() {
        let mut stream = PrefixedIo::new(
            ScriptReader::new([Step::Pending, Step::Data(b"ab")]),
            ScriptReader::new([Step::Data(b"cd")]),
        );
        let mut buf = [0u8; 8];
        assert!(poll_read_once(&mut stream, &mut buf).is_pending());
        let Poll::Ready(Ok(n)) = poll_read_once(&mut stream, &mut buf) else {
            panic!("expected prefix and inner data");
        };
        assert_eq!(&buf[..n], b"abcd");
    }

    #[tokio::test]
    async fn test_prefix_read_error_before_any_prefix_bytes() {
        let mut stream = PrefixedIo::new(
            ScriptReader::new([Step::Err(std::io::ErrorKind::Other), Step::Data(b"ab")]),
            ScriptReader::new([Step::Data(b"cd")]),
        );
        let mut buf = [0u8; 8];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
    }

    #[test]
    fn test_prefix_read_appends_to_prefilled_buf() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            ScriptReader::new([Step::Data(b"cd")]),
        );
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
    async fn test_prefix_read_limit_across_prefix_boundary() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"ab"[..]),
            ScriptReader::new([Step::Data(b"cdef")]),
        );
        let mut head = Vec::new();
        AsyncReadExt::take(&mut stream, 3)
            .read_to_end(&mut head)
            .await
            .unwrap();
        assert_eq!(head, b"abc");
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"def");
    }

    #[test]
    fn test_prefix_clone_keeps_os_error_code() {
        let mut stream = PrefixedIo::new(Cursor::new(&b""[..]), Cursor::new(&b""[..]));
        stream.deferred_err = Some(std::io::Error::from_raw_os_error(10054));
        let clone = stream.clone();
        assert_eq!(
            clone.deferred_err.and_then(|err| err.raw_os_error()),
            Some(10054)
        );
    }

    #[tokio::test]
    async fn test_prefix_read_nested() {
        let mut stream = PrefixedIo::new(
            Cursor::new(&b"a"[..]),
            PrefixedIo::new(Cursor::new(&b"b"[..]), Cursor::new(&b"cd"[..])),
        );
        let mut buf = [0u8; 16];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
    }

    #[tokio::test]
    async fn test_prefix_zero_capacity_read_keeps_prefix() {
        let mut stream = PrefixedIo::new(Cursor::new(&b"ab"[..]), Cursor::new(&b"cd"[..]));
        assert_eq!(AsyncReadExt::read(&mut stream, &mut []).await.unwrap(), 0);
        let mut buf = [0u8; 16];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");

        let mut stream = PrefixedIo::new(Cursor::new(&b"ab"[..]), Cursor::new(&b"cd"[..]));
        assert_eq!(Read::read(&mut stream, &mut []).unwrap(), 0);
        let n = Read::read(&mut stream, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ab");
    }

    fn new_prefix_write_stream() -> PrefixedIo<Cursor<Vec<u8>>, ServiceInput<Cursor<Vec<u8>>>> {
        let prefix_data = Cursor::new(Vec::new());
        let inner_data = Cursor::new(Vec::new());
        PrefixedIo::new(prefix_data, ServiceInput::new(inner_data))
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
    async fn test_prefix_stream_write() {
        #[derive(Debug)]
        struct TestCase<'a> {
            writes: &'a [&'static str],
        }

        impl TestCase<'_> {
            async fn test_sync_and_async(&self) {
                let mut stream = new_prefix_write_stream();
                test_multi_write_async(&mut stream, self.writes).await;

                assert!(!stream.prefix_eof, "[async] writes: {:?}", self.writes);
                assert_eq!(
                    stream.prefix.position(),
                    0,
                    "[async] writes: {:?}",
                    self.writes
                );
                assert!(
                    stream.prefix.into_inner().is_empty(),
                    "[async] writes: {:?}",
                    self.writes
                );

                assert_eq!(
                    self.writes.join(""),
                    String::from_utf8(stream.inner.input.into_inner()).unwrap(),
                    "[async] writes: {:?}",
                    self.writes,
                );

                let mut stream = new_prefix_write_stream();
                test_multi_write_sync(&mut stream, self.writes);

                assert!(!stream.prefix_eof, "[sync] writes: {:?}", self.writes);
                assert_eq!(
                    stream.prefix.position(),
                    0,
                    "[sync] writes: {:?}",
                    self.writes
                );
                assert!(
                    stream.prefix.into_inner().is_empty(),
                    "[sync] writes: {:?}",
                    self.writes,
                );

                assert_eq!(
                    self.writes.join(""),
                    String::from_utf8(stream.inner.input.into_inner()).unwrap(),
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
