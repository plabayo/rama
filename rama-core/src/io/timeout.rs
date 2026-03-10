use pin_project_lite::pin_project;
use rama_utils::macros::generate_set_and_with;
use std::{
    io::{self, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf},
    time::{Instant, Sleep, sleep_until},
};

pin_project! {
    #[derive(Debug)]
    struct TimeoutState {
        timeout: Option<Duration>,
        #[pin]
        cur: Sleep,
        active: bool,
    }
}

impl TimeoutState {
    #[inline]
    fn new() -> Self {
        Self {
            timeout: None,
            cur: sleep_until(Instant::now()),
            active: false,
        }
    }

    #[inline]
    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    #[inline]
    fn set_timeout(&mut self, timeout: Option<Duration>) {
        debug_assert!(
            !self.active,
            "set_timeout is only expected before a timeout becomes active"
        );
        self.timeout = timeout;
    }

    #[inline]
    fn set_timeout_pinned(mut self: Pin<&mut Self>, timeout: Option<Duration>) {
        *self.as_mut().project().timeout = timeout;
        self.reset();
    }

    #[inline]
    fn reset(self: Pin<&mut Self>) {
        let this = self.project();

        if *this.active {
            *this.active = false;
            this.cur.reset(Instant::now());
        }
    }

    #[inline]
    fn poll_check(self: Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<()> {
        let mut this = self.project();

        let timeout = match this.timeout {
            Some(timeout) => *timeout,
            None => return Ok(()),
        };

        if !*this.active {
            this.cur.as_mut().reset(Instant::now() + timeout);
            *this.active = true;
        }

        match this.cur.poll(cx) {
            Poll::Ready(()) => {
                *this.active = false;
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
            Poll::Pending => Ok(()),
        }
    }
}

pin_project! {
    /// An `AsyncRead`er which applies a timeout to read operations.
    #[derive(Debug)]
    pub struct TimeoutReader<R> {
        #[pin]
        reader: R,
        #[pin]
        state: TimeoutState,
    }
}

impl<R> TimeoutReader<R>
where
    R: AsyncRead,
{
    /// Returns a new `TimeoutReader` wrapping the specified reader.
    ///
    /// There is initially no timeout.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            state: TimeoutState::new(),
        }
    }

    /// Returns the current read timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.state.timeout()
    }

    generate_set_and_with! {
        /// Sets the read timeout.
        ///
        /// This can only be used before the reader is pinned;
        /// use [`set_timeout_pinned`](Self::set_timeout_pinned)
        /// otherwise.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.state.set_timeout(timeout);
            self
        }
    }

    /// Sets the read timeout.
    ///
    /// This will reset any pending timeout. Use [`set_timeout`](Self::set_timeout) instead if the reader is not yet
    /// pinned.
    pub fn set_timeout_pinned(self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.project().state.set_timeout_pinned(timeout);
    }

    /// Returns a shared reference to the inner reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Returns a mutable reference to the inner reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Returns a pinned mutable reference to the inner reader.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
        self.project().reader
    }

    /// Consumes the `TimeoutReader`, returning the inner reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R> AsyncRead for TimeoutReader<R>
where
    R: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        let r = this.reader.poll_read(cx, buf);
        match r {
            Poll::Pending => this.state.poll_check(cx)?,
            Poll::Ready(_) => this.state.reset(),
        }
        r
    }
}

impl<R> AsyncWrite for TimeoutReader<R>
where
    R: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().reader.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().reader.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().reader.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().reader.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.reader.is_write_vectored()
    }
}

impl<R> AsyncSeek for TimeoutReader<R>
where
    R: AsyncSeek,
{
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        self.project().reader.start_seek(position)
    }
    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        self.project().reader.poll_complete(cx)
    }
}

pin_project! {
    /// An `AsyncWrite`er which applies a timeout to write operations.
    #[derive(Debug)]
    pub struct TimeoutWriter<W> {
        #[pin]
        writer: W,
        #[pin]
        state: TimeoutState,
    }
}

impl<W> TimeoutWriter<W>
where
    W: AsyncWrite,
{
    /// Returns a new `TimeoutWriter` wrapping the specified writer.
    ///
    /// There is initially no timeout.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            state: TimeoutState::new(),
        }
    }

    /// Returns the current write timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.state.timeout()
    }

    generate_set_and_with! {
        /// Sets the write timeout.
        ///
        /// This can only be used before the writer is pinned;
        /// use [`set_timeout_pinned`](Self::set_timeout_pinned)
        /// otherwise.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.state.set_timeout(timeout);
            self
        }
    }

    /// Sets the write timeout.
    ///
    /// This will reset any pending timeout. Use [`set_timeout`](Self::set_timeout)
    /// instead if the writer is not yet pinned.
    pub fn set_timeout_pinned(self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.project().state.set_timeout_pinned(timeout);
    }

    /// Returns a shared reference to the inner writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Returns a mutable reference to the inner writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Returns a pinned mutable reference to the inner writer.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut W> {
        self.project().writer
    }

    /// Consumes the `TimeoutWriter`, returning the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> AsyncWrite for TimeoutWriter<W>
where
    W: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let r = this.writer.poll_write(cx, buf);
        match r {
            Poll::Pending => this.state.poll_check(cx)?,
            Poll::Ready(_) => this.state.reset(),
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        let r = this.writer.poll_flush(cx);
        match r {
            Poll::Pending => this.state.poll_check(cx)?,
            Poll::Ready(_) => this.state.reset(),
        }
        r
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        let r = this.writer.poll_shutdown(cx);
        match r {
            Poll::Pending => this.state.poll_check(cx)?,
            Poll::Ready(_) => this.state.reset(),
        }
        r
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let r = this.writer.poll_write_vectored(cx, bufs);
        match r {
            Poll::Pending => this.state.poll_check(cx)?,
            Poll::Ready(_) => this.state.reset(),
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.writer.is_write_vectored()
    }
}

impl<W> AsyncRead for TimeoutWriter<W>
where
    W: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().writer.poll_read(cx, buf)
    }
}

impl<W> AsyncSeek for TimeoutWriter<W>
where
    W: AsyncSeek,
{
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        self.project().writer.start_seek(position)
    }
    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        self.project().writer.poll_complete(cx)
    }
}

pin_project! {
    /// A io which applies read and write timeouts to an inner io.
    #[derive(Debug)]
    pub struct TimeoutIo<S> {
        #[pin]
        io: TimeoutReader<TimeoutWriter<S>>
    }
}

impl<S> TimeoutIo<S>
where
    S: AsyncRead + AsyncWrite,
{
    /// Returns a new `TimeoutIo` wrapping the specified io.
    ///
    /// There is initially no read or write timeout.
    pub fn new(io: S) -> Self {
        let writer = TimeoutWriter::new(io);
        let io = TimeoutReader::new(writer);
        Self { io }
    }

    /// Returns the current read timeout.
    pub fn read_timeout(&self) -> Option<Duration> {
        self.io.timeout()
    }

    generate_set_and_with! {
        /// Sets the read timeout.
        ///
        /// This can only be used before the io is pinned; use
        /// [`set_read_timeout_pinned`](Self::set_read_timeout_pinned) otherwise.
        pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.io.maybe_set_timeout(timeout);
            self
        }
    }

    /// Sets the read timeout.
    ///
    /// This will reset any pending read timeout. Use [`set_read_timeout`](Self::set_read_timeout) instead if the io
    /// has not yet been pinned.
    pub fn set_read_timeout_pinned(self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.project().io.set_timeout_pinned(timeout)
    }

    /// Returns the current write timeout.
    pub fn write_timeout(&self) -> Option<Duration> {
        self.io.get_ref().timeout()
    }

    generate_set_and_with! {
        /// Sets the write timeout.
        ///
        /// This can only be used before the io is pinned; use
        /// [`set_write_timeout_pinned`](Self::set_write_timeout_pinned) otherwise.
        pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.io.get_mut().maybe_set_timeout(timeout);
            self
        }
    }

    /// Sets the write timeout.
    ///
    /// This will reset any pending write timeout. Use [`set_write_timeout`](Self::set_write_timeout) instead if the
    /// io has not yet been pinned.
    pub fn set_write_timeout_pinned(self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.project().io.get_pin_mut().set_timeout_pinned(timeout)
    }

    /// Returns a shared reference to the inner io.
    pub fn get_ref(&self) -> &S {
        self.io.get_ref().get_ref()
    }

    /// Returns a mutable reference to the inner io.
    pub fn get_mut(&mut self) -> &mut S {
        self.io.get_mut().get_mut()
    }

    /// Returns a pinned mutable reference to the inner io.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        self.project().io.get_pin_mut().get_pin_mut()
    }

    /// Consumes the io, returning the inner io.
    pub fn into_inner(self) -> S {
        self.io.into_inner().into_inner()
    }
}

impl<S> AsyncRead for TimeoutIo<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().io.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TimeoutIo<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().io.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().io.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().io.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::futures::FutureExt as _;

    use std::pin::pin;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    pin_project! {
        struct DelayIo {
            #[pin]
            sleep: Sleep,
        }
    }

    impl DelayIo {
        fn new(until: Instant) -> Self {
            Self {
                sleep: sleep_until(until),
            }
        }
    }

    impl AsyncRead for DelayIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            _buf: &mut ReadBuf,
        ) -> Poll<Result<(), io::Error>> {
            match self.project().sleep.poll(cx) {
                Poll::Ready(()) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for DelayIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            match self.project().sleep.poll(cx) {
                Poll::Ready(()) => Poll::Ready(Ok(buf.len())),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_timeout() {
        let reader = DelayIo::new(Instant::now() + Duration::from_millis(150));
        let mut reader = pin!(TimeoutReader::new(reader).with_timeout(Duration::from_millis(100)));

        let r = reader.read(&mut [0]).await;
        assert_eq!(r.err().unwrap().kind(), io::ErrorKind::TimedOut);

        let _ = reader.read(&mut [0]).await.unwrap();
    }

    #[tokio::test]
    async fn read_ok() {
        let reader = DelayIo::new(Instant::now() + Duration::from_millis(100));
        let mut reader = pin!(TimeoutReader::new(reader).with_timeout(Duration::from_millis(500)));

        let _ = reader.read(&mut [0]).await.unwrap();
    }

    #[tokio::test]
    async fn write_timeout() {
        let writer = DelayIo::new(Instant::now() + Duration::from_millis(150));
        let mut writer = pin!(TimeoutWriter::new(writer).with_timeout(Duration::from_millis(100)));

        let r = writer.write(&[0]).await;
        assert_eq!(r.err().unwrap().kind(), io::ErrorKind::TimedOut);

        let _ = writer.write(&[0]).await.unwrap();
    }

    #[tokio::test]
    async fn write_ok() {
        let writer = DelayIo::new(Instant::now() + Duration::from_millis(100));
        let mut writer = pin!(TimeoutWriter::new(writer).with_timeout(Duration::from_millis(500)));

        let _ = writer.write(&[0]).await.unwrap();
    }

    #[tokio::test]
    async fn read_timeout_disabled() {
        let reader = DelayIo::new(Instant::now() + Duration::from_millis(20));
        let mut reader = pin!(TimeoutReader::new(reader));

        let _ = reader.read(&mut [0]).await.unwrap();
    }

    #[tokio::test]
    async fn write_timeout_disabled() {
        let writer = DelayIo::new(Instant::now() + Duration::from_millis(20));
        let mut writer = pin!(TimeoutWriter::new(writer));

        let _ = writer.write(&[0]).await.unwrap();
    }

    #[tokio::test]
    async fn read_set_timeout_pinned_resets_pending_timer() {
        let reader = DelayIo::new(Instant::now() + Duration::from_millis(150));
        let mut reader = pin!(TimeoutReader::new(reader).with_timeout(Duration::from_millis(100)));

        let mut buf = [0];

        {
            let mut pinned_reader = reader.as_mut();
            let mut fut = pin!(pinned_reader.read(&mut buf));
            assert!(fut.as_mut().now_or_never().is_none());
        }

        reader
            .as_mut()
            .set_timeout_pinned(Some(Duration::from_millis(500)));

        let _ = reader.read(&mut [0]).await.unwrap();
    }

    #[tokio::test]
    async fn write_set_timeout_pinned_resets_pending_timer() {
        let writer = DelayIo::new(Instant::now() + Duration::from_millis(150));
        let mut writer = pin!(TimeoutWriter::new(writer).with_timeout(Duration::from_millis(100)));

        {
            let mut pinned_writer = writer.as_mut();
            let mut fut = pin!(pinned_writer.write(&[0]));
            assert!(fut.as_mut().now_or_never().is_none());
        }

        writer
            .as_mut()
            .set_timeout_pinned(Some(Duration::from_millis(500)));

        let _ = writer.write(&[0]).await.unwrap();
    }

    #[tokio::test]
    async fn rw_test() {
        let (mut writer, reader) = duplex(16);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            writer.write_all(b"f").await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = writer.write_all(b"f").await; // this may hit an eof
        });

        let mut s = pin!(TimeoutIo::new(reader).with_read_timeout(Duration::from_millis(100)));

        let _ = s.read(&mut [0]).await.unwrap();
        let r = s.read(&mut [0]).await;

        match r {
            Ok(v) => panic!("unexpected success: value = {v}"),
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_io_write_timeout() {
        let io = DelayIo::new(Instant::now() + Duration::from_millis(150));
        let mut io = pin!(TimeoutIo::new(io).with_write_timeout(Duration::from_millis(100)));

        let r = io.write(&[0]).await;
        assert_eq!(r.err().unwrap().kind(), io::ErrorKind::TimedOut);
    }
}
