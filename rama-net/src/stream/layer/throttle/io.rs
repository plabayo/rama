use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_utils::rate::{Acquire, Rate, RateLimiter, TokenBucket};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

use super::ThrottleMode;

pin_project! {
    /// A wrapper around an [`AsyncRead`] and/or [`AsyncWrite`] that
    /// paces reads and/or writes against a byte-rate token bucket.
    ///
    /// See the [module docs](super) for the semantics, and
    /// [`ThrottleLayer`](super::ThrottleLayer) /
    /// [`OutgoingThrottleLayer`](super::OutgoingThrottleLayer) to apply
    /// this in a transport stack.
    ///
    /// [`AsyncRead`]: tokio::io::AsyncRead
    /// [`AsyncWrite`]: tokio::io::AsyncWrite
    #[derive(Debug)]
    pub struct ThrottledIo<S> {
        #[pin]
        stream: S,
        read: Option<DirState>,
        write: Option<DirState>,
        quantum: Option<u64>,
    }
}

impl<S> ThrottledIo<S> {
    /// Create a new [`ThrottledIo`] that (until a mode is set)
    /// throttles neither direction.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read: None,
            write: None,
            quantum: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Throttle the read (ingress) direction with the given
        /// [`ThrottleMode`], or disable it with `None`.
        ///
        /// Setting a mode must happen within a tokio runtime context.
        pub fn read_mode(mut self, mode: Option<ThrottleMode>) -> Self {
            self.read = mode.map(|mode| DirState::new(mode, self.quantum));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Throttle the write (egress) direction with the given
        /// [`ThrottleMode`], or disable it with `None`.
        ///
        /// Setting a mode must happen within a tokio runtime context.
        pub fn write_mode(mut self, mode: Option<ThrottleMode>) -> Self {
            self.write = mode.map(|mode| DirState::new(mode, self.quantum));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the grant quantum in bytes: the budget reserved per
        /// IO operation (clamped to the burst capacity).
        ///
        /// Defaults to a tenth of a period worth of bytes, at most 16 KiB.
        pub fn quantum(mut self, quantum: Option<u64>) -> Self {
            self.quantum = quantum;
            for state in [&mut self.read, &mut self.write].into_iter().flatten() {
                state.set_quantum(quantum);
            }
            self
        }
    }

    /// Get the inner [`AsyncRead`] and/or [`AsyncWrite`] stream,
    /// dropping the throttling for this stream.
    ///
    /// [`AsyncRead`]: tokio::io::AsyncRead
    /// [`AsyncWrite`]: tokio::io::AsyncWrite
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Get a reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

impl<S: ExtensionsRef> ExtensionsRef for ThrottledIo<S> {
    fn extensions(&self) -> &Extensions {
        self.stream.extensions()
    }
}

#[derive(Debug)]
struct DirState {
    budget: Budget,
    burst: u64,
    quantum: u64,
    reserved: u64,
    sleep: Option<Pin<Box<Sleep>>>,
    sleeping: bool,
}

impl DirState {
    fn new(mode: ThrottleMode, quantum: Option<u64>) -> Self {
        let (budget, rate, burst) = match mode {
            ThrottleMode::PerConn { rate, burst } => (
                Budget::Own {
                    bucket: TokenBucket::new(rate, burst),
                    epoch: Instant::now(),
                },
                rate,
                burst,
            ),
            ThrottleMode::Shared(limiter) => {
                let rate = limiter.rate();
                let burst = limiter.burst();
                (Budget::Shared(limiter), rate, burst)
            }
        };
        let quantum = quantum
            .unwrap_or_else(|| super::default_quantum(rate))
            .clamp(1, burst);
        Self {
            budget,
            burst,
            quantum,
            reserved: 0,
            sleep: None,
            sleeping: false,
        }
    }

    fn set_quantum(&mut self, quantum: Option<u64>) {
        self.quantum = match quantum {
            Some(quantum) => quantum.clamp(1, self.burst),
            None => super::default_quantum(self.budget.rate()).clamp(1, self.burst),
        };
    }

    /// Reserve budget for the next IO operation of (up to) `want_hint`
    /// bytes, sleeping until the bucket allows it.
    ///
    /// A reservation is carried across `Pending` polls and must be
    /// settled with [`DirState::settle`] once the IO completed.
    fn poll_reserve(&mut self, cx: &mut Context<'_>, want_hint: u64) -> Poll<u64> {
        loop {
            if self.reserved > 0 {
                return Poll::Ready(self.reserved);
            }
            let want = want_hint.min(self.quantum).max(1);
            match self.budget.try_acquire(want) {
                Acquire::Granted => {
                    self.reserved = want;
                    return Poll::Ready(want);
                }
                Acquire::RetryAt(at) => {
                    let deadline = self.budget.deadline(at);
                    let sleep = self
                        .sleep
                        .get_or_insert_with(|| Box::pin(sleep_until(deadline)));
                    if !self.sleeping {
                        sleep.as_mut().reset(deadline);
                        self.sleeping = true;
                    }
                    ready!(sleep.as_mut().poll(cx));
                    self.sleeping = false;
                }
                Acquire::Never => {
                    // defence-in-depth: want is clamped to the quantum,
                    // which is clamped to the burst capacity
                    debug_assert!(false, "quantum-clamped reserve reported Acquire::Never");
                    self.reserved = want;
                    return Poll::Ready(want);
                }
            }
        }
    }

    /// Settle the current reservation: `used` bytes were consumed,
    /// the remainder is refunded.
    fn settle(&mut self, used: u64) {
        let unused = self.reserved.saturating_sub(used);
        if unused > 0 {
            self.budget.refund(unused);
        }
        self.reserved = 0;
    }
}

impl Drop for DirState {
    fn drop(&mut self) {
        // an IO dropped mid-operation gives its reservation back
        // (only observable for a shared budget)
        if self.reserved > 0 {
            self.budget.refund(self.reserved);
        }
    }
}

#[derive(Debug)]
enum Budget {
    Own { bucket: TokenBucket, epoch: Instant },
    Shared(RateLimiter),
}

impl Budget {
    fn rate(&self) -> Rate {
        match self {
            Self::Own { bucket, .. } => bucket.rate(),
            Self::Shared(limiter) => limiter.rate(),
        }
    }

    fn try_acquire(&mut self, n: u64) -> Acquire {
        match self {
            Self::Own { bucket, epoch } => {
                let now = Instant::now().saturating_duration_since(*epoch).as_nanos() as u64;
                bucket.try_acquire(now, n)
            }
            Self::Shared(limiter) => limiter.try_acquire(n),
        }
    }

    fn refund(&mut self, n: u64) {
        match self {
            Self::Own { bucket, .. } => bucket.refund(n),
            Self::Shared(limiter) => limiter.refund(n),
        }
    }

    fn deadline(&self, retry_at_nanos: u64) -> Instant {
        match self {
            Self::Own { epoch, .. } => epoch
                .checked_add(Duration::from_nanos(retry_at_nanos))
                // saturated retry-at with an extreme rate config: far enough
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400 * 365)),
            Self::Shared(limiter) => limiter.deadline(retry_at_nanos),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncRead for ThrottledIo<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let Some(state) = this.read else {
            return this.stream.poll_read(cx, buf);
        };
        if buf.remaining() == 0 {
            return this.stream.poll_read(cx, buf);
        }

        let reserved = ready!(state.poll_reserve(cx, buf.remaining() as u64));

        let mut limited = buf.take((reserved as usize).min(buf.remaining()));
        match this.stream.poll_read(cx, &mut limited) {
            // reservation is kept for the next poll
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                // SAFETY: `limited` borrows the unfilled part of `buf`
                // and the inner reader initialized+filled `n` bytes of it.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                state.settle(n as u64);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                state.settle(0);
                Poll::Ready(Err(err))
            }
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncWrite for ThrottledIo<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let Some(state) = this.write else {
            return this.stream.poll_write(cx, buf);
        };
        if buf.is_empty() {
            return this.stream.poll_write(cx, buf);
        }

        let reserved = ready!(state.poll_reserve(cx, buf.len() as u64));

        let allowed = (reserved as usize).min(buf.len());
        match this.stream.poll_write(cx, &buf[..allowed]) {
            // reservation is kept for the next poll
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                state.settle(n as u64);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                state.settle(0);
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        if self.write.is_none() {
            return self.project().stream.poll_write_vectored(cx, bufs);
        }
        // throttled: pace through poll_write on the first non-empty
        // buffer (correctness over vectored throughput)
        let buf = bufs
            .iter()
            .find(|buf| !buf.is_empty())
            .map_or(&[][..], |buf| &**buf);
        self.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        self.write.is_none() && self.stream.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_utils::rate::Rate;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn throttled_writer<S>(stream: S, units_per_sec: u64, quantum: u64) -> ThrottledIo<S> {
        ThrottledIo::new(stream)
            .with_write_mode(ThrottleMode::per_conn(Rate::per_sec(units_per_sec)))
            .with_quantum(quantum)
    }

    #[tokio::test(start_paused = true)]
    async fn write_paces_per_conn() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut throttled = throttled_writer(client, 1_000, 500);

        tokio::spawn(async move {
            let mut sink = Vec::new();
            server.read_to_end(&mut sink).await.unwrap();
        });

        let start = Instant::now();
        // 3000 bytes at 1000/s with a 1000 burst: 1000 now, rest at 1000/s
        throttled.write_all(&[0u8; 3_000]).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn read_paces_per_conn() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(&[0u8; 3_000]).await.unwrap();
        drop(server);

        let mut throttled = ThrottledIo::new(client)
            .with_read_mode(ThrottleMode::per_conn(Rate::per_sec(1_000)))
            .with_quantum(500);

        let start = Instant::now();
        let mut sink = Vec::new();
        throttled.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink.len(), 3_000);
        // 2s for the data + one more paced (and fully refunded)
        // reservation for the read that discovers EOF
        assert_eq!(start.elapsed(), Duration::from_millis(2_500));
    }

    #[tokio::test(start_paused = true)]
    async fn unthrottled_direction_passes_through() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        // only reads are throttled; writes are instant
        let mut throttled =
            ThrottledIo::new(client).with_read_mode(ThrottleMode::per_conn(Rate::per_sec(1)));

        let start = Instant::now();
        throttled.write_all(&[0u8; 10_000]).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        let mut buf = [0u8; 10_000];
        server.read_exact(&mut buf).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shared_budget_is_aggregate() {
        let limiter = RateLimiter::from_rate(Rate::per_sec(1_000));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let mut throttled = ThrottledIo::new(client)
                .with_write_mode(ThrottleMode::shared(limiter.clone()))
                .with_quantum(500);
            tokio::spawn(async move {
                let mut sink = Vec::new();
                server.read_to_end(&mut sink).await.unwrap();
            });
            tasks.spawn(async move { throttled.write_all(&[0u8; 1_000]).await });
        }

        let start = Instant::now();
        while let Some(res) = tasks.join_next().await {
            res.unwrap().unwrap();
        }
        // 2000 bytes against one shared 1000/s budget with a 1000 burst
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    /// an inner writer that accepts at most `max` bytes per write
    struct ShortWriter {
        max: usize,
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Ready(Ok(buf.len().min(self.max)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn short_writes_are_refunded() {
        // 90 bytes of budget total; without refunds the short writes
        // (3 x 30 out of reservations of 90/60/30) would need 180
        let mut throttled = throttled_writer(ShortWriter { max: 30 }, 90, 90);

        let start = Instant::now();
        throttled.write_all(&[0u8; 90]).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// an inner writer that returns Pending on every first call
    struct PendingOnceWriter {
        pending: bool,
    }

    impl AsyncWrite for PendingOnceWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending = true;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reservation_survives_pending_without_double_spend() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        let mut throttled = ThrottledIo::new(PendingOnceWriter { pending: true })
            .with_write_mode(ThrottleMode::shared(limiter.clone()))
            .with_quantum(100);

        let start = Instant::now();
        throttled.write_all(&[0u8; 100]).await.unwrap();
        // a double-spend across the Pending poll would have to wait
        assert_eq!(start.elapsed(), Duration::ZERO);
        // and exactly the written bytes were spent
        assert!(matches!(limiter.try_acquire(1), Acquire::RetryAt(_)));
    }

    /// an inner writer that never completes a write
    struct NeverWriter;

    impl AsyncWrite for NeverWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drop_refunds_shared_reservation() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        {
            let mut throttled = ThrottledIo::new(NeverWriter)
                .with_write_mode(ThrottleMode::shared(limiter.clone()));
            // reserve (inner write stays pending), then drop mid-write
            let write = throttled.write(&[0u8; 50]);
            tokio::time::timeout(Duration::from_millis(1), write)
                .await
                .unwrap_err();
        }
        assert_eq!(limiter.try_acquire(100), Acquire::Granted);
    }
}
