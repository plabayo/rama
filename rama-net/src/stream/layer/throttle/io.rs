use std::{
    fmt,
    future::Future,
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

struct DirState {
    budget: Budget,
    burst: u64,
    quantum: u64,
    /// Budget reserved for the IO poll currently in progress.
    reserved: u64,
    sleep: Option<Pin<Box<Sleep>>>,
    sleeping: bool,
    refund_wait: Option<RefundWait>,
}

impl fmt::Debug for DirState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirState")
            .field("budget", &self.budget)
            .field("burst", &self.burst)
            .field("quantum", &self.quantum)
            .field("reserved", &self.reserved)
            .field("sleep", &self.sleep)
            .field("sleeping", &self.sleeping)
            .field("waiting_for_refund", &self.refund_wait.is_some())
            .finish()
    }
}

struct RefundWait(Pin<Box<dyn Future<Output = ()> + Send + 'static>>);

impl fmt::Debug for RefundWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefundWait")
    }
}

impl Future for RefundWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
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
            refund_wait: None,
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
    /// Callers refund on `Pending` so an idle connection holds no capacity.
    fn poll_reserve(&mut self, cx: &mut Context<'_>, want_hint: u64) -> Poll<u64> {
        loop {
            if self.reserved > 0 {
                return Poll::Ready(self.reserved);
            }
            if self
                .refund_wait
                .as_mut()
                .is_some_and(|wait| Pin::new(wait).poll(cx).is_ready())
            {
                self.refund_wait = None;
                self.sleeping = false;
                continue;
            }
            let want = want_hint.min(self.quantum).max(1);
            let mut acquire = self.budget.try_acquire(want);
            if matches!(acquire, Acquire::RetryAt(_)) && self.refund_wait.is_none() {
                self.refund_wait = self.budget.refund_wait();
                if self
                    .refund_wait
                    .as_mut()
                    .is_some_and(|wait| Pin::new(wait).poll(cx).is_ready())
                {
                    self.refund_wait = None;
                    self.sleeping = false;
                    continue;
                }
                // The listener is registered now. Retry once to close the
                // window in which a refund could have landed after the first
                // budget check but before waker registration.
                acquire = self.budget.try_acquire(want);
            }
            match acquire {
                Acquire::Granted => {
                    self.refund_wait = None;
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
                let now =
                    u64::try_from(Instant::now().saturating_duration_since(*epoch).as_nanos())
                        .unwrap_or(u64::MAX);
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

    fn refund_wait(&self) -> Option<RefundWait> {
        match self {
            Self::Own { .. } => None,
            Self::Shared(limiter) => Some(RefundWait(Box::pin(limiter.notified_on_refund()))),
        }
    }

    fn deadline(&self, retry_at_nanos: u64) -> Instant {
        match self {
            Self::Own { epoch, .. } => epoch
                .checked_add(Duration::from_nanos(retry_at_nanos))
                // saturated retry-at with an extreme rate config: far enough
                .unwrap_or_else(|| {
                    Instant::now()
                        .checked_add(Duration::from_hours(8_760))
                        .unwrap_or_else(Instant::now)
                }),
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
        let cap = (reserved as usize).min(buf.remaining());
        let mut limited = buf.take(cap);
        match this.stream.poll_read(cx, &mut limited) {
            Poll::Pending => {
                // An idle reader must not pin aggregate capacity. The inner
                // reader registered this task's waker, so retry when it wakes.
                state.settle(0);
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                // SAFETY: `limited` borrows the unfilled part of `buf` and the
                // inner reader initialized+filled `n` bytes of it.
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
            Poll::Pending => {
                // No bytes were accepted. Refund before yielding so a pending
                // stream neither pins aggregate capacity nor later recreates
                // capacity after another stream spends intervening refill.
                // The inner writer registered this task's waker.
                state.settle(0);
                Poll::Pending
            }
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
        // 3000 bytes at 1000/s from a full 1000 burst: 1000 immediate and
        // 2000 paced. Discovering EOF waits for one 500-byte grant because
        // the wrapper cannot know the read is empty before polling it; that
        // grant is refunded.
        assert_eq!(start.elapsed(), Duration::from_millis(2_500));
    }

    #[tokio::test(start_paused = true)]
    async fn read_shared_budget_is_aggregate() {
        let limiter = RateLimiter::from_rate(Rate::per_sec(1_000));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            server.write_all(&[0u8; 1_000]).await.unwrap();
            drop(server);
            let mut throttled = ThrottledIo::new(client)
                .with_read_mode(ThrottleMode::shared(limiter.clone()))
                .with_quantum(500);
            tasks.spawn(async move {
                let mut sink = Vec::new();
                throttled.read_to_end(&mut sink).await.unwrap();
                sink.len()
            });
        }

        let start = Instant::now();
        let mut total = 0;
        while let Some(res) = tasks.join_next().await {
            total += res.unwrap();
        }
        assert_eq!(total, 2_000);
        // 2000 bytes read against one shared 1000/s budget with a 1000 burst,
        // plus one refunded 500-byte grant to discover EOF.
        assert_eq!(start.elapsed(), Duration::from_millis(1_500));
    }

    /// an inner reader that is always pending: data never arrives
    struct NeverReader;

    impl AsyncRead for NeverReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_read_holds_no_shared_budget() {
        use std::future::Future as _;

        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        let mut throttled =
            ThrottledIo::new(NeverReader).with_read_mode(ThrottleMode::shared(limiter.clone()));

        // poll the read exactly once: it is Pending (no data), and the
        // future is kept alive (not dropped), so nothing can have been
        // refunded — a reserve-before-read model would be holding a quantum.
        let mut buf = [0u8; 64];
        let read = throttled.read(&mut buf);
        let mut read = std::pin::pin!(read);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(read.as_mut().poll(&mut cx).is_pending());

        // the entire shared burst is still available: the pending read
        // charged nothing, so data-less connection churn steals no budget.
        assert_eq!(limiter.try_acquire(100), Acquire::Granted);
    }

    #[tokio::test(start_paused = true)]
    async fn final_read_spends_shared_budget_before_delivery() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(&[0u8; 50]).await.unwrap();

        let mut throttled = ThrottledIo::new(client)
            .with_read_mode(ThrottleMode::shared(limiter.clone()))
            .with_quantum(100);
        let mut buf = [0u8; 50];
        assert_eq!(throttled.read(&mut buf).await.unwrap(), 50);
        drop(throttled);

        assert_eq!(limiter.try_acquire(50), Acquire::Granted);
        assert!(matches!(limiter.try_acquire(1), Acquire::RetryAt(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn eof_read_costs_no_budget() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        let (client, server) = tokio::io::duplex(64 * 1024);
        drop(server); // immediate EOF, zero bytes

        let mut throttled =
            ThrottledIo::new(client).with_read_mode(ThrottleMode::shared(limiter.clone()));

        let mut sink = Vec::new();
        throttled.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink.len(), 0);
        // discovering EOF read no bytes, so the full burst is untouched
        assert_eq!(limiter.try_acquire(100), Acquire::Granted);
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

    #[tokio::test(start_paused = true)]
    async fn shared_refund_wakes_a_writer_before_its_old_deadline() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        assert_eq!(limiter.try_acquire(100), Acquire::Granted);
        let (client, _server) = tokio::io::duplex(1_024);
        let mut throttled = ThrottledIo::new(client)
            .with_write_mode(ThrottleMode::shared(limiter.clone()))
            .with_quantum(100);

        let start = Instant::now();
        let waiting = tokio::spawn(async move { throttled.write_all(&[0u8; 100]).await });
        tokio::task::yield_now().await;

        limiter.refund(100);
        waiting.await.unwrap().unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);
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
    async fn pending_write_refunds_then_reacquires_without_double_spend() {
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
    async fn pending_write_holds_no_shared_reservation() {
        let limiter = RateLimiter::new(Rate::per_sec(100), 100);
        {
            let mut throttled = ThrottledIo::new(NeverWriter)
                .with_write_mode(ThrottleMode::shared(limiter.clone()));
            // poll once (inner write stays pending), then drop mid-write
            let write = throttled.write(&[0u8; 50]);
            tokio::time::timeout(Duration::from_millis(1), write)
                .await
                .unwrap_err();
        }
        assert_eq!(limiter.try_acquire(100), Acquire::Granted);
    }
}
