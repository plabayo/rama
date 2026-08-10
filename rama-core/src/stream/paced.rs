use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;
use rama_utils::rate::{Acquire, Rate, RateLimiter};
use tokio::time::{Sleep, sleep_until};

use crate::bytes::{Bytes, BytesMut};
use crate::futures::{Sink, Stream};

pin_project! {
    /// A [`Sink`] combinator that paces the items sent through it
    /// against a token bucket: the go-to way to rate datagram flows.
    ///
    /// Wrap any framed sink — e.g. a `ConnectedUdpFramed`, a
    /// `UdpFramed` or a unix datagram codec — and every item's cost
    /// (its byte length, by default: see [`DatagramCost`]) is paid
    /// from the budget:
    ///
    /// - [`Sink::start_send`] never blocks an item: its cost is
    ///   recorded as *debt*;
    /// - [`Sink::poll_ready`] repays outstanding debt (waiting on the
    ///   bucket as needed) before accepting the next item.
    ///
    /// The long-run rate is exact, with at most one item of overshoot —
    /// the right semantics for pacing, as a datagram is atomic.
    /// Sending items larger than the burst capacity is fine: their debt
    /// is repaid in burst-sized chunks.
    ///
    /// [`Stream`] is passed through, so a duplex frame transport stays
    /// bridgeable (e.g. via [`StreamForwardService`]) after wrapping.
    ///
    /// To pace items-per-second rather than bytes-per-second, price
    /// every item at one unit via [`PacedSink::with_cost_fn`].
    ///
    /// [`StreamForwardService`]: crate::stream::StreamForwardService
    #[derive(Debug)]
    pub struct PacedSink<S, C = ()> {
        #[pin]
        sink: S,
        limiter: RateLimiter,
        debt: u64,
        sleep: Option<Pin<Box<Sleep>>>,
        sleeping: bool,
        cost: C,
    }
}

impl<S> PacedSink<S> {
    /// Create a new [`PacedSink`] pacing at the given [`Rate`], with a
    /// burst capacity of one period worth of units.
    pub fn new(sink: S, rate: Rate) -> Self {
        Self::with_limiter(sink, RateLimiter::from_rate(rate))
    }

    /// Create a new [`PacedSink`] pacing against a caller-provided
    /// [`RateLimiter`]: clones of the handle share one aggregate
    /// budget (e.g. an egress cap across many flows).
    pub fn with_limiter(sink: S, limiter: RateLimiter) -> Self {
        Self {
            sink,
            limiter,
            debt: 0,
            sleep: None,
            sleeping: false,
            cost: (),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the burst capacity (default: one period worth of units).
        ///
        /// This rebuilds the sink's own [`RateLimiter`]: any previously
        /// shared budget handle is disconnected.
        pub fn burst(mut self, burst: u64) -> Self {
            self.limiter = RateLimiter::new(self.limiter.rate(), burst);
            self
        }
    }
}

impl<S, C> PacedSink<S, C> {
    /// Price items with the given function instead of
    /// their [`DatagramCost`].
    ///
    /// E.g. `|_| 1` paces items-per-second rather than bytes-per-second.
    pub fn with_cost_fn<F>(self, cost_fn: F) -> PacedSink<S, CostFn<F>> {
        PacedSink {
            sink: self.sink,
            limiter: self.limiter,
            debt: self.debt,
            sleep: self.sleep,
            sleeping: self.sleeping,
            cost: CostFn(cost_fn),
        }
    }

    /// The [`RateLimiter`] enforcing this sink's budget
    /// (clone it to share the budget elsewhere).
    #[must_use]
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Consume this combinator, returning the underlying sink.
    pub fn into_inner(self) -> S {
        self.sink
    }

    /// Get a reference to the underlying sink.
    pub fn get_ref(&self) -> &S {
        &self.sink
    }
}

/// Prices the items sent through a [`PacedSink`].
///
/// The default coster `()` uses the item's own [`DatagramCost`];
/// [`CostFn`] uses a closure instead.
pub trait ItemCost<I> {
    /// The cost of the given item, in rate units.
    fn cost_of(&self, item: &I) -> u64;
}

impl<I: DatagramCost> ItemCost<I> for () {
    fn cost_of(&self, item: &I) -> u64 {
        item.cost()
    }
}

/// An [`ItemCost`] pricing items with a closure,
/// see [`PacedSink::with_cost_fn`].
pub struct CostFn<F>(F);

impl<F> fmt::Debug for CostFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CostFn").finish()
    }
}

impl<I, F: Fn(&I) -> u64> ItemCost<I> for CostFn<F> {
    fn cost_of(&self, item: &I) -> u64 {
        (self.0)(item)
    }
}

/// The intrinsic cost of a datagram-ish item: its byte length.
///
/// This is what a [`PacedSink`] charges by default. The tuple impl
/// covers address-carrying sinks such as `UdpFramed`
/// (`(item, SocketAddr)`).
pub trait DatagramCost {
    /// The cost of this item, in rate units.
    fn cost(&self) -> u64;
}

impl DatagramCost for Bytes {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for BytesMut {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for Vec<u8> {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for Box<[u8]> {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for &[u8] {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for String {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl DatagramCost for &str {
    fn cost(&self) -> u64 {
        self.len() as u64
    }
}

impl<T: DatagramCost, A> DatagramCost for (T, A) {
    fn cost(&self) -> u64 {
        self.0.cost()
    }
}

impl<S, I, C> Sink<I> for PacedSink<S, C>
where
    S: Sink<I>,
    C: ItemCost<I>,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        while *this.debt > 0 {
            let want = (*this.debt).min(this.limiter.burst());
            match this.limiter.try_acquire(want) {
                Acquire::Granted => *this.debt -= want,
                Acquire::RetryAt(at) => {
                    let deadline = this.limiter.deadline(at);
                    let sleep = match this.sleep.as_mut() {
                        Some(sleep) => sleep,
                        None => this.sleep.insert(Box::pin(sleep_until(deadline))),
                    };
                    if !*this.sleeping {
                        sleep.as_mut().reset(deadline);
                        *this.sleeping = true;
                    }
                    ready!(sleep.as_mut().poll(cx));
                    *this.sleeping = false;
                }
                Acquire::Never => {
                    // defence-in-depth: chunks are clamped to the burst
                    // capacity, so this cannot fire; drop the debt
                    // rather than stall the sink forever
                    debug_assert!(false, "burst-clamped repayment reported Acquire::Never");
                    *this.debt = 0;
                }
            }
        }
        this.sink.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        let this = self.project();
        // charge only once the item is actually accepted, so a failed
        // send does not leave phantom debt that over-throttles the next item
        let cost = this.cost.cost_of(&item);
        this.sink.start_send(item)?;
        *this.debt = this.debt.saturating_add(cost);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close(cx)
    }
}

impl<S, C> Stream for PacedSink<S, C>
where
    S: Stream,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().sink.poll_next(cx)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.sink.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::futures::SinkExt;
    use std::convert::Infallible;
    use std::time::Duration;
    use tokio::time::Instant;

    #[derive(Debug, Default)]
    struct VecSink {
        items: Vec<Bytes>,
    }

    impl Sink<Bytes> for VecSink {
        type Error = Infallible;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.get_mut().items.push(item);
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn paces_by_byte_cost() {
        let mut sink = PacedSink::new(VecSink::default(), Rate::per_sec(1_000));
        let item = || Bytes::from_static(&[0u8; 500]);

        let start = Instant::now();
        // burst 1000: two items pass without any debt to repay ...
        sink.send(item()).await.unwrap();
        sink.send(item()).await.unwrap();
        sink.send(item()).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        // ... the fourth has to wait for the third one's debt
        sink.send(item()).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(500));

        sink.send(item()).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(1_000));

        assert_eq!(sink.get_ref().items.len(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn paces_items_with_cost_fn() {
        // 2 datagrams per second, independent of their size
        let mut sink =
            PacedSink::new(VecSink::default(), Rate::per_sec(2)).with_cost_fn(|_: &Bytes| 1);

        let start = Instant::now();
        for _ in 0..3 {
            sink.send(Bytes::from_static(b"whatever")).await.unwrap();
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        sink.send(Bytes::from_static(b"...")).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(500));

        sink.send(Bytes::from_static(b"...")).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(1_000));
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_items_repay_in_chunks() {
        let mut sink = PacedSink::new(VecSink::default(), Rate::per_sec(100)).with_burst(100);

        let start = Instant::now();
        // 250 > burst: sent right away, debt repaid in chunks after
        sink.send(Bytes::from(vec![0u8; 250])).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        // 100 (burst) + 100 @+1s + 50 @+1.5s
        sink.send(Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(1_500));
    }

    #[tokio::test(start_paused = true)]
    async fn shared_limiter_is_aggregate() {
        let limiter = RateLimiter::from_rate(Rate::per_sec(1_000));
        let mut sink_a = PacedSink::with_limiter(VecSink::default(), limiter.clone());
        let mut sink_b = PacedSink::with_limiter(VecSink::default(), limiter);

        let start = Instant::now();
        sink_a.send(Bytes::from(vec![0u8; 800])).await.unwrap();
        sink_b.send(Bytes::from(vec![0u8; 800])).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        // a's 800 debt fits the shared 1000 burst ...
        sink_a.send(Bytes::from(vec![0u8; 100])).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        // ... so b's 800 debt has only 200 left and waits for 600 more
        sink_b.send(Bytes::from(vec![0u8; 100])).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(600));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_start_send_charges_no_debt() {
        // rejects its first item, accepts the rest
        struct FlakySink {
            reject_next: bool,
            items: Vec<Bytes>,
        }

        impl Sink<Bytes> for FlakySink {
            type Error = &'static str;

            fn poll_ready(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
                let this = self.get_mut();
                if this.reject_next {
                    this.reject_next = false;
                    return Err("rejected");
                }
                this.items.push(item);
                Ok(())
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut sink = PacedSink::new(
            FlakySink {
                reject_next: true,
                items: Vec::new(),
            },
            Rate::per_sec(100),
        )
        .with_burst(100);

        let start = Instant::now();
        // a big item is rejected: its cost must not be charged as debt
        let err = sink.send(Bytes::from(vec![0u8; 1_000])).await.unwrap_err();
        assert_eq!(err, "rejected");

        // a within-burst item now sends immediately; a phantom 1_000-unit
        // debt from the reject would have forced a ~9s wait here.
        sink.send(Bytes::from(vec![0u8; 50])).await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(sink.get_ref().items.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_is_passed_through() {
        use crate::futures::StreamExt;

        let inner = crate::futures::stream::iter([1u8, 2, 3]);
        // pin on the stack: a pure Stream wrapped in PacedSink
        let paced = PacedSink::new(inner, Rate::per_sec(1));
        let items: Vec<_> = paced.collect().await;
        assert_eq!(items, [1, 2, 3]);
    }
}
