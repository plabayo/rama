//! Pull-driven capture: the first attempt and the retry coordinator take turns
//! driving the same source, writer, and partially written frame.
use super::{
    RetryBody, SourceBody,
    storage::{ReplaySource, ReplayWriter},
};
use crate::{
    HeaderMap, StreamingBody,
    body::{Frame, SizeHint},
};
use parking_lot::Mutex;
use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::future::{BoxFuture, FutureExt as _, Shared},
};
use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, Waker, ready},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

type SharedError = Arc<dyn std::error::Error + Send + Sync>;
type Resolution = Result<Option<Arc<dyn ReplaySource>>, SharedError>;
type ReplayFuture = Shared<BoxFuture<'static, Resolution>>;

struct Resolver {
    shared: Arc<Mutex<SharedStream>>,
    future: OnceLock<ReplayFuture>,
}

impl Resolver {
    fn reader(&self) -> ReplayFuture {
        self.future
            .get_or_init(|| replay_future(self.shared.clone()))
            .clone()
    }
}

#[derive(Clone)]
pub(super) struct PendingReplay {
    pub(super) hint: SizeHint,
    resolver: Arc<Resolver>,
    reader: Option<ReplayFuture>,
}

impl fmt::Debug for PendingReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingReplay")
            .field("hint", &self.hint)
            .finish_non_exhaustive()
    }
}

impl PendingReplay {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Resolution> {
        let reader = self.reader.get_or_insert_with(|| self.resolver.reader());
        Pin::new(reader).poll(cx)
    }
}

pub(super) struct Capture {
    pending: PendingReplay,
}

pub(super) fn capture(
    body: SourceBody,
    hint: SizeHint,
    writer: Box<dyn ReplayWriter>,
    max_bytes: u64,
    timeout: Duration,
) -> (RetryBody, Capture) {
    let shared = Arc::new(Mutex::new(SharedStream {
        tee: Some(Tee {
            body,
            hint,
            writer: Some(writer),
            frame: None,
            seal: None,
            deadline: Some(Deadline::new(timeout)),
            trailers: None,
            seal_budget: None,
            eof: false,
            bytes_left: max_bytes,
        }),
        owner: Owner::Attempt,
        first_reader_alive: true,
        attempt_finished: false,
        takeover_waiter: None,
        waiter: None,
    }));
    let pending = PendingReplay {
        hint,
        resolver: Arc::new(Resolver {
            shared: shared.clone(),
            future: OnceLock::new(),
        }),
        reader: None,
    };
    (RetryBody::forwarding(Forward(shared)), Capture { pending })
}

fn replay_future(coordinator: Arc<Mutex<SharedStream>>) -> ReplayFuture {
    poll_fn(move |cx| {
        let mut state = coordinator.lock();
        match state.owner {
            Owner::Released => return Poll::Ready(Ok(None)),
            Owner::Attempt if !state.attempt_finished => {
                state.takeover_waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Owner::Attempt => state.owner = Owner::Coordinator,
            Owner::Coordinator => (),
        }
        state.waiter = Some(cx.waker().clone());
        let Some(tee) = &mut state.tee else {
            return Poll::Ready(Ok(None));
        };
        let result = ready!(tee.poll_replay(cx));
        state.tee = None;
        state.waiter = None;
        Poll::Ready(result)
    })
    .boxed()
    .shared()
}

impl Capture {
    pub(super) fn allow_replay_after_attempt(&self) -> bool {
        let waiter = {
            let mut state = self.pending.resolver.shared.lock();
            let Some(tee) = &state.tee else {
                return false;
            };
            // The result can contain the live reader, even behind another body
            // adapter. Leave its remaining frames with it, including pending writes.
            if (state.first_reader_alive && !tee.eof) || !tee.possible() {
                return false;
            }
            state.attempt_finished = true;
            state.takeover_waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        true
    }

    pub(super) async fn finish(&self) -> Result<bool, BoxError> {
        self.pending
            .resolver
            .reader()
            .await
            .map(|source| source.is_some())
            .map_err(|error| Box::new(error) as BoxError)
    }

    pub(super) fn pending_body(&self) -> RetryBody {
        RetryBody::pending(self.pending.clone())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let mut state = self.pending.resolver.shared.lock();
        if matches!(state.owner, Owner::Coordinator) || !state.first_reader_alive {
            state.tee = None;
        } else if let Some(tee) = &mut state.tee {
            // E.g. a proxy returned a response body which streams the original
            // request. Leave it the source and any unforwarded frame.
            tee.disable();
        }
        state.owner = Owner::Released;
        let waiting_policy = state.takeover_waiter.take();
        let reader = state.waiter.take();
        drop(state);
        if let Some(waiter) = waiting_policy {
            waiter.wake();
        }
        if let Some(waker) = reader {
            waker.wake();
        }
    }
}

enum Owner {
    Attempt,
    Coordinator,
    Released,
}

struct SharedStream {
    tee: Option<Tee>,
    owner: Owner,
    first_reader_alive: bool,
    attempt_finished: bool,
    takeover_waiter: Option<Waker>,
    waiter: Option<Waker>,
}

pub(super) struct Forward(Arc<Mutex<SharedStream>>);

impl Drop for Forward {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.first_reader_alive = false;
        if matches!(state.owner, Owner::Released) {
            state.tee = None;
        }
        if !matches!(state.owner, Owner::Coordinator) {
            state.waiter = None;
        }
    }
}

impl fmt::Debug for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Forward")
    }
}

impl SharedStream {
    fn forwarding(&self) -> Option<&Tee> {
        if matches!(self.owner, Owner::Coordinator) {
            None
        } else {
            self.tee.as_ref()
        }
    }
}

impl StreamingBody for Forward {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut state = self.0.lock();
        if matches!(state.owner, Owner::Coordinator) {
            return Poll::Ready(None);
        }
        let Some(tee) = &mut state.tee else {
            return Poll::Ready(None);
        };
        let frame = tee.poll_frame(cx, false);
        state.waiter = frame.is_pending().then(|| cx.waker().clone());
        frame
    }

    fn size_hint(&self) -> SizeHint {
        self.0
            .lock()
            .forwarding()
            .map_or(SizeHint::with_exact(0), |tee| tee.hint)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .forwarding()
            .is_none_or(|tee| tee.eof && tee.seal.is_none())
    }
}

/// Ready sources and synchronous memory writes only need the timestamp. Install
/// a runtime timer when a pending source or write actually needs a wakeup.
struct Deadline {
    at: Instant,
    timer: Option<Pin<Box<Sleep>>>,
}

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self {
            at: rama_utils::time::deadline_after(Instant::now(), timeout),
            timer: None,
        }
    }

    fn elapsed(&self) -> bool {
        Instant::now() >= self.at
    }

    fn arm(&mut self, cx: &mut Context<'_>) {
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.at)));
        if timer.as_mut().poll(cx).is_ready() {
            // The deadline elapsed between the caller's check and registration.
            cx.waker().wake_by_ref();
        }
    }
}

struct Tee {
    body: SourceBody,
    hint: SizeHint,
    writer: Option<Box<dyn ReplayWriter>>,
    // The complete original frame stays here until delivered. In particular,
    // cancellation of a partial filesystem write never truncates forwarding.
    frame: Option<Frame<Bytes>>,
    seal: Option<BoxFuture<'static, Result<Arc<dyn ReplaySource>, BoxError>>>,
    deadline: Option<Deadline>,
    trailers: Option<HeaderMap>,
    seal_budget: Option<Duration>,
    eof: bool,
    bytes_left: u64,
}

impl Tee {
    fn possible(&self) -> bool {
        self.seal_budget.is_some() || self.deadline.as_ref().is_some_and(|d| !d.elapsed())
    }

    fn disable(&mut self) {
        self.writer = None;
        self.seal = None;
        self.deadline = None;
        self.seal_budget = None;
        self.trailers = None;
    }

    fn reached_eof(&mut self) {
        self.eof = true;
        // The upload is complete; time waiting for a service response or
        // retry backoff must not consume the remaining storage I/O budget.
        self.seal_budget = self
            .deadline
            .as_ref()
            .map(|d| d.at.saturating_duration_since(Instant::now()));
    }

    fn poll_replay(&mut self, cx: &mut Context<'_>) -> Poll<Resolution> {
        loop {
            if self.deadline.is_none() {
                return Poll::Ready(Ok(None));
            }
            if let Some(budget) = self.seal_budget.take() {
                let (Some(writer), Some(timer)) = (self.writer.take(), &mut self.deadline) else {
                    return Poll::Ready(Ok(None));
                };
                *timer = Deadline::new(budget);
                self.seal = Some(writer.finish(self.trailers.take()));
            }
            if let Some(seal) = &mut self.seal {
                let Some(clock) = &mut self.deadline else {
                    return Poll::Ready(Ok(None));
                };
                if clock.elapsed() {
                    return Poll::Ready(Ok(None));
                }
                return match seal.as_mut().poll(cx) {
                    Poll::Ready(source) => Poll::Ready(Ok(source.ok())),
                    Poll::Pending => {
                        clock.arm(cx);
                        Poll::Pending
                    }
                };
            }
            // A source can always be ready; yield to cancellation and deadlines.
            ready!(tokio::task::coop::poll_proceed(cx)).made_progress();
            if let Some(Err(error)) = ready!(self.poll_frame(cx, true)) {
                return Poll::Ready(Err(error.into()));
            }
        }
    }

    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        draining: bool,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let frame = self.poll_next(cx, draining);
        if frame.is_pending()
            && let Some(clock) = &mut self.deadline
        {
            clock.arm(cx);
        }
        frame
    }

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
        draining: bool,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.seal_budget.is_none() && self.deadline.as_ref().is_some_and(Deadline::elapsed) {
            self.disable();
        }
        if self.eof || (draining && self.deadline.is_none()) {
            return Poll::Ready(None);
        }

        let frame = match self.frame.take() {
            Some(frame) => frame,
            None => match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
                Some(Ok(frame)) => frame,
                Some(Err(error)) => {
                    self.disable();
                    self.eof = true;
                    self.hint.set_exact(0);
                    return Poll::Ready(Some(Err(error)));
                }
                None => {
                    self.reached_eof();
                    self.hint.set_exact(0);
                    return Poll::Ready(None);
                }
            },
        };
        if self.poll_store(cx, &frame).is_pending() {
            self.frame = Some(frame);
            return Poll::Pending;
        }
        if let Some(data) = frame.data_ref() {
            self.hint.consume(data.len() as u64);
        }
        if self.body.is_end_stream() {
            self.reached_eof();
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn poll_store(&mut self, cx: &mut Context<'_>, frame: &Frame<Bytes>) -> Poll<()> {
        let Some(writer) = &mut self.writer else {
            return Poll::Ready(());
        };
        if self.trailers.is_some() {
            // Replay cursors represent data followed by a single trailer map.
            // Forward a nonconforming source intact on the first attempt.
            self.disable();
        } else if let Some(data) = frame.data_ref() {
            let Some(remaining) = self.bytes_left.checked_sub(data.len() as u64) else {
                self.disable();
                return Poll::Ready(());
            };
            match ready!(writer.poll_append(cx, data)) {
                Ok(()) => self.bytes_left = remaining,
                Err(_) => self.disable(),
            }
        } else if let Some(trailers) = frame.trailers_ref() {
            self.trailers = Some(trailers.clone());
        }
        Poll::Ready(())
    }
}
