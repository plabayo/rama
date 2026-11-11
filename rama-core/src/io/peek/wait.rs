use std::{error::Error, fmt, future::pending, io, num::NonZeroUsize, pin::pin};

use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::{PeekEgressPredicate, PeekStopReason, PeekVerdict};
use crate::{
    bytes::{BufMut, Bytes},
    graceful::{Cause, WeakScope},
};

/// Default maximum number of egress bytes a peek inspects.
pub const DEFAULT_EGRESS_PEEK_MAX_SIZE: usize = 64;

/// Bytes reserved per egress read, so a large egress limit is not allocated up front.
const EGRESS_READ_CHUNK: usize = 64;

/// Event that cuts a peek short before it reached a verdict.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeekCutoff {
    /// The scope the input runs in was cancelled.
    Cancelled,
    /// The scope the input runs in was aborted; this always fails the peek.
    Aborted,
    /// The egress predicate rejected the bytes the server sent.
    EgressMismatch,
    /// The egress reached EOF or failed before its predicate settled.
    EgressClosed,
}

impl From<PeekCutoff> for PeekStopReason {
    fn from(cutoff: PeekCutoff) -> Self {
        match cutoff {
            PeekCutoff::Cancelled => Self::Cancelled,
            PeekCutoff::Aborted => Self::Aborted,
            PeekCutoff::EgressMismatch => Self::EgressMismatch,
            PeekCutoff::EgressClosed => Self::EgressClosed,
        }
    }
}

/// How far a peek got when a [`PeekCutoff`] happened.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeekProgress {
    /// Nothing was peeked yet.
    Idle,
    /// Some bytes were peeked, but not enough for a verdict.
    Partial,
}

impl PeekProgress {
    /// Progress of a peek that holds `peeked` bytes.
    #[must_use]
    pub const fn from_peeked(peeked: usize) -> Self {
        if peeked == 0 {
            Self::Idle
        } else {
            Self::Partial
        }
    }
}

/// Action a [`PeekPolicy`] selects for a [`PeekCutoff`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeekAction {
    /// Stop peeking and hand the input to the fallback.
    Fallback,
    /// Stop peeking and fail with [`PeekCutoffError`].
    Fail,
    /// Ignore the cutoff and keep waiting for input.
    ///
    /// The cutoff is evaluated again once the [`PeekProgress`] changes.
    Wait,
}

/// Decides what a [`PeekCutoff`] does, given the [`PeekProgress`] of the ingress peek.
///
/// Definitive verdicts (match, reject, EOF, size limits) are not affected,
/// and [`PeekCutoff::Aborted`] always fails.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PeekPolicy {
    cancelled_idle: PeekAction,
    cancelled_partial: PeekAction,
    egress_mismatch_idle: PeekAction,
    egress_mismatch_partial: PeekAction,
    egress_closed_idle: PeekAction,
    egress_closed_partial: PeekAction,
}

impl Default for PeekPolicy {
    fn default() -> Self {
        Self::FAIL_OPEN
    }
}

impl PeekPolicy {
    /// A cancelled scope and a closed egress invoke the fallback.
    ///
    /// An egress mismatch invokes the fallback for idle input and is ignored
    /// for partial input, as the client already started the protocol.
    /// This is the default.
    pub const FAIL_OPEN: Self = Self {
        cancelled_idle: PeekAction::Fallback,
        cancelled_partial: PeekAction::Fallback,
        egress_mismatch_idle: PeekAction::Fallback,
        egress_mismatch_partial: PeekAction::Wait,
        egress_closed_idle: PeekAction::Fallback,
        egress_closed_partial: PeekAction::Fallback,
    };

    /// A cancelled scope fails the peek.
    ///
    /// Egress cutoffs behave as in [`Self::FAIL_OPEN`].
    pub const FAIL_CLOSED: Self = Self {
        cancelled_idle: PeekAction::Fail,
        cancelled_partial: PeekAction::Fail,
        ..Self::FAIL_OPEN
    };

    /// The [`PeekAction`] for `cutoff` at `progress`.
    #[must_use]
    pub const fn action(&self, cutoff: PeekCutoff, progress: PeekProgress) -> PeekAction {
        match (cutoff, progress) {
            (PeekCutoff::Aborted, _) => PeekAction::Fail,
            (PeekCutoff::Cancelled, PeekProgress::Idle) => self.cancelled_idle,
            (PeekCutoff::Cancelled, PeekProgress::Partial) => self.cancelled_partial,
            (PeekCutoff::EgressMismatch, PeekProgress::Idle) => self.egress_mismatch_idle,
            (PeekCutoff::EgressMismatch, PeekProgress::Partial) => self.egress_mismatch_partial,
            (PeekCutoff::EgressClosed, PeekProgress::Idle) => self.egress_closed_idle,
            (PeekCutoff::EgressClosed, PeekProgress::Partial) => self.egress_closed_partial,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a cancelled scope before any byte was peeked.
        pub const fn cancelled_idle(mut self, action: PeekAction) -> Self {
            self.cancelled_idle = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a cancelled scope after a partial peek.
        pub const fn cancelled_partial(mut self, action: PeekAction) -> Self {
            self.cancelled_partial = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for an egress mismatch before any byte was peeked.
        pub const fn egress_mismatch_idle(mut self, action: PeekAction) -> Self {
            self.egress_mismatch_idle = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for an egress mismatch after a partial peek.
        pub const fn egress_mismatch_partial(mut self, action: PeekAction) -> Self {
            self.egress_mismatch_partial = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a closed egress before any byte was peeked.
        pub const fn egress_closed_idle(mut self, action: PeekAction) -> Self {
            self.egress_closed_idle = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a closed egress after a partial peek.
        pub const fn egress_closed_partial(mut self, action: PeekAction) -> Self {
            self.egress_closed_partial = action;
            self
        }
    }
}

/// Selects the [`PeekPolicy`] a peeker applies to one input.
///
/// Configured on a single peeker, so it affects only that peeker. It is
/// implemented for a static [`PeekPolicy`] and for `Fn(&Input) -> PeekPolicy`
/// closures; implement it for a type of your own to reuse one selection
/// across peekers that see different input types.
pub trait PeekPolicyProvider<Input>: Send + Sync + 'static {
    /// The [`PeekPolicy`] to apply while peeking `input`.
    fn peek_policy(&self, input: &Input) -> PeekPolicy;
}

impl<Input> PeekPolicyProvider<Input> for PeekPolicy {
    #[inline(always)]
    fn peek_policy(&self, _input: &Input) -> PeekPolicy {
        *self
    }
}

impl<Input, F> PeekPolicyProvider<Input> for F
where
    F: Fn(&Input) -> PeekPolicy + Send + Sync + 'static,
{
    #[inline(always)]
    fn peek_policy(&self, input: &Input) -> PeekPolicy {
        self(input)
    }
}

/// A [`PeekCutoff`] for which the [`PeekPolicy`] selected [`PeekAction::Fail`].
#[derive(Debug, Clone)]
pub struct PeekCutoffError {
    cutoff: PeekCutoff,
    cause: Option<Cause>,
}

impl PeekCutoffError {
    /// A peek failed by `cutoff`, for a peeker that waits without a [`PeekWaiter`].
    #[must_use]
    pub const fn new(cutoff: PeekCutoff, cause: Option<Cause>) -> Self {
        Self { cutoff, cause }
    }

    /// The cutoff that failed the peek.
    #[must_use]
    pub const fn cutoff(&self) -> PeekCutoff {
        self.cutoff
    }

    /// Why the scope was cancelled or aborted, for scope cutoffs.
    #[must_use]
    pub const fn cause(&self) -> Option<&Cause> {
        self.cause.as_ref()
    }
}

impl fmt::Display for PeekCutoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.cutoff {
            PeekCutoff::Cancelled => "protocol peek scope cancelled before a verdict",
            PeekCutoff::Aborted => "protocol peek scope aborted before a verdict",
            PeekCutoff::EgressMismatch => "protocol peek egress mismatch before a verdict",
            PeekCutoff::EgressClosed => "protocol peek egress closed before a verdict",
        })?;
        if let Some(cause) = &self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}

impl Error for PeekCutoffError {}

impl From<PeekCutoffError> for io::Error {
    fn from(error: PeekCutoffError) -> Self {
        let kind = match error.cutoff {
            PeekCutoff::Cancelled => io::ErrorKind::Interrupted,
            PeekCutoff::Aborted => io::ErrorKind::ConnectionAborted,
            PeekCutoff::EgressMismatch => io::ErrorKind::InvalidData,
            PeekCutoff::EgressClosed => io::ErrorKind::UnexpectedEof,
        };
        Self::new(kind, error)
    }
}

/// Outcome of a single [`PeekWaiter::read`].
#[derive(Debug)]
pub enum PeekRead {
    /// Bytes read into the buffer, `0` meaning EOF.
    Read(usize),
    /// Reading failed.
    Error(io::Error),
    /// A [`PeekCutoff`] stopped the peek, see [`PeekWaiter::check`].
    Cutoff(PeekCutoff),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum EgressState {
    Reading,
    /// Matched, or still consistent at the size limit: keep waiting for the client.
    Settled,
    Cutoff(PeekCutoff),
}

/// The egress side a [`PeekWaiter`] reads while a peek waits for ingress input.
pub struct PeekEgress<'a> {
    reader: &'a mut (dyn AsyncRead + Unpin + Send + 'a),
    predicate: &'a dyn PeekEgressPredicate,
    buffer: Vec<u8>,
    max_size: usize,
    state: EgressState,
}

impl fmt::Debug for PeekEgress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeekEgress")
            .field("peeked", &self.buffer.len())
            .field("max_size", &self.max_size)
            .field("state", &self.state)
            .finish()
    }
}

impl<'a> PeekEgress<'a> {
    /// Peek at most `max_size` bytes from `reader`, judged by `predicate`.
    ///
    /// Nothing is read when [`PeekEgressPredicate::peeks_egress`] is `false`.
    pub fn new(
        reader: &'a mut (dyn AsyncRead + Unpin + Send + 'a),
        predicate: &'a dyn PeekEgressPredicate,
        max_size: NonZeroUsize,
    ) -> Self {
        let state = if predicate.peeks_egress() {
            EgressState::Reading
        } else {
            EgressState::Settled
        };
        Self {
            reader,
            predicate,
            buffer: Vec::new(),
            max_size: max_size.get(),
            state,
        }
    }

    async fn step(&mut self) -> Option<PeekCutoff> {
        let want = self.max_size - self.buffer.len();
        self.buffer.reserve(want.min(EGRESS_READ_CHUNK));
        let read = self
            .reader
            .read_buf(&mut (&mut self.buffer).limit(want))
            .await;
        let cutoff = match read {
            Ok(0) => Some(PeekCutoff::EgressClosed),
            Err(err) => {
                tracing::debug!("I/O peek: egress read error: {err}");
                Some(PeekCutoff::EgressClosed)
            }
            Ok(_) => match self.predicate.egress(&self.buffer) {
                PeekVerdict::Match(()) => {
                    self.state = EgressState::Settled;
                    None
                }
                PeekVerdict::Reject => Some(PeekCutoff::EgressMismatch),
                PeekVerdict::NeedMore => {
                    if self.buffer.len() >= self.max_size {
                        self.state = EgressState::Settled;
                    }
                    None
                }
            },
        };
        if let Some(cutoff) = cutoff {
            tracing::trace!(
                "I/O peek: egress {cutoff:?} after {} bytes",
                self.buffer.len()
            );
            self.state = EgressState::Cutoff(cutoff);
        }
        cutoff
    }
}

/// Reads peek input, bounded by a scope and classifying the egress
/// as directed by a [`PeekPolicy`].
///
/// Share one waiter across the phases of a single peek. Input that is ready
/// always wins over a cutoff, and the egress is only read while the waiter
/// waits for ingress input.
#[derive(Debug, Default)]
pub struct PeekWaiter<'a> {
    scope: Option<WeakScope>,
    egress: Option<PeekEgress<'a>>,
    policy: PeekPolicy,
    cancelled_waived: Option<PeekProgress>,
    mismatch_waived: Option<PeekProgress>,
    closed_waived: Option<PeekProgress>,
    failed: Option<PeekCutoff>,
}

impl<'a> PeekWaiter<'a> {
    /// Create a waiter without scope or egress, using [`PeekPolicy::FAIL_OPEN`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`PeekPolicy`] applied to cutoffs.
        pub fn policy(mut self, policy: PeekPolicy) -> Self {
            self.policy = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the scope that can cut the peek short, usually the scope
        /// the input runs in, see [`scope_context`].
        ///
        /// [`scope_context`]: crate::graceful::scope_context
        pub fn scope(mut self, scope: Option<WeakScope>) -> Self {
            self.scope = scope;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the egress side read while the peek waits for ingress input.
        pub fn egress(mut self, egress: Option<PeekEgress<'a>>) -> Self {
            self.egress = egress;
            self
        }
    }

    /// The egress bytes read so far, to be replayed to the service that follows.
    #[must_use]
    pub fn egress_prefix(&self) -> &[u8] {
        self.egress
            .as_ref()
            .map(|egress| egress.buffer.as_slice())
            .unwrap_or_default()
    }

    /// Take the egress bytes read so far, ending the borrow of the egress.
    #[must_use]
    pub fn into_egress_prefix(self) -> Bytes {
        self.egress
            .map(|egress| Bytes::from(egress.buffer))
            .unwrap_or_default()
    }

    /// Read into `buf` unless a cutoff stops the peek first.
    ///
    /// `peeked` is the number of ingress bytes this peek holds so far.
    pub async fn read<R>(&mut self, reader: &mut R, buf: &mut [u8], peeked: usize) -> PeekRead
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        self.wait_for_read(reader.read(buf), peeked).await
    }

    pub(super) async fn read_buf<R, B>(
        &mut self,
        reader: &mut R,
        buf: &mut B,
        peeked: usize,
    ) -> PeekRead
    where
        R: AsyncRead + Unpin + ?Sized,
        B: BufMut + ?Sized,
    {
        self.wait_for_read(reader.read_buf(buf), peeked).await
    }

    async fn wait_for_read(
        &mut self,
        read: impl Future<Output = io::Result<usize>>,
        peeked: usize,
    ) -> PeekRead {
        let mut read = pin!(read);
        let progress = PeekProgress::from_peeked(peeked);
        loop {
            let Self {
                scope,
                egress,
                cancelled_waived,
                mismatch_waived,
                closed_waived,
                ..
            } = self;

            let egress_cutoff = egress
                .as_ref()
                .and_then(|egress| match egress.state {
                    EgressState::Cutoff(cutoff) => Some(cutoff),
                    EgressState::Reading | EgressState::Settled => None,
                })
                .filter(|cutoff| {
                    let waived = if *cutoff == PeekCutoff::EgressMismatch {
                        *mismatch_waived
                    } else {
                        *closed_waived
                    };
                    waived != Some(progress)
                });
            let egress_reading = egress
                .as_mut()
                .filter(|egress| egress.state == EgressState::Reading);
            let scope = scope.as_ref();
            let cancel_scope = scope.filter(|_| *cancelled_waived != Some(progress));

            let cutoff = tokio::select! {
                biased;
                result = &mut read => {
                    return match result {
                        Ok(n) => PeekRead::Read(n),
                        Err(err) => PeekRead::Error(err),
                    };
                }
                () = aborted(scope) => PeekCutoff::Aborted,
                cutoff = ready_cutoff(egress_cutoff) => cutoff,
                () = cancelled(cancel_scope) => PeekCutoff::Cancelled,
                cutoff = egress_step(egress_reading) => match cutoff {
                    Some(cutoff) => cutoff,
                    None => continue,
                },
            };

            let action = self.policy.action(cutoff, progress);
            tracing::debug!("I/O peek: {cutoff:?} at {progress:?} progress: {action:?}");
            match action {
                PeekAction::Wait => {
                    let waived = match cutoff {
                        PeekCutoff::Cancelled | PeekCutoff::Aborted => &mut self.cancelled_waived,
                        PeekCutoff::EgressMismatch => &mut self.mismatch_waived,
                        PeekCutoff::EgressClosed => &mut self.closed_waived,
                    };
                    *waived = Some(progress);
                }
                PeekAction::Fallback => return PeekRead::Cutoff(cutoff),
                PeekAction::Fail => {
                    self.failed = Some(cutoff);
                    return PeekRead::Cutoff(cutoff);
                }
            }
        }
    }

    /// Returns the error of a cutoff for which the policy selected [`PeekAction::Fail`].
    pub fn check<E>(&self) -> Result<(), E>
    where
        E: From<PeekCutoffError>,
    {
        let Some(cutoff) = self.failed else {
            return Ok(());
        };
        let cause = self.scope.as_ref().and_then(|scope| match cutoff {
            PeekCutoff::Cancelled => scope.cause(),
            PeekCutoff::Aborted => scope.abort_cause(),
            PeekCutoff::EgressMismatch | PeekCutoff::EgressClosed => None,
        });
        Err(PeekCutoffError { cutoff, cause }.into())
    }
}

async fn ready_cutoff(cutoff: Option<PeekCutoff>) -> PeekCutoff {
    match cutoff {
        Some(cutoff) => cutoff,
        None => pending().await,
    }
}

async fn aborted(scope: Option<&WeakScope>) {
    match scope {
        Some(scope) => scope.aborted().await,
        None => pending().await,
    }
}

async fn cancelled(scope: Option<&WeakScope>) {
    match scope {
        Some(scope) => scope.cancelled().await,
        None => pending().await,
    }
}

async fn egress_step(egress: Option<&mut PeekEgress<'_>>) -> Option<PeekCutoff> {
    match egress {
        Some(egress) => egress.step().await,
        None => pending().await,
    }
}
