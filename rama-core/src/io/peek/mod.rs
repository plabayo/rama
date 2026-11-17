//! Protocol peeking: inspect the first bytes of an input without consuming them.
//!
//! A peeker classifies the first bytes from either side of a bridge: the
//! ingress (client) through its predicate and, on a [`BridgeIo`], the egress
//! (server) through a [`PeekEgressPredicate`]. Peekers wait for input through
//! a [`PeekWaiter`], which egress verdicts and the scope the input runs in
//! can cut short as directed by a [`PeekPolicy`]. No verdict depends on a
//! timeout: a waiting peek ends when its scope is cancelled or aborted.
//!
//! [`BridgeIo`]: super::BridgeIo

use core::num::NonZeroUsize;

use rama_utils::{macros::nonzero, octets::kib};
use tokio::io::AsyncRead;

use super::{PeekIoProvider, PrefixedIo, ReplayReader};
use crate::{
    Service,
    bytes::{BufMut as _, Bytes},
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    graceful::{WeakScope, scope_context},
    service::{RejectError, RejectService},
};

mod egress;
#[doc(inline)]
pub use egress::{ClientFirstEgress, NoEgressPeek, PeekEgressPredicate, PeekEgressPrefix};

mod wait;
#[doc(inline)]
pub use wait::{
    DEFAULT_EGRESS_PEEK_MAX_SIZE, PeekAction, PeekCutoff, PeekCutoffError, PeekEgress, PeekPolicy,
    PeekPolicyProvider, PeekProgress, PeekRead, PeekWaiter,
};

/// Default maximum number of bytes inspected by [`PeekRouter`].
pub const DEFAULT_PEEK_MAX_SIZE: usize = kib(8);

/// Default number of bytes requested per read by [`PeekRouter`].
pub const DEFAULT_PEEK_READ_CHUNK_SIZE: usize = 64;

/// Reason a protocol peek operation stopped.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PeekStopReason {
    /// The predicate selected the protocol.
    Match,
    /// The predicate definitively rejected the protocol.
    Rejected,
    /// The input reached EOF before a definitive verdict.
    Eof,
    /// Reading the input failed before a definitive verdict.
    ReadError,
    /// The scope the input runs in was cancelled before a definitive verdict.
    Cancelled,
    /// The scope the input runs in was aborted before a definitive verdict.
    Aborted,
    /// The egress predicate rejected what the server sent.
    EgressMismatch,
    /// The egress closed before its predicate settled.
    EgressClosed,
    /// The maximum peek size was reached before a definitive verdict.
    MaxPeekSizeReached,
}

impl PeekStopReason {
    /// Returns `true` when a [`PeekCutoff`] stopped the peek.
    #[must_use]
    pub const fn is_cutoff(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Aborted | Self::EgressMismatch | Self::EgressClosed
        )
    }
}

/// Options of the functional peekers that read both sides of a bridge.
#[derive(Debug, Clone)]
pub struct PeekOptions {
    policy: PeekPolicy,
    scope: Option<WeakScope>,
    max_egress_peek_size: NonZeroUsize,
}

impl Default for PeekOptions {
    fn default() -> Self {
        Self {
            policy: PeekPolicy::FAIL_OPEN,
            scope: None,
            max_egress_peek_size: DEFAULT_EGRESS_PEEK_MAX_SIZE,
        }
    }
}

impl PeekOptions {
    /// Options using [`PeekPolicy::FAIL_OPEN`], no scope and the default egress limit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Options for peeking `input`: the [`PeekPolicy`] `policy` selects for it,
    /// the scope it runs in, see [`scope_context`], and `max_egress_peek_size`.
    #[must_use]
    pub fn from_input<Input, Pol>(
        input: &Input,
        policy: &Pol,
        max_egress_peek_size: NonZeroUsize,
    ) -> Self
    where
        Input: ExtensionsRef,
        Pol: PeekPolicyProvider<Input> + ?Sized,
    {
        Self {
            policy: policy.peek_policy(input),
            scope: scope_context(input.extensions()),
            max_egress_peek_size,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`PeekPolicy`] applied to cutoffs.
        pub fn policy(mut self, policy: PeekPolicy) -> Self {
            self.policy = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the scope that can cut the peek short, usually the scope the
        /// input runs in, see [`scope_context`].
        pub fn scope(mut self, scope: Option<WeakScope>) -> Self {
            self.scope = scope;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the byte limit for peeking the egress.
        pub fn max_egress_peek_size(mut self, max_egress_peek_size: NonZeroUsize) -> Self {
            self.max_egress_peek_size = max_egress_peek_size;
            self
        }
    }

    /// A [`PeekWaiter`] reading `egress`, if any, judged by `predicate`.
    ///
    /// Without an egress a single stream is never read beyond its ingress.
    pub fn waiter<'a, E>(
        &self,
        egress: Option<&'a mut E>,
        predicate: &'a dyn PeekEgressPredicate,
    ) -> PeekWaiter<'a>
    where
        E: AsyncRead + Unpin + Send + 'a,
    {
        PeekWaiter::new()
            .with_policy(self.policy)
            .maybe_with_scope(self.scope.clone())
            .maybe_with_egress(
                egress.map(|egress| PeekEgress::new(egress, predicate, self.max_egress_peek_size)),
            )
    }
}

/// The input of a [`PeekIoProvider`] once peeked: the ingress mapped to `PeekedIo`
/// and the egress, if any, replaying the egress bytes the peek consumed.
pub type PeekMapped<Input, PeekedIo> = <Input as PeekIoProvider>::Mapped<
    PeekedIo,
    PeekPrefixedIo<<Input as PeekIoProvider>::PeekEgressIo>,
>;

/// Map a peeked `input` so its ingress first replays `ingress_prefix` and its
/// egress, if any, first replays `egress_prefix`, see [`PeekWaiter::finish`].
pub fn replay_peeked<Input, P>(
    input: Input,
    ingress_prefix: P,
    egress_prefix: Bytes,
) -> PeekMapped<Input, PrefixedIo<P, Input::PeekIo>>
where
    Input: PeekIoProvider,
    P: AsyncRead + Send + 'static,
{
    input.map_peek_io(
        |io| PrefixedIo::new(ingress_prefix, io),
        |io| PrefixedIo::new(ReplayReader::new(egress_prefix), io),
    )
}

/// A generic [`Service`] router driven by a fail-fast [`PeekVerdict`] predicate.
///
/// Peeking uses a grow-on-demand heap buffer and replays all read bytes. Any
/// outcome other than [`PeekVerdict::Match`] dispatches to the fallback, except
/// a cutoff for which the [`PeekPolicy`] selects [`PeekAction::Fail`].
///
/// On a [`BridgeIo`] the egress is judged by the egress predicate, see
/// [`PeekRouter::with_egress_predicate`]; by default it is not read.
///
/// [`BridgeIo`]: super::BridgeIo
#[derive(Debug, Clone)]
pub struct PeekRouter<P, T, F = RejectService<(), RejectError>, Pol = PeekPolicy, E = NoEgressPeek>
{
    predicate: P,
    egress_predicate: E,
    acceptor: T,
    fallback: F,
    peek_policy: Pol,
    max_peek_size: usize,
    max_egress_peek_size: NonZeroUsize,
    peek_read_chunk_size: NonZeroUsize,
}

impl<P, T> PeekRouter<P, T, RejectService<(), RejectError>> {
    /// Create a router that rejects non-matching input by default.
    #[must_use]
    pub fn new(predicate: P, acceptor: T) -> Self {
        Self {
            predicate,
            egress_predicate: NoEgressPeek,
            acceptor,
            fallback: RejectService::default(),
            peek_policy: PeekPolicy::FAIL_OPEN,
            max_peek_size: DEFAULT_PEEK_MAX_SIZE,
            max_egress_peek_size: DEFAULT_EGRESS_PEEK_MAX_SIZE,
            peek_read_chunk_size: nonzero!(DEFAULT_PEEK_READ_CHUNK_SIZE),
        }
    }
}

impl<P, T, Pol, E> PeekRouter<P, T, RejectService<(), RejectError>, Pol, E> {
    /// Attach a fallback [`Service`].
    #[must_use]
    pub fn with_fallback<F>(self, fallback: F) -> PeekRouter<P, T, F, Pol, E> {
        PeekRouter {
            predicate: self.predicate,
            egress_predicate: self.egress_predicate,
            acceptor: self.acceptor,
            fallback,
            peek_policy: self.peek_policy,
            max_peek_size: self.max_peek_size,
            max_egress_peek_size: self.max_egress_peek_size,
            peek_read_chunk_size: self.peek_read_chunk_size,
        }
    }
}

impl<P, T, F, Pol, E> PeekRouter<P, T, F, Pol, E> {
    /// Set how a [`PeekCutoff`] is handled, using a static [`PeekPolicy`]
    /// or a [`PeekPolicyProvider`] that selects one per input.
    ///
    /// Defaults to [`PeekPolicy::FAIL_OPEN`]. Definitive predicate
    /// rejections invoke the fallback under any policy.
    #[must_use]
    pub fn with_peek_policy<Pol2>(self, peek_policy: Pol2) -> PeekRouter<P, T, F, Pol2, E> {
        PeekRouter {
            predicate: self.predicate,
            egress_predicate: self.egress_predicate,
            acceptor: self.acceptor,
            fallback: self.fallback,
            peek_policy,
            max_peek_size: self.max_peek_size,
            max_egress_peek_size: self.max_egress_peek_size,
            peek_read_chunk_size: self.peek_read_chunk_size,
        }
    }

    /// Judge the egress of a [`BridgeIo`] with `egress_predicate`,
    /// e.g. a [`PeekEgressPrefix`].
    ///
    /// [`BridgeIo`]: super::BridgeIo
    #[must_use]
    pub fn with_egress_predicate<E2>(self, egress_predicate: E2) -> PeekRouter<P, T, F, Pol, E2> {
        PeekRouter {
            predicate: self.predicate,
            egress_predicate,
            acceptor: self.acceptor,
            fallback: self.fallback,
            peek_policy: self.peek_policy,
            max_peek_size: self.max_peek_size,
            max_egress_peek_size: self.max_egress_peek_size,
            peek_read_chunk_size: self.peek_read_chunk_size,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the byte limit for peeking; this does not impose a time limit.
        pub fn max_peek_size(mut self, max_peek_size: NonZeroUsize) -> Self {
            self.max_peek_size = max_peek_size.get();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the byte limit for peeking the egress,
        /// defaults to [`DEFAULT_EGRESS_PEEK_MAX_SIZE`].
        pub fn max_egress_peek_size(mut self, max_egress_peek_size: NonZeroUsize) -> Self {
            self.max_egress_peek_size = max_egress_peek_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of bytes requested per read.
        pub fn peek_read_chunk_size(mut self, peek_read_chunk_size: NonZeroUsize) -> Self {
            self.peek_read_chunk_size = peek_read_chunk_size;
            self
        }
    }
}

impl<T> PeekRouter<(), T> {
    /// Create a router matching a fixed prefix.
    ///
    /// Peeking is limited to the prefix length unless overridden.
    ///
    /// # Panics
    ///
    /// Panics when `prefix` is empty.
    #[must_use]
    pub fn from_prefix(
        prefix: &'static [u8],
        acceptor: T,
    ) -> PeekRouter<impl Clone + Fn(&[u8]) -> PeekVerdict<()>, T> {
        assert!(!prefix.is_empty(), "PeekRouter prefix must not be empty");
        let mut router = PeekRouter::new(
            move |buffer: &[u8]| prefix_peek_verdict(buffer, prefix),
            acceptor,
        );
        router.max_peek_size = prefix.len();
        router
    }
}

impl<PeekableInput, Output, P, T, F, Pol, E> Service<PeekableInput> for PeekRouter<P, T, F, Pol, E>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin, PeekEgressIo: Unpin> + ExtensionsRef,
    Output: Send + 'static,
    P: Fn(&[u8]) -> PeekVerdict<()> + Send + Sync + 'static,
    E: PeekEgressPredicate + 'static,
    Pol: PeekPolicyProvider<PeekableInput>,
    T: Service<
            PeekMapped<PeekableInput, PeekPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekMapped<PeekableInput, PeekPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, mut input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let options = PeekOptions::from_input(&input, &self.peek_policy, self.max_egress_peek_size);
        let (ingress, egress) = input.peek_ios_mut();
        let mut waiter = options.waiter(egress, &self.egress_predicate);
        let mut peek_buffer = Vec::new();
        let output = peek_input_until_verdict_growing_with_output(
            ingress,
            &mut peek_buffer,
            self.max_peek_size,
            self.peek_read_chunk_size,
            &mut waiter,
            &self.predicate,
        )
        .await;
        let egress_prefix = waiter.finish::<BoxError>()?;
        let input = replay_peeked(
            input,
            ReplayReader::new(Bytes::from(peek_buffer)),
            egress_prefix,
        );

        if output.data.is_some() {
            self.acceptor.serve(input).await.into_box_error()
        } else {
            self.fallback.serve(input).await.into_box_error()
        }
    }
}

pub(crate) fn prefix_peek_verdict(buffer: &[u8], prefix: &[u8]) -> PeekVerdict<()> {
    let compared_len = buffer.len().min(prefix.len());
    if buffer[..compared_len] != prefix[..compared_len] {
        PeekVerdict::Reject
    } else if buffer.len() >= prefix.len() {
        PeekVerdict::Match(())
    } else {
        PeekVerdict::NeedMore
    }
}

/// [`PrefixedIo`] alias used by [`PeekRouter`].
pub type PeekPrefixedIo<S> = PrefixedIo<ReplayReader, S>;

/// Result of a [`peek_input_until_verdict`] call.
///
/// `peek_size` reports how many bytes were copied into the caller-provided
/// buffer before peeking stopped. `data` is only populated when the predicate
/// matched those bytes. [`PeekOutput::stop_reason`] distinguishes an
/// inconclusive cutoff from a definitive [`PeekVerdict::Reject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeekOutput<D> {
    pub data: Option<D>,
    pub peek_size: usize,
    pub stop_reason: PeekStopReason,
}

/// Verdict returned by a fail-fast peek predicate, used with
/// [`peek_input_until_verdict`] and [`peek_input_until_verdict_growing`].
///
/// Besides matching or asking for more, a predicate can `Reject` bytes that
/// can never match, so a peer that sends a short non-matching prefix and then
/// goes quiet does not keep the peek blocked on a read for a byte that never
/// arrives (e.g. a 5th TLS-record byte after 4 bytes of some other protocol):
/// dispatch falls through to the next protocol/fallback without blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekVerdict<O> {
    /// The peeked bytes match; stop and surface `Some(data)`.
    Match(O),
    /// The peeked bytes can never match; stop now, surface no data, and do not
    /// issue another read.
    Reject,
    /// Not enough bytes to decide yet; keep reading (subject to the waiter,
    /// EOF, and the buffer size).
    NeedMore,
}

/// Read into the fixed `buffer` until `predicate` decides, peeking stops, or
/// the `waiter` cuts the peek short.
///
/// The first `offset` bytes of `buffer` are an earlier peek (clamped to its
/// length); the predicate classifies them before reading. Peeking stops when:
/// - `predicate` returns [`PeekVerdict::Match`] or [`PeekVerdict::Reject`],
///   in which case no further read is issued;
/// - the reader returns EOF or an error;
/// - the `waiter` cuts the peek short, see [`PeekWaiter`];
/// - `buffer` is full.
pub async fn peek_input_until_verdict<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    offset: usize,
    waiter: &mut PeekWaiter<'_>,
    predicate: P,
) -> PeekOutput<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    let mut output = PeekOutput {
        data: None,
        peek_size: offset.min(buffer.len()),
        stop_reason: PeekStopReason::MaxPeekSizeReached,
    };

    if output.peek_size > 0 {
        match predicate(&buffer[..output.peek_size]) {
            PeekVerdict::Match(data) => {
                output.data = Some(data);
                output.stop_reason = PeekStopReason::Match;
                return output;
            }
            PeekVerdict::Reject => {
                output.stop_reason = PeekStopReason::Rejected;
                return output;
            }
            PeekVerdict::NeedMore => {}
        }
    }

    if buffer[output.peek_size..].is_empty() {
        return output;
    }

    loop {
        let n = match waiter
            .read(reader, &mut buffer[output.peek_size..], output.peek_size)
            .await
        {
            PeekRead::Read(n) => n,
            PeekRead::Error(err) => {
                tracing::debug!("I/O peek: peek read error: {err}");
                output.stop_reason = PeekStopReason::ReadError;
                return output;
            }
            PeekRead::Cutoff(cutoff) => {
                output.stop_reason = cutoff.into();
                return output;
            }
        };

        if n == 0 {
            tracing::trace!("I/O peek: break loop: no new data read...");
            output.stop_reason = PeekStopReason::Eof;
            return output;
        }

        output.peek_size = (output.peek_size + n).min(buffer.len());

        match predicate(&buffer[..output.peek_size]) {
            PeekVerdict::Match(data) => {
                output.data = Some(data);
                output.stop_reason = PeekStopReason::Match;
                tracing::trace!("I/O peek: data matched by predicate: return it...");
                return output;
            }
            PeekVerdict::Reject => {
                output.stop_reason = PeekStopReason::Rejected;
                tracing::trace!("I/O peek: predicate rejected prefix: stop peeking...");
                return output;
            }
            PeekVerdict::NeedMore => {
                if output.peek_size == buffer.len() {
                    output.stop_reason = PeekStopReason::MaxPeekSizeReached;
                    return output;
                }
            }
        }
    }
}

/// Fail-fast peek that **grows** its buffer on demand up to `max_len`, instead
/// of reading into a fixed caller-provided slice like
/// [`peek_input_until_verdict`].
///
/// Use this for a variable-length prefix (e.g. a TLS ClientHello) so the buffer
/// tracks the bytes actually received rather than being pre-sized to a length
/// the peer declared: memory stays proportional to real input, while `max_len`
/// still bounds a very large — or lying — peer. Once the buffer reaches
/// `max_len` without a verdict, peeking stops with no match.
///
/// `buffer` is caller-owned and may already hold an earlier peek (e.g. a record
/// header); a non-empty existing prefix is classified first and preserved for
/// replay. The predicate is never called with an empty slice. The buffer grows
/// in `read_chunk`-sized steps. Returns the matched value, or `None` on reject /
/// EOF / cutoff / reaching `max_len` without a match; either way `buffer` is
/// left holding exactly the peeked bytes.
pub async fn peek_input_until_verdict_growing<R, O, P>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    max_len: usize,
    read_chunk: NonZeroUsize,
    waiter: &mut PeekWaiter<'_>,
    predicate: P,
) -> Option<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    peek_input_until_verdict_growing_with_output(
        reader, buffer, max_len, read_chunk, waiter, predicate,
    )
    .await
    .data
}

/// Same as [`peek_input_until_verdict_growing`], but returns the complete
/// [`PeekOutput`] so callers can distinguish a cutoff from a definitive
/// rejection and other inconclusive stop conditions.
pub async fn peek_input_until_verdict_growing_with_output<R, O, P>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    max_len: usize,
    read_chunk: NonZeroUsize,
    waiter: &mut PeekWaiter<'_>,
    predicate: P,
) -> PeekOutput<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    let stop = |buffer: &Vec<u8>, stop_reason| PeekOutput {
        data: None,
        peek_size: buffer.len(),
        stop_reason,
    };

    if !buffer.is_empty() {
        match predicate(buffer) {
            PeekVerdict::Match(data) => {
                return PeekOutput {
                    data: Some(data),
                    peek_size: buffer.len(),
                    stop_reason: PeekStopReason::Match,
                };
            }
            PeekVerdict::Reject => return stop(buffer, PeekStopReason::Rejected),
            PeekVerdict::NeedMore => {}
        }
    }

    let chunk = read_chunk.get();

    while buffer.len() < max_len {
        let start = buffer.len();
        let want = chunk.min(max_len - start);
        buffer.reserve(want);

        let n = match waiter
            .read_buf(reader, &mut (&mut *buffer).limit(want), start)
            .await
        {
            PeekRead::Read(n) => n,
            PeekRead::Error(err) => {
                tracing::debug!("I/O peek(grow): read error: {err}");
                return stop(buffer, PeekStopReason::ReadError);
            }
            PeekRead::Cutoff(cutoff) => {
                return stop(buffer, cutoff.into());
            }
        };

        if n == 0 {
            tracing::trace!("I/O peek(grow): break loop: no new data read...");
            return stop(buffer, PeekStopReason::Eof);
        }

        match predicate(buffer) {
            PeekVerdict::Match(data) => {
                return PeekOutput {
                    data: Some(data),
                    peek_size: buffer.len(),
                    stop_reason: PeekStopReason::Match,
                };
            }
            PeekVerdict::Reject => return stop(buffer, PeekStopReason::Rejected),
            PeekVerdict::NeedMore => {}
        }
    }

    stop(buffer, PeekStopReason::MaxPeekSizeReached)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unreachable,
        reason = "test fixture: closure is wired up but never invoked on the tested path"
    )]

    use super::*;

    use std::{
        convert::Infallible,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use crate::{
        ServiceInput,
        graceful::{Cause, Scope, attach_scope},
        io::{BridgeIo, Io},
        service::service_fn,
    };
    use tokio::io::{AsyncReadExt as _, ReadBuf};

    fn cancel_after(timeout: Duration) -> WeakScope {
        Scope::new().with_timeout(timeout).into_weak_scope()
    }

    fn scoped<I: ExtensionsRef>(input: I) -> I {
        attach_scope(
            input.extensions(),
            &Scope::new().with_timeout(Duration::from_millis(10)),
        );
        input
    }

    async fn collect_accepted(
        mut stream: impl Io + Unpin,
    ) -> Result<(&'static str, Vec<u8>), io::Error> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        Ok(("accepted", bytes))
    }

    async fn collect_fallback(
        mut stream: impl Io + Unpin,
    ) -> Result<(&'static str, Vec<u8>), io::Error> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        Ok(("fallback", bytes))
    }

    #[tokio::test]
    async fn peek_router_dispatches_and_replays_all_input() {
        const PREFIXES: &[&[u8]] = &[b"MAGIC", b"SPELL"];

        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if PREFIXES.iter().any(|prefix| buffer.starts_with(prefix)) {
                    PeekVerdict::Match(())
                } else if PREFIXES.iter().any(|prefix| prefix.starts_with(buffer)) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(collect_accepted),
        )
        .with_max_peek_size(NonZeroUsize::new(5).unwrap())
        .with_peek_read_chunk_size(NonZeroUsize::new(2).unwrap())
        .with_fallback(service_fn(collect_fallback));

        let matched = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"MAGIC payload".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("accepted", b"MAGIC payload".to_vec()), matched);

        let second_match = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"SPELL payload".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("accepted", b"SPELL payload".to_vec()), second_match);

        let rejected = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"OTHER payload".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("fallback", b"OTHER payload".to_vec()), rejected);
    }

    #[tokio::test]
    async fn peek_router_never_calls_predicate_with_empty_input() {
        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if buffer[0] == 5 {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(collect_accepted),
        )
        .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"\x05payload".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("accepted", b"\x05payload".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_configured_limit_falls_back_and_replays() {
        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_max_peek_size(NonZeroUsize::new(4).unwrap())
        .with_peek_read_chunk_size(NonZeroUsize::new(2).unwrap())
        .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"eight123".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("fallback", b"eight123".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_limit_does_not_read_from_idle_peer_again() {
        async fn read_limit(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_max_peek_size(NonZeroUsize::new(4).unwrap())
        .with_fallback(service_fn(read_limit));
        let input = ServiceInput::new(tokio::io::join(
            IdleAfterReader::new(b"four"),
            tokio::io::sink(),
        ));

        let result = tokio::time::timeout(Duration::from_secs(1), router.serve(input))
            .await
            .expect("reaching the peek limit must not issue another read")
            .unwrap();
        assert_eq!(("fallback", b"four".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_cancelled_scope_falls_back_and_replays_partial_input() {
        async fn read_partial(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if buffer.starts_with(b"MAGIC") {
                    PeekVerdict::Match(())
                } else if b"MAGIC".starts_with(buffer) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_fallback(service_fn(read_partial));

        let input = scoped(ServiceInput::new(tokio::io::join(
            IdleAfterReader::new(b"MA"),
            tokio::io::sink(),
        )));
        let result = router.serve(input).await.unwrap();
        assert_eq!(("fallback", b"MA".to_vec()), result);
        assert_eq!(PeekPolicy::FAIL_OPEN, PeekPolicy::default());
    }

    #[derive(Debug, Clone, crate::extensions::Extension)]
    struct Strict;

    #[tokio::test]
    async fn peek_router_selects_its_policy_per_input() {
        type Input = ServiceInput<tokio::io::Join<IdleAfterReader, tokio::io::Sink>>;
        let router = PeekRouter::from_prefix(b"MAGIC", service_fn(collect_accepted))
            .with_peek_policy(|input: &Input| {
                if input.extensions().contains::<Strict>() {
                    PeekPolicy::FAIL_CLOSED
                } else {
                    PeekPolicy::FAIL_OPEN
                }
            })
            .with_fallback(service_fn(async |mut stream: PeekPrefixedIo<Input>| {
                let mut bytes = [0_u8; 2];
                stream.read_exact(&mut bytes).await?;
                Ok::<_, io::Error>(("fallback", bytes.to_vec()))
            }));
        let partial = || {
            scoped(ServiceInput::new(tokio::io::join(
                IdleAfterReader::new(b"MA"),
                tokio::io::sink(),
            )))
        };

        let result = router.serve(partial()).await.unwrap();
        assert_eq!(("fallback", b"MA".to_vec()), result);

        let strict = partial();
        strict.extensions().insert(Strict);
        let error = router.serve(strict).await.unwrap_err();
        assert_eq!(
            Some(PeekCutoff::Cancelled),
            error
                .downcast_ref::<PeekCutoffError>()
                .map(PeekCutoffError::cutoff)
        );
    }

    #[tokio::test]
    async fn peek_router_fail_closed_cancel_returns_typed_error_without_fallback() {
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls_for_service = Arc::clone(&fallback_calls);
        let fallback = service_fn(move || {
            fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>(("fallback", Vec::<u8>::new())) }
        });

        let router = PeekRouter::from_prefix(
            b"MAGIC",
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_peek_policy(PeekPolicy::FAIL_CLOSED)
        .with_fallback(fallback);

        let input = scoped(ServiceInput::new(tokio::io::join(
            IdleAfterReader::new(b"MA"),
            tokio::io::sink(),
        )));
        let error = router.serve(input).await.unwrap_err();

        assert_eq!(
            Some(PeekCutoff::Cancelled),
            error
                .downcast_ref::<PeekCutoffError>()
                .map(PeekCutoffError::cutoff)
        );
        assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn peek_router_definitive_mismatch_falls_back_under_both_policies() {
        for policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            let router = PeekRouter::from_prefix(b"MAGIC", service_fn(collect_accepted))
                .with_peek_policy(policy)
                .with_fallback(service_fn(collect_fallback));

            let result = router
                .serve(ServiceInput::new(std::io::Cursor::new(b"NOPE".to_vec())))
                .await
                .unwrap();
            assert_eq!(("fallback", b"NOPE".to_vec()), result);
        }
    }

    #[tokio::test]
    async fn peek_router_fail_closed_without_scope_preserves_existing_eof_fallback() {
        let router = PeekRouter::from_prefix(b"PING", service_fn(collect_accepted))
            .with_peek_policy(PeekPolicy::FAIL_CLOSED)
            .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(ServiceInput::new(std::io::Cursor::new(b"PI".to_vec())))
            .await
            .unwrap();
        assert_eq!(("fallback", b"PI".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_read_error_falls_back_and_replays_partial_input() {
        async fn read_partial(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_fallback(service_fn(read_partial));
        let reader = tokio_test::io::Builder::new()
            .read(b"MA")
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let input = ServiceInput::new(tokio::io::join(reader, tokio::io::sink()));

        let result = router.serve(input).await.unwrap();
        assert_eq!(("fallback", b"MA".to_vec()), result);
    }

    #[tokio::test]
    async fn prefix_peek_router_decides_before_idle_peer_blocks() {
        async fn read_ping(mut stream: impl Io + Unpin) -> Result<&'static str, io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(b"PING", &bytes);
            Ok("accepted")
        }

        async fn read_pong(mut stream: impl Io + Unpin) -> Result<&'static str, io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(b"PONG", &bytes);
            Ok("fallback")
        }

        let matched = PeekRouter::from_prefix(b"PING", service_fn(read_ping))
            .with_fallback(service_fn(read_pong));
        let matched_input = ServiceInput::new(tokio::io::join(
            IdleAfterReader::new(b"PING"),
            tokio::io::sink(),
        ));
        let result = tokio::time::timeout(Duration::from_secs(1), matched.serve(matched_input))
            .await
            .expect("matching prefix must not wait for more input")
            .unwrap();
        assert_eq!("accepted", result);

        let rejected = PeekRouter::from_prefix(b"PING", service_fn(read_ping))
            .with_fallback(service_fn(read_pong));
        let rejected_input = ServiceInput::new(tokio::io::join(
            IdleAfterReader::new(b"PONG"),
            tokio::io::sink(),
        ));
        let result = tokio::time::timeout(Duration::from_secs(1), rejected.serve(rejected_input))
            .await
            .expect("diverging prefix must not wait for more input")
            .unwrap();
        assert_eq!("fallback", result);
    }

    #[tokio::test]
    async fn prefix_peek_router_replays_eof_mid_prefix() {
        let router = PeekRouter::from_prefix(b"PING", service_fn(collect_accepted))
            .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(ServiceInput::new(std::io::Cursor::new(b"PI".to_vec())))
            .await
            .unwrap();
        assert_eq!(("fallback", b"PI".to_vec()), result);
    }

    #[tokio::test]
    async fn prefix_peek_router_falls_back_when_limit_is_shorter_than_prefix() {
        let router = PeekRouter::from_prefix(b"PING", service_fn(collect_accepted))
            .with_max_peek_size(NonZeroUsize::new(2).unwrap())
            .with_fallback(service_fn(collect_fallback));
        let result = router
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PING payload".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(("fallback", b"PING payload".to_vec()), result);
    }

    #[test]
    #[should_panic(expected = "PeekRouter prefix must not be empty")]
    fn prefix_peek_router_rejects_empty_prefix() {
        let _router = PeekRouter::from_prefix(
            b"",
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::<u8>::new()))),
        );
    }

    fn exactly(expected: &'static [u8]) -> impl Fn(&[u8]) -> PeekVerdict<usize> {
        move |buf| {
            if buf == expected {
                PeekVerdict::Match(buf.len())
            } else if expected.starts_with(buf) {
                PeekVerdict::NeedMore
            } else {
                PeekVerdict::Reject
            }
        }
    }

    #[tokio::test]
    async fn returns_immediately_for_empty_buffer() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = [];

        let output = peek_input_until_verdict::<_, (), _>(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            |_| unreachable!(),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
        assert_eq!(output.stop_reason, PeekStopReason::MaxPeekSizeReached);
    }

    #[tokio::test]
    async fn verdict_match_returns_data_on_first_read() {
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
        assert_eq!(output.stop_reason, PeekStopReason::Match);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn verdict_need_more_accumulates_across_reads_until_match() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_hits_eof_before_match() {
        let mut reader = tokio_test::io::Builder::new().read(b"he").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(output.stop_reason, PeekStopReason::Eof);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_errors_after_progress() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(output.stop_reason, PeekStopReason::ReadError);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_no_data_when_first_read_errors() {
        let mut reader = tokio_test::io::Builder::new()
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
        assert_eq!(output.stop_reason, PeekStopReason::ReadError);
    }

    #[tokio::test]
    async fn cancelled_scope_returns_partial_bytes_already_peeked() {
        let mut reader = TwoPhaseReader {
            first_chunk: Some(b"he".to_vec()),
            sleep: Some(Box::pin(tokio::time::sleep(Duration::from_millis(50)))),
        };
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new().with_scope(cancel_after(Duration::from_millis(10))),
            exactly(b"hello"),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(output.stop_reason, PeekStopReason::Cancelled);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn verdict_stops_when_buffer_is_full() {
        let mut reader = tokio_test::io::Builder::new().read(b"hel").build();
        let mut buffer = [0_u8; 3];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 3);
        assert_eq!(output.stop_reason, PeekStopReason::MaxPeekSizeReached);
    }

    #[tokio::test]
    async fn verdict_classifies_the_prefilled_offset_before_reading() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = *b"hello";
        let offset = buffer.len();

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            offset,
            &mut PeekWaiter::new(),
            exactly(b"hello"),
        )
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn verdict_reject_returns_without_blocking_on_idle_peer() {
        // A peer that sends a short non-matching prefix and then stays connected
        // without sending more (never EOF). A rejecting predicate must return
        // immediately; otherwise the next read would block forever and only the
        // timeout below would end it.
        let mut reader = IdleAfterReader::new(b"PING");

        let output = tokio::time::timeout(
            Duration::from_secs(5),
            peek_input_until_verdict(
                &mut reader,
                &mut [0_u8; 5],
                0,
                &mut PeekWaiter::new(),
                |buf: &[u8]| {
                    if buf.first() == Some(&0x16) {
                        PeekVerdict::Match(())
                    } else {
                        PeekVerdict::Reject
                    }
                },
            ),
        )
        .await
        .expect("reject must stop peeking without waiting for a full buffer");

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 4);
        assert_eq!(output.stop_reason, PeekStopReason::Rejected);
    }

    #[tokio::test]
    async fn verdict_assembles_fragmented_prefix() {
        // Under TCP fragmentation a `NeedMore` verdict keeps reading (one byte
        // per read here) until the predicate can decide.
        let mut reader = tokio_test::io::Builder::new()
            .read(b"\x16")
            .read(b"\x03")
            .read(b"\x03")
            .read(b"\x00")
            .read(b"\x2a")
            .build();
        let mut buffer = [0_u8; 5];

        let output = peek_input_until_verdict(
            &mut reader,
            &mut buffer,
            0,
            &mut PeekWaiter::new(),
            |buf: &[u8]| {
                if buf.first() != Some(&0x16) {
                    PeekVerdict::Reject
                } else if buf.len() >= 5 {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::NeedMore
                }
            },
        )
        .await;

        assert!(output.data.is_some());
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn verdict_growing_grows_across_reads_until_match() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(4).unwrap(),
            &mut PeekWaiter::new(),
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(buf.len())
                } else if b"hello".starts_with(buf) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
        )
        .await;

        assert_eq!(data, Some(5));
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_uses_spare_capacity_and_preserves_prefix_on_error() {
        struct SpareReader;

        impl AsyncRead for SpareReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                assert!(
                    buf.initialized().is_empty(),
                    "peek initialized spare capacity"
                );
                assert_eq!(buf.remaining(), 3);
                Poll::Ready(Err(io::Error::other("read failed")))
            }
        }

        let mut buffer = Vec::with_capacity(32);
        buffer.extend_from_slice(b"prefix");
        let output = peek_input_until_verdict_growing_with_output(
            &mut SpareReader,
            &mut buffer,
            9,
            NonZeroUsize::new(8).unwrap(),
            &mut PeekWaiter::new(),
            |_| PeekVerdict::<()>::NeedMore,
        )
        .await;
        assert_eq!(output.stop_reason, PeekStopReason::ReadError);
        assert_eq!(output.peek_size, 6);
        assert_eq!(buffer, b"prefix");
    }

    #[tokio::test]
    async fn verdict_growing_does_not_classify_empty_buffer_at_eof() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            8,
            NonZeroUsize::new(8).unwrap(),
            &mut PeekWaiter::new(),
            |_buf: &[u8]| -> PeekVerdict<()> { unreachable!() },
        )
        .await;

        assert!(data.is_none());
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn verdict_growing_never_grows_past_max_len() {
        // `max_len` (5) is deliberately NOT a multiple of the chunk (2), so the
        // final read is clamped to the remaining-to-cap; the buffer must land
        // exactly on `max_len` and never past it, even with data still available.
        let mut reader = FillReader { remaining: 100 };
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            5,
            NonZeroUsize::new(2).unwrap(),
            &mut PeekWaiter::new(),
            |_buf: &[u8]| PeekVerdict::<()>::NeedMore,
        )
        .await;

        assert!(data.is_none());
        assert_eq!(buffer.len(), 5, "buffer must land exactly on max_len");
    }

    #[tokio::test]
    async fn verdict_growing_matches_within_a_generous_scope() {
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(8).unwrap(),
            &mut PeekWaiter::new().with_scope(cancel_after(Duration::from_secs(5))),
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(())
                } else if b"hello".starts_with(buf) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
        )
        .await;

        assert!(data.is_some());
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_matches_preseeded_buffer_without_reading() {
        // The pre-seeded buffer already satisfies the predicate, so no read may
        // happen — an empty mock reader panics on any unexpected read.
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = b"hello".to_vec();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(8).unwrap(),
            &mut PeekWaiter::new(),
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::NeedMore
                }
            },
        )
        .await;

        assert!(data.is_some());
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_rejects_without_blocking_on_idle_peer() {
        // A non-matching prefix then an idle-but-open peer: the reject must
        // return without blocking on the byte that never arrives.
        let mut reader = IdleAfterReader::new(b"PING");
        let mut buffer = Vec::new();

        let data = tokio::time::timeout(
            Duration::from_secs(5),
            peek_input_until_verdict_growing(
                &mut reader,
                &mut buffer,
                64,
                NonZeroUsize::new(8).unwrap(),
                &mut PeekWaiter::new(),
                |buf: &[u8]| {
                    if buf.is_empty() {
                        PeekVerdict::NeedMore
                    } else if buf[0] == 0x16 {
                        PeekVerdict::Match(())
                    } else {
                        PeekVerdict::Reject
                    }
                },
            ),
        )
        .await
        .expect("reject must stop without blocking");

        assert!(data.is_none());
        assert_eq!(buffer, b"PING");
    }

    #[tokio::test]
    async fn replay_peeked_replays_both_prefixes_before_live_bytes() {
        let input = BridgeIo(
            std::io::Cursor::new(b"live ingress".to_vec()),
            std::io::Cursor::new(b"live egress".to_vec()),
        );
        let BridgeIo(mut ingress, mut egress) = replay_peeked(
            input,
            ReplayReader::new(Bytes::from_static(b"peeked ")),
            Bytes::from_static(b"server "),
        );

        let mut bytes = Vec::new();
        ingress.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(b"peeked live ingress", bytes.as_slice());
        bytes.clear();
        egress.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(b"server live egress", bytes.as_slice());
    }

    #[tokio::test]
    async fn replay_peeked_maps_a_plain_io_to_its_ingress_only() {
        let mut io = replay_peeked(
            std::io::Cursor::new(b"live".to_vec()),
            ReplayReader::new(Bytes::from_static(b"peeked ")),
            Bytes::new(),
        );

        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(b"peeked live", bytes.as_slice());
    }

    fn cancelled_scope() -> Scope {
        let scope = Scope::new();
        scope.cancel(Cause::Owner);
        scope
    }

    #[tokio::test]
    async fn wait_for_ready_input_wins_over_a_cutoff() {
        let scope = cancelled_scope();
        scope.abort(Cause::Owner);
        let mut waiter = PeekWaiter::new()
            .with_policy(PeekPolicy::FAIL_CLOSED)
            .with_scope(scope.clone_weak());

        assert_eq!(Ok(7), waiter.wait_for(std::future::ready(7), 0).await);
        waiter.check::<PeekCutoffError>().unwrap();
    }

    #[tokio::test]
    async fn wait_for_cancel_follows_the_policy() {
        let scope = cancelled_scope();

        let mut waiter = PeekWaiter::new().with_scope(scope.clone_weak());
        assert_eq!(
            Err(PeekCutoff::Cancelled),
            waiter.wait_for(std::future::pending::<()>(), 0).await
        );
        waiter.check::<PeekCutoffError>().unwrap();

        let mut waiter = PeekWaiter::new()
            .with_policy(PeekPolicy::FAIL_CLOSED)
            .with_scope(scope.clone_weak());
        assert_eq!(
            Err(PeekCutoff::Cancelled),
            waiter.wait_for(std::future::pending::<()>(), 3).await
        );
        let err = waiter.check::<PeekCutoffError>().unwrap_err();
        assert_eq!(PeekCutoff::Cancelled, err.cutoff());
        assert!(matches!(err.cause(), Some(Cause::Owner)));
    }

    #[tokio::test]
    async fn wait_for_abort_fails_under_any_policy() {
        let scope = Scope::new();
        scope.abort(Cause::Reason("shutdown"));
        let mut waiter = PeekWaiter::new()
            .with_policy(PeekPolicy::FAIL_OPEN.with_cancelled_idle(PeekAction::Wait))
            .with_scope(scope.clone_weak());

        assert_eq!(
            Err(PeekCutoff::Aborted),
            waiter.wait_for(std::future::pending::<()>(), 0).await
        );
        let err = waiter.check::<PeekCutoffError>().unwrap_err();
        assert_eq!(PeekCutoff::Aborted, err.cutoff());
        assert!(matches!(err.cause(), Some(Cause::Reason("shutdown"))));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_waives_a_waited_cancel_until_progress_changes() {
        let scope = cancelled_scope();
        let mut waiter = PeekWaiter::new()
            .with_policy(PeekPolicy::FAIL_OPEN.with_cancelled_idle(PeekAction::Wait))
            .with_scope(scope.clone_weak());

        let late = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            7
        };
        assert_eq!(Ok(7), waiter.wait_for(late, 0).await);
        let late = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            8
        };
        assert_eq!(Ok(8), waiter.wait_for(late, 0).await);

        assert_eq!(
            Err(PeekCutoff::Cancelled),
            waiter.wait_for(std::future::pending::<()>(), 1).await
        );
        waiter.check::<PeekCutoffError>().unwrap();
    }

    /// A reader that fully fills the provided buffer until a byte budget is
    /// exhausted, then EOFs — deterministic (each read yields exactly the
    /// requested amount) for exercising the grow loop's sizing arithmetic.
    struct FillReader {
        remaining: usize,
    }

    impl AsyncRead for FillReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining().min(self.remaining);
            if n > 0 {
                buf.put_slice(&vec![0xAA_u8; n]);
                self.remaining -= n;
            }
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that yields a fixed prefix on the first read, then never
    /// produces more data nor EOF — it simply pends, modelling a peer that sent
    /// a short prefix and then went idle while keeping the connection open.
    struct IdleAfterReader {
        prefix: Option<&'static [u8]>,
    }

    impl IdleAfterReader {
        fn new(prefix: &'static [u8]) -> Self {
            Self {
                prefix: Some(prefix),
            }
        }
    }

    impl AsyncRead for IdleAfterReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(prefix) = self.prefix.take() {
                let n = prefix.len().min(buf.remaining());
                buf.put_slice(&prefix[..n]);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    struct TwoPhaseReader {
        first_chunk: Option<Vec<u8>>,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncRead for TwoPhaseReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.first_chunk.take() {
                buf.put_slice(&chunk[..chunk.len().min(buf.remaining())]);
                return Poll::Ready(Ok(()));
            }

            match self.sleep.as_mut() {
                Some(sleep) => sleep.as_mut().poll(cx).map(|_| Ok(())),
                None => Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod egress_tests;
