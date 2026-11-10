use std::{future::pending, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::Instant,
};

use super::{PeekInterrupt, PeekStopReason};
use crate::bytes::BufMut;

/// Event that cuts a peek short before it reached a verdict.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeekCutoff {
    /// The peek timeout elapsed.
    Timeout,
    /// The [`PeekInterrupt`] of the input was triggered.
    Interrupt,
}

impl From<PeekCutoff> for PeekStopReason {
    fn from(cutoff: PeekCutoff) -> Self {
        match cutoff {
            PeekCutoff::Timeout => Self::Timeout,
            PeekCutoff::Interrupt => Self::Interrupted,
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
    /// Stop peeking and fail with [`PeekTimeoutError`] or [`PeekInterruptedError`].
    Fail,
    /// Ignore the cutoff and keep waiting for input.
    ///
    /// The cutoff is evaluated again once the [`PeekProgress`] changes.
    Wait,
}

/// Decides what a [`PeekCutoff`] does, given the [`PeekProgress`] of the peek.
///
/// Distinguishing idle from partial input separates two cases a single timeout
/// cannot: a peer that never speaks first (e.g. a server-first protocol) versus
/// a peer that started a protocol message and is slow to complete it.
///
/// Definitive verdicts (match, reject, EOF, size limits) are not affected.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PeekPolicy {
    timeout_idle: PeekAction,
    timeout_partial: PeekAction,
    interrupt_idle: PeekAction,
    interrupt_partial: PeekAction,
}

impl Default for PeekPolicy {
    fn default() -> Self {
        Self::FAIL_OPEN
    }
}

impl PeekPolicy {
    /// Timeouts invoke the fallback.
    ///
    /// An interrupt invokes the fallback for idle input and is ignored for
    /// partial input. This is the default.
    pub const FAIL_OPEN: Self = Self {
        timeout_idle: PeekAction::Fallback,
        timeout_partial: PeekAction::Fallback,
        interrupt_idle: PeekAction::Fallback,
        interrupt_partial: PeekAction::Wait,
    };

    /// Timeouts fail the peek.
    ///
    /// Interrupts behave as in [`Self::FAIL_OPEN`].
    pub const FAIL_CLOSED: Self = Self {
        timeout_idle: PeekAction::Fail,
        timeout_partial: PeekAction::Fail,
        ..Self::FAIL_OPEN
    };

    /// The [`PeekAction`] for `cutoff` at `progress`.
    #[must_use]
    pub const fn action(&self, cutoff: PeekCutoff, progress: PeekProgress) -> PeekAction {
        match (cutoff, progress) {
            (PeekCutoff::Timeout, PeekProgress::Idle) => self.timeout_idle,
            (PeekCutoff::Timeout, PeekProgress::Partial) => self.timeout_partial,
            (PeekCutoff::Interrupt, PeekProgress::Idle) => self.interrupt_idle,
            (PeekCutoff::Interrupt, PeekProgress::Partial) => self.interrupt_partial,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a timeout before any byte was peeked.
        pub const fn timeout_idle(mut self, action: PeekAction) -> Self {
            self.timeout_idle = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for a timeout after a partial peek.
        pub const fn timeout_partial(mut self, action: PeekAction) -> Self {
            self.timeout_partial = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for an interrupt before any byte was peeked.
        pub const fn interrupt_idle(mut self, action: PeekAction) -> Self {
            self.interrupt_idle = action;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the action for an interrupt after a partial peek.
        pub const fn interrupt_partial(mut self, action: PeekAction) -> Self {
            self.interrupt_partial = action;
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

rama_utils::macros::error::static_str_error! {
    #[doc = "protocol peek timed out before reaching a definitive verdict"]
    pub struct PeekTimeoutError;
}

impl From<PeekTimeoutError> for io::Error {
    fn from(error: PeekTimeoutError) -> Self {
        Self::new(io::ErrorKind::TimedOut, error)
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "protocol peek interrupted before reaching a definitive verdict"]
    pub struct PeekInterruptedError;
}

impl From<PeekInterruptedError> for io::Error {
    fn from(error: PeekInterruptedError) -> Self {
        Self::new(io::ErrorKind::ConnectionAborted, error)
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

/// Reads peek input, bounded by a timeout and a [`PeekInterrupt`]
/// as directed by a [`PeekPolicy`].
///
/// The timeout starts when the waiter is created and covers all reads made
/// through it, so share one waiter across the phases of a single peek.
/// Input that is ready always wins over a cutoff.
#[derive(Debug, Default)]
pub struct PeekWaiter {
    deadline: Option<Instant>,
    interrupt: Option<Arc<PeekInterrupt>>,
    policy: PeekPolicy,
    timeout_waived: Option<PeekProgress>,
    interrupt_waived: Option<PeekProgress>,
    failed: Option<PeekCutoff>,
}

impl PeekWaiter {
    /// Create a waiter whose optional timeout starts now.
    #[must_use]
    pub fn new(timeout: Option<Duration>) -> Self {
        Self {
            deadline: timeout.map(|timeout| Instant::now() + timeout),
            ..Default::default()
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
        /// Set the [`PeekInterrupt`] that can cut the peek short,
        /// usually the one found in the input extensions.
        pub fn interrupt(mut self, interrupt: Option<Arc<PeekInterrupt>>) -> Self {
            self.interrupt = interrupt;
            self
        }
    }

    /// Read into `buf` unless a cutoff stops the peek first.
    ///
    /// `peeked` is the number of bytes this peek holds so far.
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
        let mut read = std::pin::pin!(read);
        let progress = PeekProgress::from_peeked(peeked);
        loop {
            let deadline = self
                .deadline
                .filter(|_| self.timeout_waived != Some(progress));
            let interrupt = self
                .interrupt
                .as_deref()
                .filter(|_| self.interrupt_waived != Some(progress));

            let cutoff = tokio::select! {
                biased;
                result = &mut read => {
                    return match result {
                        Ok(n) => PeekRead::Read(n),
                        Err(err) => PeekRead::Error(err),
                    };
                }
                () = sleep_until(deadline) => PeekCutoff::Timeout,
                () = interrupted(interrupt) => PeekCutoff::Interrupt,
            };

            let action = self.policy.action(cutoff, progress);
            tracing::debug!("I/O peek: {cutoff:?} at {progress:?} progress: {action:?}");
            match action {
                PeekAction::Wait => match cutoff {
                    PeekCutoff::Timeout => self.timeout_waived = Some(progress),
                    PeekCutoff::Interrupt => self.interrupt_waived = Some(progress),
                },
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
        E: From<PeekTimeoutError> + From<PeekInterruptedError>,
    {
        match self.failed {
            None => Ok(()),
            Some(PeekCutoff::Timeout) => Err(PeekTimeoutError::new().into()),
            Some(PeekCutoff::Interrupt) => Err(PeekInterruptedError::new().into()),
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending().await,
    }
}

async fn interrupted(interrupt: Option<&PeekInterrupt>) {
    match interrupt {
        Some(interrupt) => interrupt.triggered().await,
        None => pending().await,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt as _, duplex};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn waiter(timeout: Option<Duration>, policy: PeekPolicy) -> PeekWaiter {
        PeekWaiter::new(timeout).with_policy(policy)
    }

    fn triggered() -> Option<Arc<PeekInterrupt>> {
        let interrupt = Arc::new(PeekInterrupt::new());
        interrupt.trigger();
        Some(interrupt)
    }

    #[test]
    fn static_policy_ignores_the_input_and_closures_inspect_it() {
        let policy = PeekPolicy::FAIL_CLOSED;
        assert_eq!(policy, PeekPolicyProvider::<u16>::peek_policy(&policy, &25));

        let by_port = |port: &u16| {
            if *port == 443 {
                PeekPolicy::FAIL_OPEN.with_timeout_partial(PeekAction::Wait)
            } else {
                PeekPolicy::FAIL_OPEN
            }
        };
        assert_eq!(
            PeekAction::Wait,
            by_port
                .peek_policy(&443)
                .action(PeekCutoff::Timeout, PeekProgress::Partial)
        );
        assert_eq!(
            PeekAction::Fallback,
            by_port
                .peek_policy(&25)
                .action(PeekCutoff::Timeout, PeekProgress::Partial)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_action_depends_on_progress() {
        let policy = PeekPolicy::FAIL_OPEN.with_timeout_partial(PeekAction::Fail);
        let (_client, mut reader) = duplex(64);
        let mut buf = [0u8; 8];

        let mut idle = waiter(Some(Duration::from_millis(200)), policy);
        let read = idle.read(&mut reader, &mut buf, 0).await;
        assert!(matches!(read, PeekRead::Cutoff(PeekCutoff::Timeout)));
        idle.check::<io::Error>().unwrap();

        let mut partial = waiter(Some(Duration::from_millis(200)), policy);
        let read = partial.read(&mut reader, &mut buf, 3).await;
        assert!(matches!(read, PeekRead::Cutoff(PeekCutoff::Timeout)));
        let err = partial.check::<io::Error>().unwrap_err();
        assert_eq!(io::ErrorKind::TimedOut, err.kind());
    }

    #[tokio::test(start_paused = true)]
    async fn waived_timeout_keeps_waiting_for_slow_input() {
        let policy = PeekPolicy::FAIL_CLOSED.with_timeout_partial(PeekAction::Wait);
        let (mut client, mut reader) = duplex(64);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            client.write_all(b"rest").await.unwrap();
            client
        });

        let mut waiter = waiter(Some(Duration::from_millis(200)), policy);
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(HOUR, waiter.read(&mut reader, &mut buf, 3))
            .await
            .unwrap();
        assert!(matches!(read, PeekRead::Read(4)));
        waiter.check::<io::Error>().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn waived_cutoff_is_evaluated_again_once_input_arrives() {
        let policy = PeekPolicy::FAIL_CLOSED.with_timeout_idle(PeekAction::Wait);
        let (mut client, mut reader) = duplex(64);
        // the handle keeps the client open after it wrote
        let _client = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            client.write_all(b"a").await.unwrap();
            client
        });

        let mut waiter = waiter(Some(Duration::from_millis(200)), policy);
        let mut buf = [0u8; 8];
        let read = waiter.read(&mut reader, &mut buf, 0).await;
        assert!(matches!(read, PeekRead::Read(1)));

        let read = waiter.read(&mut reader, &mut buf[1..], 1).await;
        assert!(matches!(read, PeekRead::Cutoff(PeekCutoff::Timeout)));
        assert!(waiter.check::<io::Error>().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn ready_input_wins_over_a_triggered_interrupt() {
        let (mut client, mut reader) = duplex(64);
        client.write_all(b"GET").await.unwrap();

        let mut waiter = PeekWaiter::default().with_interrupt(triggered().unwrap());
        let mut buf = [0u8; 8];
        let read = waiter.read(&mut reader, &mut buf, 0).await;
        assert!(matches!(read, PeekRead::Read(3)));
    }

    #[tokio::test(start_paused = true)]
    async fn interrupt_ends_idle_peek_but_not_partial_one_by_default() {
        let (mut client, mut reader) = duplex(64);
        let mut buf = [0u8; 8];

        let mut idle = PeekWaiter::default().maybe_with_interrupt(triggered());
        let read = idle.read(&mut reader, &mut buf, 0).await;
        assert!(matches!(read, PeekRead::Cutoff(PeekCutoff::Interrupt)));
        idle.check::<io::Error>().unwrap();

        let mut partial = PeekWaiter::default().maybe_with_interrupt(triggered());
        let pending = tokio::time::timeout(HOUR, partial.read(&mut reader, &mut buf, 2)).await;
        assert!(pending.is_err(), "partial input keeps waiting");

        client.write_all(b"x").await.unwrap();
        let read = partial.read(&mut reader, &mut buf, 2).await;
        assert!(matches!(read, PeekRead::Read(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn interrupt_can_fail_the_peek() {
        let (_client, mut reader) = duplex(64);
        let policy = PeekPolicy::FAIL_OPEN.with_interrupt_idle(PeekAction::Fail);
        let mut waiter = waiter(None, policy).maybe_with_interrupt(triggered());
        let mut buf = [0u8; 8];

        let read = waiter.read(&mut reader, &mut buf, 0).await;
        assert!(matches!(read, PeekRead::Cutoff(PeekCutoff::Interrupt)));
        let err = waiter.check::<crate::error::BoxError>().unwrap_err();
        assert!(err.is::<PeekInterruptedError>());
    }
}
