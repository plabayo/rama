//! Opt-in observation and application of initial connection-level receive credit.
//!
//! Observed credit includes validated connection WINDOW_UPDATE increments before
//! the first complete peer HEADERS; that initial block must be accepted. Credit
//! after nonempty DATA commitment is explicitly ambiguous before that boundary.
//! Receive targets preserve the cumulative credit, not frame timing/occurrences
//! or steady-state flow-control behavior. Ordinary connections allocate no cell.

use crate::h2::{
    UserError,
    proto::{Error, MAX_WINDOW_SIZE},
};
use parking_lot::Mutex;
use rama_core::extensions::{Extension, Extensions};
use rama_http_types::proto::h2::frame::DEFAULT_INITIAL_WINDOW_SIZE;
use std::{
    fmt,
    sync::Arc,
    task::{Context, Waker},
};
use tokio::sync::Notify;

/// Observe one native connection's peer-advertised initial connection credit.
/// Install on its IO before the handshake. Clones observe the same connection;
/// attaching a clone to a second connection is an error. No dispatcher is held.
#[derive(Clone, Debug, Extension)]
#[non_exhaustive]
pub struct PeerInitialCredit {
    state: Arc<State>,
}

impl PeerInitialCredit {
    /// Create an unbound observation. Creating handles is the only cell allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(State {
                inner: Mutex::new(Inner {
                    status: Status::Unbound,
                    source_claimed: false,
                    target_claimed: false,
                    target_waker: None,
                }),
                complete: Notify::new(),
            }),
        }
    }

    /// Read current facts without retaining a frame history.
    #[must_use]
    pub fn snapshot(&self) -> Status {
        self.state.inner.lock().status
    }

    /// Wait for the accepted first HEADERS, or an explicit unsupported/incomplete
    /// disposition. Unbound or unresponsive sources require caller cancellation.
    pub async fn complete(&self) -> Result<u32, Failure> {
        loop {
            let notified = self.state.complete.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            match self.snapshot() {
                Status::Complete { target } => return Ok(target),
                Status::Failed { reason, .. } => return Err(reason),
                Status::Unbound | Status::Observing { .. } => (),
            }
            notified.await;
        }
    }

    /// Apply this observation as another native connection's receive preference.
    /// The destination must select initial target 65535 and disable adaptive
    /// growth explicitly. Only one destination may claim this preference.
    ///
    /// `maximum` is the caller's receive-credit budget, from the initial protocol
    /// window through [`super::MAX_WINDOW_SIZE`]. An observed target above it is
    /// refused locally before advertising or committing additional credit. The
    /// source fact remains valid; values are never clamped to the destination.
    pub fn try_receive_target(&self, maximum: u32) -> Result<ReceiveInitialCredit, super::Error> {
        if !(DEFAULT_INITIAL_WINDOW_SIZE..=MAX_WINDOW_SIZE).contains(&maximum) {
            return Err(UserError::InitialCreditConfiguration.into());
        }
        Ok(ReceiveInitialCredit {
            state: self.state.clone(),
            maximum,
        })
    }
}

impl Default for PeerInitialCredit {
    fn default() -> Self {
        Self::new()
    }
}

/// Require one connection's native receive credit to follow the paired source.
/// Install on destination IO before its handshake. Source ambiguity/incomplete
/// closure fails this destination; it does not change the source's protocol result.
#[derive(Clone, Debug, Extension)]
#[non_exhaustive]
pub struct ReceiveInitialCredit {
    state: Arc<State>,
    maximum: u32,
}

/// Current cumulative initial-credit fact. The initial protocol target is 65535.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// No native source connection has claimed the observation yet.
    Unbound,
    /// Validated growth is available, but the initial prefix is not complete.
    Observing {
        /// Cumulative target supported by validated increments so far.
        target: u32,
    },
    /// The first complete peer HEADERS passed native initial-header validation.
    Complete {
        /// Frozen cumulative target.
        target: u32,
    },
    /// Strict target use is unavailable; target is only the last known prefix.
    Failed {
        /// Last known target; strict application is unavailable.
        target: u32,
        /// Why the observation cannot complete.
        reason: Failure,
    },
}

/// Why a source cannot supply a complete unambiguous initial-credit fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// Credit after nonempty DATA commitment may replenish consumed request data.
    DataCreditBeforeInitialHeaders,
    /// The first HEADERS was ignored, refused, malformed or otherwise rejected.
    InitialHeadersNotAccepted,
    /// The source closed or its handshake was cancelled before first HEADERS.
    ClosedBeforeInitialHeaders,
    /// A native protocol or I/O error prevented establishing the initial prefix.
    NativeError,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DataCreditBeforeInitialHeaders => {
                "initial connection credit is ambiguous after DATA"
            }
            Self::InitialHeadersNotAccepted => "initial peer HEADERS was not accepted",
            Self::ClosedBeforeInitialHeaders => "connection closed before initial peer HEADERS",
            Self::NativeError => "source failed before initial peer HEADERS",
        })
    }
}

impl std::error::Error for Failure {}

#[derive(Debug)]
struct State {
    inner: Mutex<Inner>,
    complete: Notify,
}

#[derive(Debug)]
struct Inner {
    status: Status,
    source_claimed: bool,
    target_claimed: bool,
    target_waker: Option<Waker>,
}

/// Stack-only delivery of a changed cell's notifications. Native wrappers must
/// drop their stream-state guard before dispatch. No implicit Drop callback.
#[must_use = "dispatch credit notifications after releasing native stream locks"]
#[derive(Debug, Default)]
pub(super) struct Notification {
    state: Option<Arc<State>>,
    wake: Option<Waker>,
}

impl Notification {
    pub(super) fn dispatch(self) {
        if let Some(wake) = self.wake {
            wake.wake();
        }
        if let Some(state) = self.state {
            state.complete.notify_waiters();
        }
    }
}

impl State {
    fn publish(self: &Arc<Self>, change: impl FnOnce(&mut Inner) -> bool) -> Notification {
        let wake = {
            let mut inner = self.inner.lock();
            if !change(&mut inner) {
                return Notification::default();
            }
            inner.target_waker.take()
        };
        Notification {
            state: Some(self.clone()),
            wake,
        }
    }
}

pub(crate) fn validate_adaptive(extensions: &Extensions, adaptive: bool) -> Result<(), Error> {
    if adaptive && extensions.contains::<ReceiveInitialCredit>() {
        return Err(Error::User(UserError::InitialCreditConfiguration));
    }
    Ok(())
}

pub(super) fn validate_receive_config(
    extensions: &Extensions,
    target: Option<u32>,
    replayed_connection_update: bool,
) -> Result<(), Error> {
    if extensions.contains::<ReceiveInitialCredit>()
        && (target.is_some_and(|target| target != DEFAULT_INITIAL_WINDOW_SIZE)
            || replayed_connection_update)
    {
        return Err(Error::User(UserError::InitialCreditConfiguration));
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(super) struct Bindings {
    pub(super) source: Option<Source>,
    pub(super) target: Option<Target>,
}

impl Bindings {
    pub(super) fn bind(extensions: &Extensions) -> Result<Self, Error> {
        let source = extensions.get_ref::<PeerInitialCredit>();
        let target = extensions.get_ref::<ReceiveInitialCredit>();
        if let (Some(source), Some(target)) = (source, target)
            && Arc::ptr_eq(&source.state, &target.state)
        {
            return Err(Error::User(UserError::InitialCreditConfiguration));
        }
        let source = source
            .map(|source| {
                {
                    let mut inner = source.state.inner.lock();
                    if inner.source_claimed {
                        return Err(Error::User(UserError::InitialCreditConfiguration));
                    }
                    inner.source_claimed = true;
                    inner.status = Status::Observing {
                        target: DEFAULT_INITIAL_WINDOW_SIZE,
                    };
                }
                source.state.complete.notify_waiters();
                Ok(Source {
                    state: source.state.clone(),
                    data_committed: false,
                })
            })
            .transpose()?;
        let target = target
            .map(|target| {
                let mut inner = target.state.inner.lock();
                if inner.target_claimed {
                    return Err(Error::User(UserError::InitialCreditConfiguration));
                }
                if let Status::Failed { reason, .. } = inner.status {
                    return Err(Error::User(UserError::InitialCreditUnavailable(reason)));
                }
                inner.target_claimed = true;
                Ok(Target {
                    state: target.state.clone(),
                    applied: DEFAULT_INITIAL_WINDOW_SIZE,
                    maximum: target.maximum,
                })
            })
            .transpose()?;
        Ok(Self { source, target })
    }
}

#[derive(Debug)]
pub(super) struct Source {
    state: Arc<State>,
    data_committed: bool,
}

impl Source {
    pub(super) fn increment(&self, increment: u32) -> Notification {
        self.state.publish(|inner| {
            let Status::Observing { target } = inner.status else {
                return false;
            };
            inner.status = if self.data_committed {
                Status::Failed {
                    target,
                    reason: Failure::DataCreditBeforeInitialHeaders,
                }
            } else if let Some(target) = target
                .checked_add(increment)
                .filter(|value| *value <= MAX_WINDOW_SIZE)
            {
                Status::Observing { target }
            } else {
                // Native send-flow validation should already reject this path.
                // Observation alone never alters the ordinary source result.
                Status::Failed {
                    target,
                    reason: Failure::NativeError,
                }
            };
            true
        })
    }

    pub(super) fn data_committed(&mut self, len: u32) {
        self.data_committed |= len != 0;
    }

    pub(super) fn headers(&self, accepted: bool) -> Notification {
        self.state.publish(|inner| {
            let Status::Observing { target } = inner.status else {
                return false;
            };
            inner.status = if accepted {
                Status::Complete { target }
            } else {
                Status::Failed {
                    target,
                    reason: Failure::InitialHeadersNotAccepted,
                }
            };
            true
        })
    }

    pub(super) fn fail(&self, reason: Failure) -> Notification {
        self.state.publish(|inner| {
            let Status::Observing { target } = inner.status else {
                return false;
            };
            inner.status = Status::Failed { target, reason };
            true
        })
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        // Established-connection EOF seals the source outside native locks.
        // HEADERS consumes this owner only after publishing its terminal state;
        // setup/cancellation drops have not entered a native Streams lock.
        self.fail(Failure::ClosedBeforeInitialHeaders).dispatch();
    }
}

#[derive(Debug)]
pub(super) struct Target {
    state: Arc<State>,
    pub(super) applied: u32,
    maximum: u32,
}

impl Target {
    pub(super) fn pending(&self, cx: &Context<'_>) -> Result<Option<(u32, u32)>, Error> {
        let mut inner = self.state.inner.lock();
        let target = match inner.status {
            Status::Unbound => None,
            Status::Observing { target } | Status::Complete { target } => Some(target),
            Status::Failed { reason, .. } => {
                return Err(Error::User(UserError::InitialCreditUnavailable(reason)));
            }
        };
        if let Some(target) = target
            && target > self.maximum
        {
            return Err(Error::User(UserError::InitialCreditLimitExceeded {
                target,
                maximum: self.maximum,
            }));
        }
        if !matches!(
            inner.status,
            Status::Complete { .. } | Status::Failed { .. }
        ) && inner
            .target_waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            inner.target_waker = Some(cx.waker().clone());
        }
        let Some(target) = target else {
            return Ok(None);
        };
        let delta = target
            .checked_sub(self.applied)
            .ok_or_else(|| Error::User(UserError::InitialCreditConfiguration))?;
        Ok((delta != 0).then_some((target, delta)))
    }

    pub(super) fn committed(&mut self, target: u32) {
        self.applied = target;
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.state.inner.lock().target_waker = None;
    }
}

#[cfg(test)]
mod tests;
