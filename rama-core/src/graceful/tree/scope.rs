use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::time::Instant;

use super::{
    cause::Cause,
    join::JoinAborted,
    node::{Node, Target, Wait},
    signal::default_signal,
    sync::Arc,
};

/// A node in a cancellation tree, held strongly.
///
/// A scope is first cancelled (graceful phase: stop taking new work, finish what runs) and
/// then aborted (hard phase: stop now); aborted implies cancelled. Both phases flow from a
/// parent to its children, never upwards, and the earliest cause wins.
///
/// Every holder keeps the drain of this scope and its ancestors open, see
/// [`Scope::join`]; a [`WeakScope`] observes without holding. Dropping a scope cancels
/// nothing.
///
/// The `with_*` methods change the node itself, so every clone sees them; they only ever
/// move a phase earlier.
pub struct Scope {
    node: Option<Arc<Node>>,
}

/// A [`Scope`] handle that observes without holding the drain open.
#[derive(Clone)]
pub struct WeakScope {
    node: Option<Arc<Node>>,
}

impl Scope {
    /// Create a standalone root scope, active until cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            node: Some(Arc::new(Node::new_held(None))),
        }
    }

    /// Create a scope that is never cancelled.
    #[must_use]
    pub const fn never() -> Self {
        Self { node: None }
    }

    #[cfg(test)]
    pub(super) fn node(&self) -> Option<&Arc<Node>> {
        self.node.as_ref()
    }

    /// Create a child scope: cancelled when this scope is, never the other way around.
    ///
    /// The child of [`Scope::never`] is a new root.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            node: Some(Arc::new(Node::new_held(self.node.clone()))),
        }
    }

    fn or_root(self) -> Self {
        if self.node.is_some() {
            self
        } else {
            Self::new()
        }
    }

    /// Cancel this scope once `timeout` passed, counted from now.
    #[must_use]
    pub fn with_timeout(self, timeout: Duration) -> Self {
        self.with_deadline(Instant::now() + timeout)
    }

    /// Cancel this scope at `deadline`; a deadline in the past counts from now.
    #[must_use]
    pub fn with_deadline(self, deadline: Instant) -> Self {
        let scope = self.or_root();
        if let Some(node) = &scope.node {
            node.tighten_deadline(false, deadline);
        }
        scope
    }

    /// Abort this scope once `timeout` passed, counted from now.
    #[must_use]
    pub fn with_hard_timeout(self, timeout: Duration) -> Self {
        self.with_hard_deadline(Instant::now() + timeout)
    }

    /// Abort this scope at `deadline`; a deadline in the past counts from now.
    #[must_use]
    pub fn with_hard_deadline(self, deadline: Instant) -> Self {
        let scope = self.or_root();
        if let Some(node) = &scope.node {
            node.tighten_deadline(true, deadline);
        }
        scope
    }

    /// Abort this scope `grace` after it is cancelled, for any cause.
    #[must_use]
    pub fn with_grace(self, grace: Duration) -> Self {
        let scope = self.or_root();
        if let Some(node) = &scope.node {
            node.tighten_grace(grace);
        }
        scope
    }

    /// Cancel this scope when `signal` completes.
    ///
    /// The signal is polled by futures waiting on this scope or its children, never by a
    /// spawned task; until one of them observed its completion, [`Scope::is_cancelled`]
    /// does not report it.
    #[must_use]
    pub fn with_signal<F>(self, signal: F) -> Self
    where
        F: Future + Send + 'static,
    {
        let scope = self.or_root();
        if let Some(node) = &scope.node {
            node.add_signal(
                false,
                Box::pin(async move {
                    let _output = signal.await;
                }),
            );
        }
        scope
    }

    /// Cancel this scope on Ctrl+C, SIGTERM or the platform's equivalent, see [`default_signal`].
    #[must_use]
    pub fn with_default_signal(self) -> Self {
        self.with_signal(default_signal())
    }

    /// Abort this scope when `signal` completes, polled as for [`Scope::with_signal`].
    #[must_use]
    pub fn with_hard_signal<F>(self, signal: F) -> Self
    where
        F: Future + Send + 'static,
    {
        let scope = self.or_root();
        if let Some(node) = &scope.node {
            node.add_signal(
                true,
                Box::pin(async move {
                    let _output = signal.await;
                }),
            );
        }
        scope
    }

    /// Cancel this scope; the first cause is kept. No effect on [`Scope::never`].
    pub fn cancel(&self, cause: Cause) {
        if let Some(node) = &self.node {
            node.cancel(cause);
        }
    }

    /// Abort this scope, which also cancels it. No effect on [`Scope::never`].
    pub fn abort(&self, cause: Cause) {
        if let Some(node) = &self.node {
            node.abort(cause);
        }
    }

    /// Run `future` until this scope is cancelled: `None` once it is, the output otherwise.
    ///
    /// Cancellation is checked first, so a cancelled scope never polls `future`.
    pub fn run_until_cancelled<F: Future>(
        &self,
        future: F,
    ) -> impl Future<Output = Option<F::Output>> + use<F> {
        let cancelled = self.cancelled();
        async move {
            tokio::select! {
                biased;
                () = cancelled => None,
                output = future => Some(output),
            }
        }
    }

    /// Run `future` until this scope is aborted: `None` once it is, the output otherwise.
    ///
    /// Abort is checked first, so an aborted scope never polls `future`.
    pub fn run_until_aborted<F: Future>(
        &self,
        future: F,
    ) -> impl Future<Output = Option<F::Output>> + use<F> {
        let aborted = self.aborted();
        async move {
            tokio::select! {
                biased;
                () = aborted => None,
                output = future => Some(output),
            }
        }
    }

    /// Give up this hold and wait until no holder of this scope or its subtree is left.
    ///
    /// Returns the time waited; from then on the scope is closed and [`WeakScope::upgrade`]
    /// fails. Returns [`JoinAborted`] as soon as the scope is aborted, even when holders
    /// remain; await [`WeakScope::drained`] for their end. [`Scope::never`] tracks no holders,
    /// so it returns at once and is never closed: upgrading it keeps giving [`Scope::never`].
    pub async fn join(self) -> Result<Duration, JoinAborted> {
        let start = Instant::now();
        let Some(node) = self.node.clone() else {
            return Ok(Duration::ZERO);
        };
        let weak = self.clone_weak();
        drop(self);

        loop {
            if node.close_if_drained() {
                return Ok(start.elapsed());
            }
            if node.phase().hard {
                return Err(JoinAborted::new(start.elapsed(), weak.abort_cause()));
            }
            tokio::select! {
                () = weak.drained() => {}
                () = weak.aborted() => {}
            }
        }
    }

    /// Future that completes once this scope is cancelled (or aborted).
    pub fn cancelled(&self) -> Cancelled {
        Cancelled(Wait::new(self.node.clone(), Target::Graceful))
    }

    /// Future that completes once this scope is aborted.
    pub fn aborted(&self) -> Aborted {
        Aborted(Wait::new(self.node.clone(), Target::Hard))
    }

    /// Future that completes once no strong holder is left in this scope's subtree.
    ///
    /// Holding this scope keeps it from completing. [`Scope::never`] tracks no holders, so
    /// its drain is complete at once.
    pub fn drained(&self) -> Drained {
        Drained(Wait::new(self.node.clone(), Target::Drained))
    }

    /// Whether this scope is cancelled (or aborted).
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.node
            .as_deref()
            .is_some_and(|node| node.phase().graceful)
    }

    /// Whether this scope is aborted.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.node.as_deref().is_some_and(|node| node.phase().hard)
    }

    /// Why this scope is cancelled, if it is.
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        self.node.as_deref().and_then(|node| node.causes().0)
    }

    /// Why this scope is aborted, if it is.
    #[must_use]
    pub fn abort_cause(&self) -> Option<Cause> {
        self.node.as_deref().and_then(|node| node.causes().1)
    }

    /// Turn this into a [`WeakScope`].
    #[must_use]
    pub fn downgrade(self) -> WeakScope {
        self.clone_weak()
    }

    /// Get a [`WeakScope`] for the same node.
    #[must_use]
    pub fn clone_weak(&self) -> WeakScope {
        WeakScope {
            node: self.node.clone(),
        }
    }
}

impl WeakScope {
    /// Hold the scope again: refused once it is closed, and once it has no holder left while
    /// cancelled (that closes it).
    #[must_use]
    pub fn upgrade(self) -> Option<Scope> {
        match self.node {
            Some(node) => node.try_retain().then(|| Scope { node: Some(node) }),
            None => Some(Scope::never()),
        }
    }

    /// See [`Scope::cancel`].
    pub fn cancel(&self, cause: Cause) {
        if let Some(node) = &self.node {
            node.cancel(cause);
        }
    }

    /// See [`Scope::abort`].
    pub fn abort(&self, cause: Cause) {
        if let Some(node) = &self.node {
            node.abort(cause);
        }
    }

    /// See [`Scope::cancelled`].
    pub fn cancelled(&self) -> Cancelled {
        Cancelled(Wait::new(self.node.clone(), Target::Graceful))
    }

    /// See [`Scope::aborted`].
    pub fn aborted(&self) -> Aborted {
        Aborted(Wait::new(self.node.clone(), Target::Hard))
    }

    /// See [`Scope::drained`].
    pub fn drained(&self) -> Drained {
        Drained(Wait::new(self.node.clone(), Target::Drained))
    }

    /// See [`Scope::is_cancelled`].
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.node
            .as_deref()
            .is_some_and(|node| node.phase().graceful)
    }

    /// See [`Scope::is_aborted`].
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.node.as_deref().is_some_and(|node| node.phase().hard)
    }

    /// See [`Scope::cause`].
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        self.node.as_deref().and_then(|node| node.causes().0)
    }

    /// See [`Scope::abort_cause`].
    #[must_use]
    pub fn abort_cause(&self) -> Option<Cause> {
        self.node.as_deref().and_then(|node| node.causes().1)
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::never()
    }
}

impl Clone for Scope {
    fn clone(&self) -> Self {
        if let Some(node) = &self.node {
            node.retain_held();
        }
        Self {
            node: self.node.clone(),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(node) = &self.node {
            node.release();
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_scope(f, "Scope", self.node.as_deref())
    }
}

impl fmt::Debug for WeakScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_scope(f, "WeakScope", self.node.as_deref())
    }
}

fn debug_scope(f: &mut fmt::Formatter<'_>, name: &str, node: Option<&Node>) -> fmt::Result {
    match node {
        Some(node) => {
            let phase = node.phase();
            f.debug_struct(name)
                .field("cancelled", &phase.graceful)
                .field("aborted", &phase.hard)
                .field("strong", &node.strong_count())
                .finish()
        }
        None => f.debug_struct(name).field("never", &true).finish(),
    }
}

macro_rules! wait_future {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[must_use = "futures do nothing unless polled"]
        pub struct $name(Wait);

        impl Future for $name {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                Pin::new(&mut self.0).poll(cx)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

wait_future! {
    /// Future returned by [`Scope::cancelled`]; cancel safe.
    Cancelled
}

wait_future! {
    /// Future returned by [`Scope::aborted`]; cancel safe.
    Aborted
}

wait_future! {
    /// Future returned by [`Scope::drained`]; cancel safe.
    Drained
}
