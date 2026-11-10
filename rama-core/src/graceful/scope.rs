use std::{
    any::Any,
    collections::BTreeSet,
    fmt,
    future::Future,
    mem::{self, ManuallyDrop},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};
use tokio::time::Instant;

use super::{
    cause::Cause,
    context::ScopeClosed,
    join::{JoinAborted, Joined},
    node::{Node, Signal, Target, Wait},
    signal::default_signal,
    sync::{Arc, AtomicU8, Mutex, Ordering, yield_point},
};

pin_project_lite::pin_project! {
    /// `future` raced against `stop`, which is polled first.
    ///
    /// A plain future rather than an async block around `select!`:
    /// that one keeps `future` twice, doubling every spawned task.
    struct RunUntil<S, F> {
        #[pin]
        stop: S,
        #[pin]
        future: F,
    }
}

impl<S: Future<Output = ()>, F: Future> Future for RunUntil<S, F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if this.stop.poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        this.future.poll(cx).map(Some)
    }
}

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
/// [`Scope::child_of`] makes one scope below several parents: it ends when any of them does,
/// and holds each of them.
///
/// The `with_*` methods change the nodes themselves, so every clone sees them; they only
/// ever move a phase earlier.
pub struct Scope {
    nodes: Nodes,
}

/// A [`Scope`] handle that observes without holding the drain open.
#[derive(Clone)]
pub struct WeakScope {
    nodes: Nodes,
}

/// The nodes a handle refers to: none (detached), one, or the children of a scope made below
/// several parents.
#[derive(Clone)]
enum Nodes {
    Detached,
    One(Arc<Node>),
    Many(std::sync::Arc<Composite>),
}

/// A scope below several parents: one child per parent, and the phases it was first seen in.
struct Composite {
    nodes: Box<[Arc<Node>]>,
    /// The composites this one was made from: their fixed facts are its inherited ones.
    parents: Box<[std::sync::Arc<Self>]>,
    // Fixed once observed, so every clone reports the same phase instant and cause.
    facts: Mutex<Facts>,
    /// Which facts are fixed ([`GRACEFUL`], [`HARD`]), readable without the lock.
    fixed: AtomicU8,
}

const GRACEFUL: u8 = 1;
const HARD: u8 = 2;

const fn fact_bit(hard: bool) -> u8 {
    if hard { HARD } else { GRACEFUL }
}

/// When a phase was reached and why.
type Fact = Option<(Instant, Cause)>;

#[derive(Default)]
struct Facts {
    graceful: Option<(Instant, Cause)>,
    hard: Option<(Instant, Cause)>,
}

impl Scope {
    /// Create a standalone root scope, active until cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Nodes::One(Arc::new(Node::new_held(None))),
        }
    }

    /// Create a detached scope: never cancelled, and no join waits for work in it.
    #[must_use]
    pub const fn detached() -> Self {
        Self {
            nodes: Nodes::Detached,
        }
    }

    #[cfg(test)]
    pub(super) fn node(&self) -> Option<&Arc<Node>> {
        match &self.nodes {
            Nodes::One(node) => Some(node),
            Nodes::Detached | Nodes::Many(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn parts(&self) -> &[Arc<Node>] {
        self.nodes.as_slice()
    }

    /// Whether this is [`Scope::detached`], which tracks nothing and is never cancelled.
    #[must_use]
    pub const fn is_detached(&self) -> bool {
        matches!(self.nodes, Nodes::Detached)
    }

    /// Create a child scope: cancelled when this scope is, never the other way around.
    ///
    /// The child of [`Scope::detached`] is a new root.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            nodes: Nodes::children_of(self.nodes.clone()),
        }
    }

    /// Create a scope below all of `parents`: cancelled or aborted as soon as any of them is,
    /// and holding each of them, so the [`Scope::join`] of every parent waits for it.
    ///
    /// Its own phases, holds and builders are those of the new scope only, never of the
    /// parents. A parent that is an ancestor of another parent adds nothing, and neither does
    /// [`Scope::detached`]; without any other parent the new scope is a root.
    #[must_use]
    pub fn child_of<'a>(parents: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut parents: Vec<&Nodes> = parents
            .into_iter()
            .map(|parent| &parent.nodes)
            .filter(|nodes| !matches!(nodes, Nodes::Detached))
            .collect();
        let nodes = if parents.len() <= 1 {
            Nodes::children_of(parents.pop().cloned().unwrap_or(Nodes::Detached))
        } else {
            let (nodes, composites) = Nodes::merged(parents);
            Nodes::children_of_parts(nodes, composites)
        };
        Self { nodes }
    }

    fn make_root(&mut self) {
        if self.is_detached() {
            *self = Self::new();
        }
    }

    generate_set_and_with! {
        /// Cancel this scope once `timeout` passed, counted from now.
        #[no_unset]
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.maybe_set_deadline(timeout.map(|timeout| Instant::now() + timeout));
            self
        }
    }

    generate_set_and_with! {
        /// Cancel this scope at `deadline`; a deadline in the past counts from now.
        #[no_unset]
        pub fn deadline(mut self, deadline: Option<Instant>) -> Self {
            if let Some(deadline) = deadline {
                self.make_root();
                self.nodes
                    .for_each(|node| node.tighten_deadline(false, deadline));
            }
            self
        }
    }

    generate_set_and_with! {
        /// Abort this scope once `timeout` passed, counted from now.
        #[no_unset]
        pub fn hard_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.maybe_set_hard_deadline(timeout.map(|timeout| Instant::now() + timeout));
            self
        }
    }

    generate_set_and_with! {
        /// Abort this scope at `deadline`; a deadline in the past counts from now.
        #[no_unset]
        pub fn hard_deadline(mut self, deadline: Option<Instant>) -> Self {
            if let Some(deadline) = deadline {
                self.make_root();
                self.nodes
                    .for_each(|node| node.tighten_deadline(true, deadline));
            }
            self
        }
    }

    generate_set_and_with! {
        /// Abort this scope `grace` after it is cancelled, for any cause.
        #[no_unset]
        pub fn grace(mut self, grace: Option<Duration>) -> Self {
            if let Some(grace) = grace {
                self.make_root();
                self.nodes.for_each(|node| node.tighten_grace(grace));
            }
            self
        }
    }

    generate_set_and_with! {
        /// Cancel this scope when `signal` completes.
        ///
        /// The signal is polled by futures waiting on this scope or its children, never by a
        /// spawned task; until one of them observed its completion, [`Scope::is_cancelled`]
        /// does not report it.
        pub fn signal(mut self, signal: impl Future + Send + 'static) -> Self {
            self.make_root();
            self.nodes.add_signal(false, signal);
            self
        }
    }

    generate_set_and_with! {
        /// Cancel this scope `delay` after `signal` completes, as [`Scope::with_signal`] does
        /// once the delay passed. Ancestor phases and hard limits still apply at once.
        pub fn delayed_signal(
            mut self,
            signal: impl Future + Send + 'static,
            delay: Duration,
        ) -> Self {
            self.set_signal(async move {
                drop(signal.await);
                tokio::time::sleep(delay).await;
            });
            self
        }
    }

    generate_set_and_with! {
        /// Cancel this scope on Ctrl+C, SIGTERM or the platform's equivalent, see [`default_signal`].
        pub fn default_signal(mut self) -> Self {
            self.set_signal(default_signal());
            self
        }
    }

    generate_set_and_with! {
        /// Abort this scope when `signal` completes, polled as for [`Scope::with_signal`].
        pub fn hard_signal(mut self, signal: impl Future + Send + 'static) -> Self {
            self.make_root();
            self.nodes.add_signal(true, signal);
            self
        }
    }

    /// Cancel this scope; the first cause is kept. No effect on [`Scope::detached`].
    pub fn cancel(&self, cause: Cause) {
        self.nodes.cancel(cause);
    }

    /// Abort this scope, which also cancels it. No effect on [`Scope::detached`].
    pub fn abort(&self, cause: Cause) {
        self.nodes.abort(cause);
    }

    /// Run `future` until this scope is cancelled: `None` once it is, the output otherwise.
    ///
    /// Cancellation is checked first, so a cancelled scope never polls `future`.
    pub fn run_until_cancelled<F: Future>(
        &self,
        future: F,
    ) -> impl Future<Output = Option<F::Output>> + use<F> {
        RunUntil {
            stop: self.cancelled(),
            future,
        }
    }

    /// Run `future` until this scope is aborted: `None` once it is, the output otherwise.
    ///
    /// Abort is checked first, so an aborted scope never polls `future`.
    pub fn run_until_aborted<F: Future>(
        &self,
        future: F,
    ) -> impl Future<Output = Option<F::Output>> + use<F> {
        RunUntil {
            stop: self.aborted(),
            future,
        }
    }

    /// Give up this hold and wait until no holder of this scope or its subtree is left.
    ///
    /// Returns once drained, even when the scope was never cancelled: work already done
    /// leaves nothing to wait for. From then on the scope is closed and
    /// [`WeakScope::into_scope`] fails; a scope made by [`Scope::child_of`] is closed as a
    /// whole once any of its parts is. Returns [`JoinAborted`] as soon as the scope is
    /// aborted, even when holders remain; await [`WeakScope::drained`] for their end.
    /// [`Scope::detached`] tracks no holders, so it returns at once and is never closed:
    /// upgrading it keeps giving [`Scope::detached`]. See [`Scope::join_once_cancelled`] to
    /// wait for the cancel first.
    pub async fn join(self) -> Result<Joined, JoinAborted> {
        let start = Instant::now();
        if self.is_detached() {
            return Ok(Joined::new(Duration::ZERO, None));
        }
        let weak = self.clone_weak();
        drop(self);

        loop {
            if weak.nodes.close_if_drained() {
                return Ok(Joined::new(start.elapsed(), weak.cause()));
            }
            if weak.is_aborted() {
                return Err(JoinAborted::new(start.elapsed(), weak.abort_cause()));
            }
            // Biased: both arms only wake the loop, which rechecks everything.
            tokio::select! {
                biased;
                () = weak.drained() => {}
                () = weak.aborted() => {}
            }
        }
    }

    /// Wait until this scope is cancelled, then [`Scope::join`] it: the shutdown of a root
    /// whose work may end before it is cancelled. Never returns for [`Scope::detached`].
    pub async fn join_once_cancelled(self) -> Result<Joined, JoinAborted> {
        self.cancelled().await;
        self.join().await
    }

    /// Future that completes once this scope is cancelled (or aborted).
    #[inline]
    pub fn cancelled(&self) -> Cancelled {
        Cancelled(Waits::new(&self.nodes, Target::Graceful))
    }

    /// Future that completes once this scope is aborted.
    #[inline]
    pub fn aborted(&self) -> Aborted {
        Aborted(Waits::new(&self.nodes, Target::Hard))
    }

    /// Future that completes once no strong holder is left in this scope's subtree.
    ///
    /// Holding this scope keeps it from completing. [`Scope::detached`] tracks no holders, so
    /// its drain is complete at once.
    #[inline]
    pub fn drained(&self) -> Drained {
        Drained(Waits::new(&self.nodes, Target::Drained))
    }

    /// Whether this scope is cancelled (or aborted).
    #[inline]
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.nodes.is_cancelled()
    }

    /// Whether this scope is aborted.
    #[inline]
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.nodes.is_aborted()
    }

    /// Why this scope is cancelled, if it is: for a scope made by [`Scope::child_of`], the
    /// earliest cause, fixed once observed.
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        self.nodes.cause(false)
    }

    /// Why this scope is aborted, if it is, as for [`Scope::cause`].
    #[must_use]
    pub fn abort_cause(&self) -> Option<Cause> {
        self.nodes.cause(true)
    }

    /// Turn this into a [`WeakScope`], giving up this hold.
    #[must_use]
    pub fn into_weak_scope(self) -> WeakScope {
        self.clone_weak()
    }

    /// Get a [`WeakScope`] for the same nodes.
    #[must_use]
    pub fn clone_weak(&self) -> WeakScope {
        WeakScope {
            nodes: self.nodes.clone(),
        }
    }
}

impl WeakScope {
    /// The weak handle of [`Scope::detached`]: work outside any shutdown, never cancelled.
    #[must_use]
    pub const fn detached() -> Self {
        Self {
            nodes: Nodes::Detached,
        }
    }

    /// Hold the scope, as [`WeakScope::into_scope`] does, keeping this handle: the one fallible
    /// step before starting work in it.
    ///
    /// # Errors
    ///
    /// [`ScopeClosed`] once the scope is closed.
    pub fn try_hold(&self) -> Result<Scope, ScopeClosed> {
        self.clone().into_scope().ok_or(ScopeClosed)
    }

    /// Hold the scope again: refused once it is closed, and once it has no holder left while
    /// cancelled (that closes it). A scope made by [`Scope::child_of`] is held again only as a
    /// whole.
    #[must_use]
    pub fn into_scope(self) -> Option<Scope> {
        let held = match &self.nodes {
            Nodes::Detached => true,
            Nodes::One(node) => node.try_retain(),
            Nodes::Many(composite) => composite.try_retain(),
        };
        // Built only once held: dropping a scope gives up a hold.
        if held {
            Some(Scope { nodes: self.nodes })
        } else {
            None
        }
    }

    /// The deepest of `scopes` on each lineage, observed as one: what an input runs in.
    pub(super) fn fold(scopes: impl IntoIterator<Item = Self>) -> Self {
        let mut scopes: Vec<Self> = scopes.into_iter().collect();
        if scopes.len() == 1
            && let Some(scope) = scopes.pop()
        {
            return scope;
        }
        let (nodes, composites) = Nodes::merged(scopes.iter().map(|scope| &scope.nodes));
        Self {
            nodes: Nodes::from_nodes(nodes, composites),
        }
    }

    /// See [`Scope::cancel`].
    pub fn cancel(&self, cause: Cause) {
        self.nodes.cancel(cause);
    }

    /// See [`Scope::abort`].
    pub fn abort(&self, cause: Cause) {
        self.nodes.abort(cause);
    }

    /// See [`Scope::cancelled`].
    #[inline]
    pub fn cancelled(&self) -> Cancelled {
        Cancelled(Waits::new(&self.nodes, Target::Graceful))
    }

    /// See [`Scope::aborted`].
    #[inline]
    pub fn aborted(&self) -> Aborted {
        Aborted(Waits::new(&self.nodes, Target::Hard))
    }

    /// See [`Scope::drained`].
    #[inline]
    pub fn drained(&self) -> Drained {
        Drained(Waits::new(&self.nodes, Target::Drained))
    }

    /// See [`Scope::is_cancelled`].
    #[inline]
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.nodes.is_cancelled()
    }

    /// See [`Scope::is_aborted`].
    #[inline]
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.nodes.is_aborted()
    }

    /// See [`Scope::cause`].
    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        self.nodes.cause(false)
    }

    /// See [`Scope::abort_cause`].
    #[must_use]
    pub fn abort_cause(&self) -> Option<Cause> {
        self.nodes.cause(true)
    }

    /// See [`Scope::is_detached`].
    #[must_use]
    pub const fn is_detached(&self) -> bool {
        matches!(self.nodes, Nodes::Detached)
    }
}

impl Nodes {
    fn as_slice(&self) -> &[Arc<Node>] {
        match self {
            Self::Detached => &[],
            Self::One(node) => std::slice::from_ref(node),
            Self::Many(composite) => &composite.nodes,
        }
    }

    /// The nodes of all of `groups` as one, normalized, and the composites among them, whose
    /// fixed facts a scope made of those nodes inherits.
    fn merged<'a>(
        groups: impl IntoIterator<Item = &'a Self>,
    ) -> (Vec<Arc<Node>>, Vec<std::sync::Arc<Composite>>) {
        let mut nodes = Vec::new();
        let mut composites = Vec::new();
        for group in groups {
            nodes.extend_from_slice(group.as_slice());
            if let Self::Many(composite) = group {
                composites.push(composite.clone());
            }
        }
        (Self::normalized(nodes), composites)
    }

    /// Drops repeated nodes and ancestors of other nodes; what remains is the deepest node of
    /// each lineage.
    fn normalized(nodes: Vec<Arc<Node>>) -> Vec<Arc<Node>> {
        let mut kept: Vec<Arc<Node>> = Vec::with_capacity(nodes.len());
        for node in nodes {
            if kept
                .iter()
                .any(|other| Arc::ptr_eq(other, &node) || is_ancestor(&node, other))
            {
                continue;
            }
            kept.retain(|other| !is_ancestor(other, &node));
            kept.push(node);
        }
        kept
    }

    fn from_nodes(mut nodes: Vec<Arc<Node>>, parents: Vec<std::sync::Arc<Composite>>) -> Self {
        match nodes.len() {
            0 => Self::Detached,
            1 => nodes.pop().map_or(Self::Detached, Self::One),
            _ => Self::Many(std::sync::Arc::new(Composite {
                nodes: nodes.into(),
                parents: parents.into(),
                facts: Mutex::new(Facts::default()),
                fixed: AtomicU8::new(0),
            })),
        }
    }

    /// One new held child below each of `parents`; a root without any.
    fn children_of(parents: Self) -> Self {
        match parents {
            Self::Detached => Self::One(held_child(None)),
            Self::One(parent) => Self::One(held_child(Some(parent))),
            Self::Many(composite) => {
                let nodes = composite.nodes.to_vec();
                Self::children_of_parts(nodes, vec![composite])
            }
        }
    }

    /// One new held child below each of `nodes`, inheriting the facts of `composites`.
    fn children_of_parts(
        nodes: Vec<Arc<Node>>,
        composites: Vec<std::sync::Arc<Composite>>,
    ) -> Self {
        match nodes.len() {
            0 => Self::One(held_child(None)),
            _ => Self::from_nodes(
                nodes
                    .into_iter()
                    .map(|parent| held_child(Some(parent)))
                    .collect(),
                composites,
            ),
        }
    }

    /// Closes every node once all of them are drained; `false` while any holder is left.
    fn close_if_drained(&self) -> bool {
        match self {
            Self::Detached => true,
            Self::One(node) => node.close_if_drained(),
            // Closed only once all parts are drained; a part revived meanwhile stops the
            // closing, and the parts closed before it already close the whole.
            Self::Many(composite) => {
                composite.nodes.iter().all(|node| node.strong_count() == 0)
                    && composite.nodes.iter().all(|node| node.close_if_drained())
            }
        }
    }

    fn add_signal<F>(&self, hard: bool, signal: F)
    where
        F: Future + Send + 'static,
    {
        let signal: Signal = Box::pin(async move {
            let _output = signal.await;
        });
        match self {
            Self::Detached => {}
            Self::One(node) => node.add_signal(hard, signal),
            Self::Many(composite) => {
                // One root drives the signal once; every part follows its phase.
                let trigger = Scope::new().with_signal(signal).into_weak_scope();
                for node in &composite.nodes {
                    node.add_signal(hard, Box::pin(trigger.cancelled()));
                }
            }
        }
    }

    fn cancel(&self, cause: Cause) {
        match self {
            Self::Detached => {}
            Self::One(node) => node.cancel(cause),
            Self::Many(composite) => {
                for_each_node(&composite.nodes, |node| node.cancel(cause.clone()))
            }
        }
    }

    fn abort(&self, cause: Cause) {
        match self {
            Self::Detached => {}
            Self::One(node) => node.abort(cause),
            Self::Many(composite) => {
                for_each_node(&composite.nodes, |node| node.abort(cause.clone()))
            }
        }
    }

    /// Runs `change` on every node; see [`for_each_node`] for a composite.
    fn for_each(&self, change: impl Fn(&Node)) {
        match self {
            Self::Detached => {}
            Self::One(node) => change(node),
            Self::Many(composite) => for_each_node(&composite.nodes, change),
        }
    }

    #[inline]
    fn is_cancelled(&self) -> bool {
        match self {
            Self::Detached => false,
            Self::One(node) => node.phase().graceful(),
            Self::Many(composite) => composite.fact(false).is_some(),
        }
    }

    #[inline]
    fn is_aborted(&self) -> bool {
        match self {
            Self::Detached => false,
            Self::One(node) => node.phase().hard(),
            Self::Many(composite) => composite.fact(true).is_some(),
        }
    }

    fn cause(&self, hard: bool) -> Option<Cause> {
        match self {
            Self::Detached => None,
            Self::One(node) => {
                let (graceful, hard_cause) = node.causes();
                if hard { hard_cause } else { graceful }
            }
            Self::Many(composite) => composite.fact(hard),
        }
    }
}

impl Composite {
    fn retain_held(&self) {
        for node in &self.nodes {
            node.retain_held();
        }
    }

    fn release(&self) {
        for_each_node(&self.nodes, Node::release);
    }

    /// Holds every part again, or none: a part refused (or a panic while holding one) lets go
    /// of the parts already held.
    fn try_retain(&self) -> bool {
        for (retained, node) in self.nodes.iter().enumerate() {
            match catch_unwind(AssertUnwindSafe(|| node.try_retain())) {
                Ok(true) => {}
                Ok(false) => {
                    for_each_node(&self.nodes[..retained], Node::release);
                    return false;
                }
                Err(payload) => {
                    if let Some(rollback) = each_node(&self.nodes[..retained], Node::release) {
                        dispose(rollback);
                    }
                    resume_unwind(payload);
                }
            }
        }
        true
    }

    /// The cause of the earliest phase of any part or inherited from a parent composite,
    /// fixed once seen; an inherited fact wins a tie, then the first part.
    fn fact(&self, hard: bool) -> Option<Cause> {
        if let Some((_, cause)) = self.fixed(hard) {
            return Some(cause);
        }
        self.fix_lineage(hard);
        self.fixed(hard).map(|(_, cause)| cause)
    }

    fn fixed(&self, hard: bool) -> Option<(Instant, Cause)> {
        let facts = self.facts.lock();
        if hard { &facts.hard } else { &facts.graceful }.clone()
    }

    /// Fixes this composite and every unfixed one it was made from, parents first, from one
    /// read of their parts taken children first. An ancestor publishes before its descendants,
    /// so a phase a part inherited is also seen on the parts of the composite above it, which
    /// is fixed first and handed down. A `hard` pass fixes the graceful facts too, first and
    /// from the same read: aborted implies cancelled.
    fn fix_lineage(&self, hard: bool) {
        // Read outside the facts lock: publishing a phase may run signal destructors. The parts
        // inherit every phase above them, so nothing is fixed before one of them reached it.
        let mut reached = false;
        let mut walked: SmallVec<[bool; 8]> = SmallVec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let (phase, up) = node.phase_walked();
            reached |= phase.reached(hard);
            walked.push(up);
            yield_point();
        }
        if !reached {
            return;
        }
        let read = |node: &Arc<Node>| {
            if hard {
                node.published_both_at()
            } else {
                (node.published_at(false), None)
            }
        };
        if self.parents.is_empty() {
            let parts: SmallVec<[_; 4]> = self.nodes.iter().map(read).collect();
            let _fact = self.fix_from(false, parts.iter().map(|part| part.0), None);
            if hard {
                let _fact = self.fix_from(true, parts.iter().map(|part| part.1), None);
            }
            return;
        }
        // Observing the parts of this composite publishes every node above them, the parts of
        // the composites it was made from included, so those are only read: one walk up, not
        // one per composite.
        for (node, walked) in self.nodes.iter().zip(walked) {
            if !walked {
                node.publish_up_the_chain();
            }
        }
        let lineage = self.unfixed_lineage(hard);
        // Read children first into one buffer, taken back parents first.
        let mut published: SmallVec<[(Option<Instant>, Option<Instant>); 8]> =
            SmallVec::with_capacity(lineage.iter().map(|c| c.nodes.len()).sum());
        for composite in lineage.iter().rev() {
            published.extend(composite.nodes.iter().map(read));
            yield_point();
        }
        // In a chain the parent of each composite is the one fixed just before it.
        let mut previous: Option<(&Self, Fact, Fact)> = None;
        for composite in lineage {
            let start = published.len() - composite.nodes.len();
            let parts: SmallVec<[_; 4]> = published.drain(start..).collect();
            let graceful = composite.fix_from(
                false,
                parts.iter().map(|part| part.0),
                previous.as_ref().map(|(parent, fact, _)| (*parent, fact)),
            );
            let hard_fact = if hard {
                composite.fix_from(
                    true,
                    parts.iter().map(|part| part.1),
                    previous.as_ref().map(|(parent, _, fact)| (*parent, fact)),
                )
            } else {
                None
            };
            previous = Some((composite, graceful, hard_fact));
            yield_point();
        }
    }

    /// This composite and every unfixed one it was made from, each after its parents; a walk
    /// on the heap, as composites may be made from each other to any depth.
    fn unfixed_lineage(&self, hard: bool) -> SmallVec<[&Self; 8]> {
        let mut order = SmallVec::new();
        // Only a composite with several parents lets the walk meet another twice, and then
        // only above it, so the composites met before the first such one are not recorded.
        let mut seen = None::<BTreeSet<usize>>;
        let mut stack: SmallVec<[(&Self, bool); 8]> = SmallVec::new();
        stack.push((self, false));
        while let Some((composite, expanded)) = stack.pop() {
            if expanded {
                order.push(composite);
                continue;
            }
            let first_visit = seen
                .as_mut()
                .is_none_or(|seen| seen.insert(std::ptr::from_ref(composite).addr()));
            if first_visit && !composite.is_fixed(hard) {
                if composite.parents.len() > 1 {
                    seen.get_or_insert_default();
                }
                stack.push((composite, true));
                stack.extend(composite.parents.iter().map(|parent| (&**parent, false)));
            }
        }
        order
    }

    fn is_fixed(&self, hard: bool) -> bool {
        self.fixed.load(Ordering::Acquire) & fact_bit(hard) != 0
    }

    /// Fixes the earliest of the parents' facts and the phases its parts `published` at, if
    /// any, and returns the fact now fixed; the parents are fixed before it. An inherited fact
    /// wins a tie, then the first part. `previous` is a composite fixed just before, with its
    /// fact, read instead of its lock when a parent.
    fn fix_from(
        &self,
        hard: bool,
        published: impl IntoIterator<Item = Option<Instant>>,
        previous: Option<(&Self, &Fact)>,
    ) -> Fact {
        let inherited = self
            .parents
            .iter()
            .filter_map(|parent| match previous {
                Some((composite, fact)) if std::ptr::eq(parent.as_ref(), composite) => fact.clone(),
                _ => parent.fixed(hard),
            })
            .min_by_key(|(at, _)| *at);
        let own = self
            .nodes
            .iter()
            .zip(published)
            .filter_map(|(node, at)| Some((at?, node)))
            .min_by_key(|(at, _)| *at);
        let earliest = match (inherited, own) {
            (Some(inherited), Some((at, _))) if inherited.0 <= at => Some(inherited),
            // Published, so its cause is there and never changes.
            (_, Some((_, node))) => node.published_so_far(hard),
            (inherited, None) => inherited,
        };
        let mut facts = self.facts.lock();
        let slot = if hard {
            &mut facts.hard
        } else {
            &mut facts.graceful
        };
        let fact = match earliest {
            Some(earliest) => slot.get_or_insert(earliest).clone(),
            // Fixed meanwhile by another observer, or not reached yet.
            None => return slot.clone(),
        };
        self.fixed.fetch_or(fact_bit(hard), Ordering::Release);
        Some(fact)
    }
}

impl Drop for Composite {
    fn drop(&mut self) {
        // Composites this was the last reference to go one by one, not as nested drops.
        let mut parents = mem::take(&mut self.parents).into_vec();
        while let Some(parent) = parents.pop() {
            if let Some(mut parent) = std::sync::Arc::into_inner(parent) {
                parents.append(&mut mem::take(&mut parent.parents).into_vec());
            }
        }
    }
}

fn held_child(parent: Option<Arc<Node>>) -> Arc<Node> {
    Arc::new(Node::new_held(parent))
}

/// Runs `change` on every node, then resumes the first panic; see [`each_node`].
fn for_each_node(nodes: &[Arc<Node>], change: impl Fn(&Node)) {
    if let Some(payload) = each_node(nodes, change) {
        resume_unwind(payload);
    }
}

/// Runs `change` on every node, past one that panics (a waker or a signal's destructor may),
/// and returns the first panic: a change made to a composite never stops at one of its parts.
fn each_node(nodes: &[Arc<Node>], change: impl Fn(&Node)) -> Option<Box<dyn Any + Send>> {
    let mut first = None;
    let mut later = Vec::new();
    for node in nodes {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| change(node))) {
            if first.is_none() {
                first = Some(payload);
            } else {
                later.push(payload);
            }
        }
    }
    // Only once every node is changed: a payload's destructor may panic too.
    later.into_iter().for_each(dispose);
    first
}

/// Drops a panic payload that is not resumed, and the payload of a panic its destructor
/// raises, and so on; one still panicking a few levels down is leaked instead.
fn dispose(mut payload: Box<dyn Any + Send>) {
    for _ in 0..4 {
        match catch_unwind(AssertUnwindSafe(|| drop(payload))) {
            Ok(()) => return,
            Err(nested) => payload = nested,
        }
    }
    let _leaked = Box::leak(payload);
}

/// Whether `ancestor` is a strict ancestor of `node`.
fn is_ancestor(ancestor: &Node, node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if std::ptr::eq(parent, ancestor) {
            return true;
        }
        current = parent.parent();
    }
    false
}

impl Default for Scope {
    fn default() -> Self {
        Self::detached()
    }
}

impl Default for WeakScope {
    fn default() -> Self {
        Self::detached()
    }
}

impl From<Scope> for WeakScope {
    /// Gives up the hold of `scope`.
    fn from(scope: Scope) -> Self {
        scope.into_weak_scope()
    }
}

impl From<&Scope> for WeakScope {
    fn from(scope: &Scope) -> Self {
        scope.clone_weak()
    }
}

impl From<&Self> for WeakScope {
    fn from(scope: &Self) -> Self {
        scope.clone()
    }
}

impl Clone for Scope {
    #[inline]
    fn clone(&self) -> Self {
        let nodes = match &self.nodes {
            Nodes::Detached => Nodes::Detached,
            Nodes::One(node) => {
                node.retain_held();
                Nodes::One(node.clone())
            }
            Nodes::Many(composite) => {
                composite.retain_held();
                Nodes::Many(composite.clone())
            }
        };
        Self { nodes }
    }
}

impl Drop for Scope {
    #[inline]
    fn drop(&mut self) {
        match &self.nodes {
            Nodes::Detached => {}
            Nodes::One(node) => node.release(),
            Nodes::Many(composite) => composite.release(),
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_scope(f, "Scope", &self.nodes)
    }
}

impl fmt::Debug for WeakScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_scope(f, "WeakScope", &self.nodes)
    }
}

fn debug_scope(f: &mut fmt::Formatter<'_>, name: &str, nodes: &Nodes) -> fmt::Result {
    match nodes {
        Nodes::Detached => f.debug_struct(name).field("detached", &true).finish(),
        Nodes::One(node) => {
            let phase = node.phase();
            f.debug_struct(name)
                .field("cancelled", &phase.graceful())
                .field("aborted", &phase.hard())
                .field("strong", &node.strong_count())
                .finish()
        }
        Nodes::Many(composite) => f
            .debug_struct(name)
            .field("parts", &composite.nodes.len())
            .field("cancelled", &nodes.is_cancelled())
            .field("aborted", &nodes.is_aborted())
            .finish(),
    }
}

/// The waits behind a scope future: one per node.
///
/// The first wait is inline and the rest only exist for a composite, so a single-node future
/// is built field by field in place.
struct Waits {
    first: Wait,
    // Released by `Drop for Waits`, so dropping a single-node future is one inlined check.
    rest: ManuallyDrop<Option<Box<Rest>>>,
}

/// The waits on the other parts of a composite.
struct Rest {
    waits: Box<[Wait]>,
    composite: std::sync::Arc<Composite>,
    /// The phase waited for (`true` for the hard one), fixed as the composite's fact once
    /// reached; a drain (`None`) waits for every node.
    phase: Option<bool>,
}

// The single-node paths inline into other crates; the composite paths stay out of line.
impl Waits {
    #[inline]
    fn new(nodes: &Nodes, target: Target) -> Self {
        match nodes {
            Nodes::Detached => Self {
                first: Wait::new(None, target),
                rest: ManuallyDrop::new(None),
            },
            Nodes::One(node) => Self {
                first: Wait::new(Some(node.clone()), target),
                rest: ManuallyDrop::new(None),
            },
            Nodes::Many(composite) => {
                // The boxed rest first: nothing is called after a wait is built, so no arm
                // goes through a stack copy.
                let rest = Rest::new(composite, target);
                Self {
                    first: Wait::new(composite.nodes.first().cloned(), target),
                    rest: ManuallyDrop::new(Some(rest)),
                }
            }
        }
    }

    fn drop_rest(&mut self) {
        drop(self.rest.take());
    }

    #[inline]
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let first = Pin::new(&mut self.first).poll(cx);
        match &mut *self.rest {
            None => first,
            Some(rest) => rest.poll(first, cx),
        }
    }
}

impl Drop for Waits {
    #[inline]
    fn drop(&mut self) {
        if self.rest.is_some() {
            self.drop_rest();
        }
    }
}

impl Rest {
    fn new(composite: &std::sync::Arc<Composite>, target: Target) -> Box<Self> {
        Box::new(Self {
            waits: composite.nodes[1..]
                .iter()
                .map(|node| Wait::new(Some(node.clone()), target))
                .collect(),
            composite: composite.clone(),
            phase: match target {
                Target::Graceful => Some(false),
                Target::Hard => Some(true),
                Target::Drained => None,
            },
        })
    }

    /// Combines the poll of the first wait with the others.
    fn poll(&mut self, first: Poll<()>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(hard) = self.phase {
            let reached = first.is_ready()
                || self
                    .waits
                    .iter_mut()
                    .any(|wait| Pin::new(wait).poll(cx).is_ready());
            if !reached {
                return Poll::Pending;
            }
            // Observed as reached: fixed now, as by `is_cancelled`.
            let _cause = self.composite.fact(hard);
            return Poll::Ready(());
        }
        let mut ready = usize::from(first.is_ready());
        for wait in self.waits.iter_mut() {
            if Pin::new(wait).poll(cx).is_ready() {
                ready += 1;
            }
        }
        if ready == self.waits.len() + 1 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

macro_rules! wait_future {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[must_use = "futures do nothing unless polled"]
        pub struct $name(Waits);

        impl Future for $name {
            type Output = ();

            #[inline]
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                self.0.poll(cx)
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
