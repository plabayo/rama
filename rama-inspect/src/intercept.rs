//! Bounded, typed interception waits. Protocol adapters choose messages, decisions,
//! admission costs, and timeout behavior. This module knows no traffic protocol.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama_core::futures::StreamExt;
use rama_utils::macros::error::static_str_error;
use tokio::sync::{oneshot, watch};

/// Admission costs are supplied by the adapter that owns the message representation.
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    pub messages: usize,
    pub bytes: usize,
    pub message_bytes: usize,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            messages: 128,
            bytes: rama_utils::octets::mib(8),
            message_bytes: rama_utils::octets::kib(256),
        }
    }
}

static_str_error! {
    /// interception queue is full
    #[derive(Copy)]
    pub struct QueueFull;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    Expired,
    Closed,
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Expired => "interception decision deadline expired",
            Self::Closed => "interception decision channel closed",
        })
    }
}

impl std::error::Error for WaitError {}

struct Pending<M, D> {
    message: Arc<M>,
    bytes: usize,
    reply: oneshot::Sender<D>,
}

struct State<M, D> {
    next: u64,
    bytes: usize,
    pending: BTreeMap<u64, Pending<M, D>>,
}

struct Inner<M, D> {
    state: Mutex<State<M, D>>,
    changes: watch::Sender<u64>,
}

/// Share this handle with protocol services and any GUI, TUI, or API controller.
pub struct Interception<M, D>(Arc<Inner<M, D>>);

impl<M, D> Clone for Interception<M, D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<M, D> std::fmt::Debug for Interception<M, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interception")
            .field("pending", &self.0.state.lock().pending.len())
            .finish_non_exhaustive()
    }
}

impl<M, D> Default for Interception<M, D> {
    fn default() -> Self {
        Self::with_changes(watch::channel(0).0)
    }
}

impl<M, D> Interception<M, D> {
    /// Share invalidation with a larger controller while retaining typed content APIs.
    pub fn with_changes(changes: watch::Sender<u64>) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                next: 0,
                bytes: 0,
                pending: BTreeMap::new(),
            }),
            changes,
        }))
    }

    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    fn changed(&self) {
        self.0.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn get(&self, id: u64) -> Option<Arc<M>> {
        self.0
            .state
            .lock()
            .pending
            .get(&id)
            .map(|p| p.message.clone())
    }

    pub fn entries(&self) -> Vec<(u64, Arc<M>)> {
        self.0
            .state
            .lock()
            .pending
            .iter()
            .map(|(id, p)| (*id, p.message.clone()))
            .collect()
    }

    /// Reserve admission and assign an ID atomically. The constructor runs only
    /// after admission succeeds, under the queue lock, and must not re-enter it.
    pub fn enqueue_with(
        &self,
        bytes: usize,
        limits: QueueLimits,
        make: impl FnOnce(u64) -> M,
    ) -> Result<Ticket<M, D>, QueueFull> {
        let mut state = self.0.state.lock();
        let next_bytes = state.bytes.checked_add(bytes).ok_or(QueueFull)?;
        if state.pending.len() >= limits.messages
            || bytes > limits.message_bytes
            || next_bytes > limits.bytes
        {
            return Err(QueueFull);
        }
        let id = state.next.checked_add(1).ok_or(QueueFull)?;
        let (reply, receive) = oneshot::channel();
        state.pending.insert(
            id,
            Pending {
                message: Arc::new(make(id)),
                bytes,
                reply,
            },
        );
        state.next = id;
        state.bytes = next_bytes;
        drop(state);
        self.changed();
        Ok(Ticket {
            queue: self.clone(),
            id,
            receive,
        })
    }

    pub fn enqueue(
        &self,
        message: M,
        bytes: usize,
        limits: QueueLimits,
    ) -> Result<Ticket<M, D>, QueueFull> {
        self.enqueue_with(bytes, limits, |_| message)
    }

    /// Validate and resolve under the same lock. Exactly one caller can win;
    /// failed validation leaves the message pending. The callback cannot re-enter.
    pub fn resolve_with<E>(
        &self,
        id: u64,
        decide: impl FnOnce(&M) -> Result<D, E>,
    ) -> Result<bool, E> {
        let mut state = self.0.state.lock();
        let Some(pending) = state.pending.get(&id) else {
            return Ok(false);
        };
        let decision = decide(&pending.message)?;
        if let Some(pending) = state.pending.remove(&id) {
            state.bytes -= pending.bytes;
            _ = pending.reply.send(decision);
        }
        drop(state);
        self.changed();
        Ok(true)
    }

    pub fn resolve(&self, id: u64, decision: D) -> bool {
        match self.resolve_with(id, |_| Ok::<D, std::convert::Infallible>(decision)) {
            Ok(resolved) => resolved,
            Err(never) => match never {},
        }
    }

    /// Release a group of related waits atomically, for example one connection.
    /// The callback runs under the queue lock and must not re-enter it.
    pub fn release_where(&self, mut decide: impl FnMut(&M) -> Option<D>) {
        let mut state = self.0.state.lock();
        let decisions = state
            .pending
            .iter()
            .filter_map(|(id, p)| decide(&p.message).map(|d| (*id, d)))
            .collect::<Vec<_>>();
        if decisions.is_empty() {
            return;
        }
        for (id, decision) in decisions {
            if let Some(pending) = state.pending.remove(&id) {
                state.bytes -= pending.bytes;
                _ = pending.reply.send(decision);
            }
        }
        drop(state);
        self.changed();
    }

    fn cancel(&self, id: u64) {
        let mut state = self.0.state.lock();
        let removed = state.pending.remove(&id);
        if let Some(pending) = &removed {
            state.bytes -= pending.bytes;
        }
        drop(state);
        if removed.is_some() {
            self.changed();
        }
    }
}

/// Owns a pending wait. Dropping it removes the message and releases admission.
#[must_use = "dropping a ticket cancels the interception wait"]
pub struct Ticket<M, D> {
    queue: Interception<M, D>,
    id: u64,
    receive: oneshot::Receiver<D>,
}

impl<M, D> Ticket<M, D> {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn wait(mut self, timeout: Duration) -> Result<D, WaitError> {
        match tokio::time::timeout(timeout, &mut self.receive).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(WaitError::Closed),
            Err(_) => Err(WaitError::Expired),
        }
    }
}

impl<M, D> Drop for Ticket<M, D> {
    fn drop(&mut self) {
        self.queue.cancel(self.id);
    }
}

impl<M: Send + Sync + 'static, D: Send + 'static> Interception<M, D> {
    /// Initial pending content followed by fresh views; slow consumers coalesce updates.
    pub fn subscribe(
        &self,
    ) -> impl rama_core::futures::Stream<Item = Vec<(u64, Arc<M>)>> + Send + 'static {
        let queue = self.clone();
        crate::subscription::subscribe(
            self.subscribe_changes(),
            rama_core::service::service_fn(move |()| {
                let entries = queue.entries();
                async move { Ok::<_, std::convert::Infallible>(entries) }
            }),
            (),
        )
        .map(|result| match result {
            Ok(value) => value,
            Err(never) => match never {},
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn cancellation_deadline_and_rejected_validation_release_admission() {
        let queue = Interception::<&str, bool>::default();
        let limits = QueueLimits {
            messages: 1,
            bytes: 4,
            message_bytes: 4,
        };
        let ticket = queue.enqueue("first", 4, limits).unwrap();
        let id = ticket.id();
        assert!(queue.enqueue("full", 1, limits).is_err());
        assert_eq!(
            queue.resolve_with(id, |_| Err::<bool, _>("invalid")),
            Err("invalid")
        );
        assert!(queue.get(id).is_some());
        drop(ticket);
        let ticket = queue.enqueue("next", 4, limits).unwrap();
        assert_eq!(
            ticket.wait(Duration::from_secs(1)).await,
            Err(WaitError::Expired)
        );
        assert!(queue.entries().is_empty());
        let ticket = queue.enqueue("again", 4, limits).unwrap();
        assert!(queue.resolve(ticket.id(), true));
        assert!(!queue.resolve(ticket.id(), false));
        assert_eq!(ticket.wait(Duration::from_secs(1)).await, Ok(true));
    }

    #[tokio::test]
    async fn typed_subscription_and_group_resolution() {
        let queue = Interception::<(u8, &'static str), bool>::default();
        let mut stream = Box::pin(queue.subscribe());
        assert!(stream.next().await.unwrap().is_empty());
        let a = queue
            .enqueue((1, "request"), 1, QueueLimits::default())
            .unwrap();
        let b = queue
            .enqueue((1, "response"), 1, QueueLimits::default())
            .unwrap();
        let c = queue
            .enqueue((2, "other"), 1, QueueLimits::default())
            .unwrap();
        assert_eq!(stream.next().await.unwrap().len(), 3);
        queue.release_where(|(group, _)| (*group == 1).then_some(true));
        assert_eq!(a.wait(Duration::from_secs(1)).await, Ok(true));
        assert_eq!(b.wait(Duration::from_secs(1)).await, Ok(true));
        assert_eq!(stream.next().await.unwrap()[0].0, c.id());
        drop(c);
        assert!(stream.next().await.unwrap().is_empty());
    }
}
