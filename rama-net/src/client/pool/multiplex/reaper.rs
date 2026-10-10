//! Taking stored connections out without scanning the pool: idle ones in the
//! order their idle clocks started, a few at a time, and broken ones as their
//! listener hears of the break.

use super::*;

/// No node: a connection not linked into the idle list.
pub(super) const UNLINKED: usize = usize::MAX;

/// Every stored connection, in one list ordered by when its idle clock started
/// (as known when it was listed or last moved), so the first is the first to
/// expire: reaping only ever looks at the front.
pub(super) struct Reaper<C, ID> {
    /// When the front is due, `u64::MAX` if nothing is: read by every checkout
    /// without a lock.
    due: AtomicU64,
    list: Mutex<IdleList<C, ID>>,
    /// The nodes of connections their listener heard break, with their `seq`.
    broken: Mutex<SmallVec<[(usize, u64); 2]>>,
}

/// What a step of the reaper found, to take out under the storage lock.
pub(super) struct Reaped<C, ID> {
    pub(super) broken: SmallVec<[Arc<StoredConnection<C, ID>>; 2]>,
    /// Idle past the timeout, nothing to ask: retired once still idle.
    pub(super) expired: SmallVec<[Arc<StoredConnection<C, ID>>; 4]>,
    /// Idle past the timeout as far as the pool knows: their admission is
    /// asked outside the lock.
    pub(super) expiring: SmallVec<[Arc<StoredConnection<C, ID>>; 2]>,
    /// When the next connection expires, if any does.
    pub(super) next_expiry: u64,
}

struct IdleList<C, ID> {
    nodes: Vec<Node<C, ID>>,
    free: Vec<usize>,
    head: usize,
    tail: usize,
}

struct Node<C, ID> {
    conn: Weak<StoredConnection<C, ID>>,
    seq: u64,
    /// When its idle clock started, as far as known when it was listed or
    /// moved: never before that of a node ahead of it.
    since: u64,
    prev: usize,
    next: usize,
}

impl<C, ID> Default for Reaper<C, ID> {
    fn default() -> Self {
        Self {
            due: AtomicU64::new(u64::MAX),
            list: Mutex::new(IdleList {
                nodes: Vec::new(),
                free: Vec::new(),
                head: UNLINKED,
                tail: UNLINKED,
            }),
            broken: Mutex::new(SmallVec::new()),
        }
    }
}

impl<C, ID> Reaper<C, ID> {
    /// Whether a step is due: one relaxed load.
    pub(super) fn is_due(&self, now: u64) -> bool {
        now >= self.due.load(Ordering::Relaxed)
    }

    /// List `conn`, just stored: with the storage lock held.
    pub(super) fn link(&self, conn: &Arc<StoredConnection<C, ID>>) {
        let mut list = self.list.lock();
        if conn.idle_node.load(Ordering::Relaxed) != UNLINKED {
            return;
        }
        let was_empty = list.head == UNLINKED;
        let since = list.tail_since().max(now_monotonic_nanos());
        let node = list.push_back(Arc::downgrade(conn), conn.seq, since);
        conn.idle_node.store(node, Ordering::Relaxed);
        if was_empty {
            // The next step learns when the front is due.
            self.due.store(0, Ordering::Relaxed);
        }
    }

    /// Unlist `conn`, taken out of storage: with the storage lock held.
    pub(super) fn unlink(&self, conn: &StoredConnection<C, ID>) {
        let mut list = self.list.lock();
        let node = conn.idle_node.swap(UNLINKED, Ordering::Relaxed);
        if node != UNLINKED {
            list.remove(node);
        }
    }

    /// The listener of `conn` heard it break: the next step takes it out.
    pub(super) fn doom(&self, conn: &StoredConnection<C, ID>) {
        let node = conn.idle_node.load(Ordering::Relaxed);
        if node == UNLINKED {
            // Not stored yet: its store looks, see `MultiplexPool::create`.
            return;
        }
        self.broken.lock().push((node, conn.seq));
        self.due.store(0, Ordering::Relaxed);
    }

    /// Look at the front, at most `budget` connections, with the storage lock
    /// held: connections busy or idle again since they were listed move to the
    /// back, the expired ones are returned (and moved to the back, until they
    /// are taken out), so the list stays ordered by idle start.
    pub(super) fn step(&self, timeout: Option<Duration>, now: u64, budget: usize) -> Reaped<C, ID> {
        let mut reaped = Reaped {
            broken: SmallVec::new(),
            expired: SmallVec::new(),
            expiring: SmallVec::new(),
            next_expiry: u64::MAX,
        };
        let mut left = budget;
        let (broken, more_broken) = {
            let mut broken = self.broken.lock();
            let taken = broken.len().min(left);
            let taken: SmallVec<[(usize, u64); 2]> = broken.drain(..taken).collect();
            (taken, !broken.is_empty())
        };
        left -= broken.len();
        let mut list = self.list.lock();
        for (node, seq) in broken {
            if let Some(conn) = list.conn(node, seq) {
                reaped.broken.push(conn);
            }
        }
        let due = match timeout.map(nanos) {
            Some(timeout) => Self::step_idle(&mut list, timeout, now, left, &mut reaped),
            None => u64::MAX,
        };
        // Breaks left for the next checkout keep it due.
        let due = if more_broken { 0 } else { due };
        self.due.store(due, Ordering::Relaxed);
        reaped
    }

    /// The idle part of [`Self::step`]: when the front is due next.
    fn step_idle(
        list: &mut IdleList<C, ID>,
        timeout: u64,
        now: u64,
        mut left: usize,
        reaped: &mut Reaped<C, ID>,
    ) -> u64 {
        loop {
            let head = list.head;
            if head == UNLINKED {
                return u64::MAX;
            }
            let due = list.nodes[head].since.saturating_add(timeout);
            if due > now {
                reaped.next_expiry = due;
                return due;
            }
            if left == 0 {
                // More is due: the next checkout goes on.
                reaped.next_expiry = now;
                return now;
            }
            left -= 1;
            let Some(conn) = list.nodes[head].conn.upgrade() else {
                list.remove(head);
                continue;
            };
            if !conn.maybe_idle() {
                // Busy: looked at again a timeout from now.
                list.move_back(head, now);
                continue;
            }
            let idle_since = conn.last_idle.as_nanos();
            if idle_since > list.nodes[head].since && idle_since.saturating_add(timeout) > now {
                // Idle again since it was listed.
                list.move_back(head, idle_since);
                continue;
            }
            // Expired: listed again until it is taken out, so a busy answer
            // from its admission leaves it in order.
            list.move_back(head, now);
            if conn.admission.is_some() {
                reaped.expiring.push(conn);
            } else {
                reaped.expired.push(conn);
            }
        }
    }
}

#[cfg(test)]
impl<C, ID> Reaper<C, ID> {
    /// The `seq` and idle start of the connections linked, front first.
    pub(super) fn linked(&self) -> Vec<(u64, u64)> {
        let list = self.list.lock();
        let mut linked = Vec::new();
        let mut at = list.head;
        while let Some(node) = list.nodes.get(at) {
            linked.push((node.seq, node.since));
            at = node.next;
        }
        linked
    }
}

impl<C, ID> IdleList<C, ID> {
    fn tail_since(&self) -> u64 {
        self.nodes.get(self.tail).map_or(0, |node| node.since)
    }

    /// The connection of `node`, if it still holds the one of `seq`.
    fn conn(&self, node: usize, seq: u64) -> Option<Arc<StoredConnection<C, ID>>> {
        self.nodes
            .get(node)
            .filter(|node| node.seq == seq)
            .and_then(|node| node.conn.upgrade())
    }

    fn push_back(&mut self, conn: Weak<StoredConnection<C, ID>>, seq: u64, since: u64) -> usize {
        let node = Node {
            conn,
            seq,
            since,
            prev: self.tail,
            next: UNLINKED,
        };
        let index = if let Some(index) = self.free.pop() {
            self.nodes[index] = node;
            index
        } else {
            self.nodes.push(node);
            self.nodes.len() - 1
        };
        match self.nodes.get_mut(self.tail) {
            Some(tail) => tail.next = index,
            None => self.head = index,
        }
        self.tail = index;
        index
    }

    fn unlink(&mut self, index: usize) {
        let Node { prev, next, .. } = self.nodes[index];
        match self.nodes.get_mut(prev) {
            Some(prev) => prev.next = next,
            None => self.head = next,
        }
        match self.nodes.get_mut(next) {
            Some(next) => next.prev = prev,
            None => self.tail = prev,
        }
    }

    fn remove(&mut self, index: usize) {
        self.unlink(index);
        let node = &mut self.nodes[index];
        // Drop its handle now, not when the node is reused.
        node.conn = Weak::new();
        node.seq = u64::MAX;
        self.free.push(index);
    }

    /// Move `index` to the back as idle `since`, kept no earlier than the
    /// node ahead of it there.
    fn move_back(&mut self, index: usize, since: u64) {
        self.unlink(index);
        let since = since.max(self.tail_since());
        let tail = self.tail;
        let node = &mut self.nodes[index];
        node.since = since;
        node.prev = tail;
        node.next = UNLINKED;
        match self.nodes.get_mut(tail) {
            Some(tail) => tail.next = index,
            None => self.head = index,
        }
        self.tail = index;
    }
}
