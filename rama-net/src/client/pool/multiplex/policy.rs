//! What a pool does at its limits: the saturation policy and the create permit.

use super::*;

/// What a [`MultiplexPool`] at a [connection limit] does for a checkout that
/// needs a new connection: wait, or replace an idle connection, of its own id
/// at the id's limit and of any id at the total one.
///
/// Closing another connection costs that connection's next request a new
/// handshake, so the default waits a little for the checkout's own connections
/// first (see [`Self::EvictIdleAfter`] for its timer). An idle connection goes
/// to the checkout that arrived first among those waiting to use it, to replace
/// it for the total limit and to replace it for its id's limit.
///
/// [connection limit]: MultiplexPool::with_max_connections_total
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaturationPolicy {
    /// Wait for a connection slot; never close another connection for one.
    Wait,
    /// Close the least recently used idle connection only for a checkout none
    /// of whose connections can take a stream; others wait for their own.
    EvictIdleWhenCold,
    /// As [`Self::EvictIdleWhenCold`], and for any checkout that waited this long.
    ///
    /// Waits on a tokio timer: the runtime needs its time driver enabled.
    EvictIdleAfter(Duration),
    /// Close the least recently used idle connection whenever a checkout needs a
    /// slot.
    EvictIdle,
}

impl Default for SaturationPolicy {
    fn default() -> Self {
        Self::EvictIdleAfter(DEFAULT_EVICT_IDLE_AFTER)
    }
}

/// The share of a [`MultiplexPool`]'s limits a new connection takes: the create
/// permit of [`MultiplexPool::get_conn`]. The connection keeps it while stored.
#[derive(Debug)]
pub struct MultiplexSlot {
    /// Of the total limit, if the pool has one.
    pub(super) total: Option<OwnedSemaphorePermit>,
    /// Of the connection's id, if the pool limits connections per id.
    pub(super) id: Option<IdPermit>,
    /// Counted in flight for its lane, if that multiplexes.
    pub(super) connect: Option<Connect>,
}

/// The connection limit of one id: its slots, and the checkouts at the limit
/// that may replace one of its idle connections.
#[derive(Debug)]
pub(super) struct IdLimit {
    pub(super) slots: Arc<Semaphore>,
    pub(super) evictors: Arc<WaitQueue>,
}

impl IdLimit {
    pub(super) fn new(max: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max.get())),
            evictors: Arc::new(WaitQueue::new()),
        }
    }

    /// Whether nothing holds a slot of it, waits for one, or a checkout of its
    /// id may queue in it.
    pub(super) fn is_unused(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1
            && Arc::strong_count(&self.slots) == 1
            && Arc::strong_count(&self.evictors) == 1
    }
}

/// How many idle connections a pool keeps, per id and in total, how many it
/// counts, and the trims asked for: see [`MultiplexPool::with_max_idle_per_id`].
///
/// One trimmer at a time closes what is over, held only while it trims:
/// whoever asks meanwhile leaves the ask to it, and it looks at the asks again
/// after letting go.
pub(super) struct IdleLimits<ID> {
    pub(super) per_id: Option<NonZeroUsize>,
    pub(super) total: Option<NonZeroUsize>,
    /// Stored connections counted idle, see [`StoredConnection::idle_count`].
    /// Signed: an uncount can pass the count it undoes.
    pub(super) idle: AtomicIsize,
    /// As `idle`, of each id, for the per-id limit: shared by the id's
    /// connections, forgotten once none holds it.
    id_idle: Mutex<HashMap<ID, Arc<AtomicIsize>>>,
    asked: Mutex<Asked<ID>>,
    trimmer: AtomicBool,
    /// Whether a task is on its way to trim: asks of listeners schedule no other.
    scheduled: AtomicBool,
    /// Where a trim asked for outside a runtime runs: the runtime of the pool's
    /// newest connection.
    pub(super) runtime: Mutex<Option<tokio::runtime::Handle>>,
}

impl<ID> std::fmt::Debug for IdleLimits<ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleLimits")
            .field("per_id", &self.per_id)
            .field("total", &self.total)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

/// Whether more than `max` are counted in `counter`.
pub(super) fn over(counter: &AtomicIsize, max: NonZeroUsize) -> bool {
    usize::try_from(counter.load(Ordering::Relaxed)).is_ok_and(|idle| idle > max.get())
}

/// The limit a trim closes an idle connection for.
#[derive(Debug, Clone, Copy)]
pub(super) enum Excess {
    PerId,
    Total,
}

/// The trims asked for: of these ids, or of every id.
pub(super) struct Asked<ID> {
    pub(super) ids: HashSet<ID>,
    pub(super) all: bool,
}

impl<ID> Default for Asked<ID> {
    fn default() -> Self {
        Self {
            ids: HashSet::default(),
            all: false,
        }
    }
}

impl<ID> Asked<ID> {
    pub(super) fn is_empty(&self) -> bool {
        !self.all && self.ids.is_empty()
    }
}

impl<ID> IdleLimits<ID> {
    /// The limits, if there are any.
    pub(super) fn new(
        per_id: Option<NonZeroUsize>,
        total: Option<NonZeroUsize>,
    ) -> Option<Arc<Self>> {
        (per_id.is_some() || total.is_some()).then(|| {
            Arc::new(Self {
                per_id,
                total,
                idle: AtomicIsize::new(0),
                id_idle: Mutex::new(HashMap::new()),
                asked: Mutex::new(Asked::default()),
                trimmer: AtomicBool::new(false),
                scheduled: AtomicBool::new(false),
                runtime: Mutex::new(None),
            })
        })
    }

    /// Whether idle connections may be over the limits: per id they are only
    /// counted by a trim.
    pub(super) fn may_be_over(&self) -> bool {
        self.per_id.is_some() || self.total.is_some_and(|max| self.idle_over(max))
    }

    /// Whether more than `max` are counted idle.
    pub(super) fn idle_over(&self, max: NonZeroUsize) -> bool {
        over(&self.idle, max)
    }

    /// The idle count of `id`'s connections, if the pool limits them per id.
    pub(super) fn id_counter(&self, id: &ID) -> Option<Arc<AtomicIsize>>
    where
        ID: Clone + Eq + std::hash::Hash,
    {
        self.per_id?;
        let mut counters = self.id_idle.lock();
        if let Some(counter) = counters.get(id) {
            return Some(counter.clone());
        }
        // Forget those of ids without connections once the map is full, then
        // leave it room for as many again, so this amortizes to O(1).
        let capacity = counters.capacity();
        if counters.len() >= capacity {
            counters.retain(|_, counter| Arc::strong_count(counter) > 1);
            if counters.len() * 2 > capacity {
                counters.reserve(capacity);
            }
        }
        let counter = Arc::new(AtomicIsize::new(0));
        counters.insert(id.clone(), counter.clone());
        Some(counter)
    }

    /// Ask for a trim of `id`'s idle connections, else of every id's: whether
    /// the caller is the trimmer now, and runs it.
    pub(super) fn ask(&self, id: Option<&ID>)
    where
        ID: Clone + Eq + std::hash::Hash,
    {
        let mut asked = self.asked.lock();
        match id {
            None => {
                asked.all = true;
                asked.ids.clear();
            }
            Some(id) if !asked.all => {
                asked.ids.insert(id.clone());
            }
            Some(_) => {}
        }
    }

    /// Hold the trimmer, unless someone else does: it sees the asks recorded
    /// before this, as it looks again after letting go.
    pub(super) fn hold(&self) -> Option<TrimmerHold<'_, ID>> {
        (!self.trimmer.swap(true, Ordering::AcqRel)).then_some(TrimmerHold(self))
    }

    /// The trims asked for so far, for the trimmer.
    pub(super) fn take(&self) -> Asked<ID> {
        std::mem::take(&mut *self.asked.lock())
    }

    /// Whether nothing is asked: read after letting go of the trimmer.
    pub(super) fn nothing_asked(&self) -> bool {
        self.asked.lock().is_empty()
    }

    /// Whether the caller schedules the task that trims: none is on its way.
    pub(super) fn schedule(&self) -> bool {
        !self.scheduled.swap(true, Ordering::AcqRel)
    }

    /// The scheduled task runs, or never will: a later ask schedules another.
    pub(super) fn unschedule(&self) {
        self.scheduled.store(false, Ordering::Release);
    }
}

/// The trimmer, held while one trims, also if it unwinds.
pub(super) struct TrimmerHold<'a, ID>(&'a IdleLimits<ID>);

impl<ID> Drop for TrimmerHold<'_, ID> {
    fn drop(&mut self) {
        // Pairs with an ask's record: the holder sees it after this, or the
        // asker holds the trimmer.
        self.0.trimmer.store(false, Ordering::Release);
    }
}

/// One slot of an id's limit, with the limit it belongs to.
#[derive(Debug)]
pub(super) struct IdPermit {
    #[expect(dead_code, reason = "held: dropping it frees the id's slot")]
    pub(super) permit: OwnedSemaphorePermit,
    pub(super) limit: Arc<IdLimit>,
}

/// How long [`SaturationPolicy::default`] lets a checkout wait for its own
/// connections before it may close another id's idle one.
pub(super) const DEFAULT_EVICT_IDLE_AFTER: Duration = Duration::from_millis(100);
