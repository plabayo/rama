//! A stored connection, its handouts, and how freed capacity reaches waiters.

use super::*;

/// A connection stored in a [`MultiplexPool`].
///
/// The connection never leaves the pool, it is shared through [`MultiplexedConnection`]
/// handles and only ever used via `&self`.
pub(super) struct StoredConnection<C, ID> {
    pub(super) conn: C,
    pub(super) id: ID,
    /// The lane the connection is filed under, `None` while it is not stored.
    /// Only accessed with the storage lock held.
    pub(super) lane: Mutex<Option<LaneKey>>,
    /// Whether the connection is filed in a lane: a hint, so releases of a
    /// connection that is not stored skip the storage lock. Written with it.
    pub(super) filed: AtomicBool,
    /// Bumped by every [`MultiplexedConnection::rekey`], under the `pool_slot`
    /// lock that admission holds: a candidate selected under an earlier lane
    /// can no longer be admitted.
    pub(super) lane_gen: AtomicU64,
    /// Creation order within the pool. Orders a lane, and so
    /// [`MuxSelection::FirstAvailable`].
    pub(super) seq: u64,
    /// The pool's `max_concurrent_streams`, needed to judge spare capacity when
    /// a handout is released.
    pub(super) stream_cap: usize,
    pub(super) max_concurrency: Option<Arc<MaxConcurrency>>,
    /// Read from its listener, which may not call into the connection itself.
    pub(super) health: Option<Arc<ConnectionHealthWatcher>>,
    /// Whether waiting checkouts were told it broke.
    pub(super) broken_told: AtomicBool,
    pub(super) admission: Option<ConnectionAdmission>,
    /// Changes its sources reported: counted by its listener.
    pub(super) changes: AtomicU64,
    /// One past the count of changes when its admission last reported work
    /// outliving its handouts: until the next change it is not asked again.
    pub(super) busy_at: AtomicU64,
    pub(super) active: AtomicUsize,
    /// The waiters of the lane the connection is filed under. A leaf lock:
    /// releases and pushed changes reach it without the storage lock.
    pub(super) lane_waiters: Mutex<Option<Arc<WaitQueue>>>,
    /// Checkouts waiting anywhere in the pool: while none waits, releases and
    /// pushed changes skip the waiters.
    pub(super) waiting: Arc<AtomicUsize>,
    /// Every waiter of the pool: new connections and rekeys.
    pub(super) notify: Arc<Notify>,
    /// Checkouts waiting for a total slot: an idle connection nobody else
    /// waits for is a chance to evict it for one.
    pub(super) slot_waiters: Arc<WaitQueue>,
    /// Checkouts at its id's limit, if the pool has one: the same chance, to
    /// replace it with a connection they can use.
    pub(super) id_evictors: Option<Arc<WaitQueue>>,
    pub(super) last_idle: AtomicInstant,
    pub(super) pool_slot: Mutex<ConnectionSlot>,
    /// Whether the lane's `open` set lists this connection. Only written with
    /// the storage lock held; released handouts read it without the lock to
    /// skip re-listing a connection that is still listed.
    pub(super) listed: AtomicBool,
    /// Where released handouts re-list this connection. Weak, since storage owns
    /// the connection.
    pub(super) storage: Weak<Mutex<Storage<C, ID>>>,
    pub(super) relist_fn: fn(&Arc<Self>),
    /// The pool's idle limits, if it has any.
    pub(super) idle_limits: Option<Arc<IdleLimits>>,
    /// Its standing in the idle limits' count: [`COUNTED`] as it goes idle,
    /// [`UNCOUNTED`] again as a stream is admitted or outliving work is seen,
    /// [`GONE`] while it is not stored.
    pub(super) idle_count: AtomicU8,
    pub(super) trim_fn: fn(&Arc<Self>),
    pub(super) trim_all_fn: TrimAll<C, ID>,
}

/// [`StoredConnection::idle_count`]: stored, not counted idle.
pub(super) const UNCOUNTED: u8 = 0;
/// [`StoredConnection::idle_count`]: stored and counted idle.
pub(super) const COUNTED: u8 = 1;
/// [`StoredConnection::idle_count`]: not stored, never counted.
pub(super) const GONE: u8 = 2;

/// Trims every id's idle connections over the limits, see [`trim_all`].
pub(super) type TrimAll<C, ID> = fn(&Weak<Mutex<Storage<C, ID>>>, &IdleLimits, &AtomicUsize);

/// A stream reserved on a connection by [`StoredConnection::try_admit`], with
/// the transport credit reserved for it, if the connection has a provider.
pub(super) struct Admitted(pub(super) Option<ConnectionAdmissionLease>);

/// Admission and eviction share this lock so a previously captured snapshot
/// cannot acquire a stream after the connection's capacity has been transferred.
pub(super) struct ConnectionSlot {
    pub(super) slots: MultiplexSlot,
    pub(super) retired: bool,
}

impl<C, ID> StoredConnection<C, ID> {
    /// A connection is idle when none of its handouts are in flight and no work
    /// they outlived still occupies it.
    ///
    /// Asks its admission, which may take the source's own locks: never call it
    /// with the storage lock held, see [`Self::maybe_idle`].
    pub(super) fn is_idle(&self) -> bool {
        if !self.maybe_idle() {
            return false;
        }
        // Read before asking: a change after the answer makes it ask again.
        let changes = self.changes.load(Ordering::Acquire);
        if self.in_use_unleased() {
            // Not asked again until its source changes, which restarts the
            // idle clock.
            self.busy_at
                .store(changes.wrapping_add(1), Ordering::Relaxed);
            self.uncount_idle();
            return false;
        }
        true
    }

    /// Whether the connection can be idle, from atomics only: none of its
    /// handouts are in flight, and its admission did not report work outliving
    /// them since its last change, which it reports once such work ends.
    pub(super) fn maybe_idle(&self) -> bool {
        self.active.load(Ordering::Relaxed) == 0
            && self.busy_at.load(Ordering::Relaxed)
                != self.changes.load(Ordering::Acquire).wrapping_add(1)
    }

    /// Count the connection idle for the pool's idle limits, once while it is
    /// stored: whether this counted it.
    pub(super) fn count_idle(&self) -> bool {
        let Some(limits) = &self.idle_limits else {
            return false;
        };
        let counted = self
            .idle_count
            .compare_exchange(UNCOUNTED, COUNTED, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        if counted {
            limits.idle.fetch_add(1, Ordering::Relaxed);
        }
        counted
    }

    /// No longer count the connection idle.
    pub(super) fn uncount_idle(&self) {
        if let Some(limits) = &self.idle_limits
            && self
                .idle_count
                .compare_exchange(COUNTED, UNCOUNTED, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            limits.idle.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// The connection is stored: counted once it goes idle. With the storage
    /// lock held, as [`Self::unfile_idle`].
    pub(super) fn file_idle(&self) {
        self.idle_count.store(UNCOUNTED, Ordering::Release);
    }

    /// The connection left storage: never counted until it is stored again.
    pub(super) fn unfile_idle(&self) {
        if self.idle_count.swap(GONE, Ordering::AcqRel) == COUNTED
            && let Some(limits) = &self.idle_limits
        {
            limits.idle.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Trim the idle connections over the limits from a task of its own, if
    /// they may be over: a listener may hold its source's locks, and trimming
    /// asks admissions.
    fn trim_later(&self)
    where
        C: Send + Sync + 'static,
        ID: Send + Sync + 'static,
    {
        let Some(limits) = &self.idle_limits else {
            return;
        };
        let over_total = limits
            .total
            .is_some_and(|max| limits.idle.load(Ordering::Relaxed) > max.get());
        if !over_total && limits.per_id.is_none() || limits.trimming.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            limits.trimming.store(false, Ordering::Release);
            return;
        };
        let (storage, limits, waiting, trim) = (
            self.storage.clone(),
            limits.clone(),
            self.waiting.clone(),
            self.trim_all_fn,
        );
        runtime.spawn(async move {
            trim(&storage, &limits, &waiting);
            limits.trimming.store(false, Ordering::Release);
        });
    }

    /// Work outlived its handouts, such as an upgraded tunnel.
    fn in_use_unleased(&self) -> bool {
        self.admission
            .as_ref()
            .is_some_and(ConnectionAdmission::in_use)
    }

    /// Retire the connection if `idle` holds under its slot lock, so it admits
    /// no stream any more: returns that lock, with the slots to take over.
    pub(super) fn retire_if(
        &self,
        idle: impl FnOnce(&Self) -> bool,
    ) -> Option<parking_lot::MutexGuard<'_, ConnectionSlot>> {
        let mut slot = self.pool_slot.lock();
        if slot.retired || !idle(self) {
            return None;
        }
        slot.retired = true;
        // On its way out: not idle for the limits any more.
        self.uncount_idle();
        Some(slot)
    }

    /// Effective per-connection concurrency: the connection's [`MaxConcurrency`]
    /// extension ([`usize::MAX`] if unset), capped by the pool's
    /// `max_concurrent_streams`. Read live on every admission, so it tracks
    /// changes (e.g. h2 SETTINGS updates).
    ///
    /// A value of 0 is valid, e.g. a peer advertising `SETTINGS_MAX_CONCURRENT_STREAMS=0`
    pub(super) fn effective_capacity(&self, cap: usize) -> usize {
        self.max_concurrency
            .as_ref()
            .map_or(usize::MAX, |m| m.get())
            .min(cap)
    }

    /// Whether a stream slot is free right now, judged live like every admission.
    pub(super) fn has_capacity(&self, cap: usize) -> bool {
        self.active.load(Ordering::Relaxed) < self.effective_capacity(cap)
    }

    /// Re-list a connection that has spare stream capacity in its lane's
    /// `open` set after a handout was released.
    ///
    /// A connection stays listed while it has room, so a busy multiplexed
    /// connection costs no lock here. It is only unlisted when a checkout took
    /// its last slot, and only exclusive connections pay the lock on every
    /// release. Of a release and an unlisting racing it, one sees the other:
    /// see the fences in [`MultiplexedConnection::drop`] and [`Lane::pick`].
    pub(super) fn relist(self: &Arc<Self>) {
        if !self.listed.load(Ordering::Relaxed) && self.filed.load(Ordering::Relaxed) {
            (self.relist_fn)(self);
        }
    }

    /// Admit a new in-flight stream (while `active < limit`) and bind it to a
    /// [`MultiplexedConnection`] in one step, so `active` is never incremented
    /// without a handout to release it on drop. Returns `None` at capacity.
    ///
    /// Takes `&Arc<Self>` (not `&self`) since the handout needs to share the
    /// `Arc`; `&Arc<Self>` as a method receiver is still unstable.
    pub(super) fn try_create_multiplexed(
        self: &Arc<Self>,
        lane_gen: u64,
        cap: usize,
        input: &Extensions,
    ) -> Option<MultiplexedConnection<C, ID>>
    where
        C: ExtensionsRef,
    {
        self.try_admit(lane_gen, cap, input)
            .map(|Admitted(admission)| MultiplexedConnection {
                inner: self.clone(),
                admission,
            })
    }

    /// Reserve one stream, and its transport credit if the connection publishes
    /// a provider, or return `None` without side effects when the connection
    /// cannot take a stream now, or was rekeyed since it was selected under
    /// `lane_gen`.
    ///
    /// The caller must turn a successful result into a handout, since the
    /// stream counter is only released by dropping one.
    pub(super) fn try_admit(
        &self,
        lane_gen: u64,
        cap: usize,
        input: &Extensions,
    ) -> Option<Admitted>
    where
        C: ExtensionsRef,
    {
        // Resource providers run outside all pool locks. If admission loses a
        // race below, dropping this reservation immediately returns its credit.
        let admission = match &self.admission {
            Some(provider) => match provider.try_acquire(input) {
                Ok(Some(lease)) => Some(lease),
                Ok(None) => return None,
                Err(error) => {
                    // Publish retirement through the existing health signal so
                    // later sweeps need no additional lock on healthy lookups.
                    if let Some(health) =
                        self.conn.extensions().get_ref::<ConnectionHealthWatcher>()
                    {
                        health.mark_broken();
                    } else {
                        let health = ConnectionHealthWatcher::default();
                        health.mark_broken();
                        self.conn.extensions().insert(health);
                    }
                    self.pool_slot.lock().retired = true;
                    trace!(%error, "multiplex pool: resource provider retired connection");
                    return None;
                }
            },
            None => None,
        };
        let slot = self.pool_slot.lock();
        // A close can be reported while the connector's compatibility policy
        // runs outside the storage lock. Do not hand out a known-broken
        // connection merely because its earlier snapshot was healthy.
        let broken = self
            .conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|health| health.health() == ConnectionHealth::Broken);
        let rekeyed = self.lane_gen.load(Ordering::Acquire) != lane_gen;
        if slot.retired || rekeyed || broken || !self.has_capacity(cap) {
            return None;
        }
        // Admission is serialized with retirement. Concurrent lease drops only
        // decrease the count, so no compare/exchange loop is needed here.
        self.active.fetch_add(1, Ordering::Relaxed);
        drop(slot);
        self.uncount_idle();
        Some(Admitted(admission))
    }
}

impl<C, ID> StoredConnection<C, ID> {
    /// Capacity of the connection was freed: hand its lane's waiters to
    /// `wake` or, if nobody waits there, offer an idle connection to the
    /// pool's waiters for eviction. Skipped while no checkout waits.
    ///
    /// Call after a `SeqCst` fence that follows the change. It pairs with the
    /// fence of [`WaitQueue::push`]: of a waiter queuing and this change, one
    /// sees the other; a waiter leaving meets it under the queue's lock.
    ///
    /// `in_listener`: called from a source's notification, which may hold the
    /// source's locks, so nothing may call into a source. Work outliving the
    /// handouts is then not asked about: the woken checkout checks it.
    pub(super) fn freed(&self, wake: fn(&WaitQueue) -> bool, in_listener: bool) {
        if self.waiting.load(Ordering::Relaxed) == 0 {
            return;
        }
        let waiters = self.lane_waiters.lock().clone();
        let spoken_for = waiters.as_ref().is_some_and(|waiters| wake(waiters))
            && self.has_capacity(self.stream_cap);
        let idle = if in_listener {
            self.active.load(Ordering::Relaxed) == 0
        } else {
            self.is_idle()
        };
        if !idle {
            return;
        }
        // Eviction leaves an idle connection to its lane's waiters, unless a
        // checkout waiting for a slot arrived before them.
        let lane_front = waiters.as_ref().and_then(|waiters| waiters.front_order());
        let chance_for = |evictors: &WaitQueue| {
            !spoken_for
                || evictors
                    .front_order()
                    .is_some_and(|evictor| lane_front.is_none_or(|lane| evictor < lane))
        };
        if chance_for(&self.slot_waiters) {
            self.slot_waiters.wake_one();
        }
        if let Some(id_evictors) = &self.id_evictors
            && chance_for(id_evictors)
        {
            id_evictors.wake_one();
        }
    }

    /// Whether the health watcher it was created with marks it broken.
    pub(super) fn is_broken(&self) -> bool {
        self.health
            .as_ref()
            .is_some_and(|health| health.health() == ConnectionHealth::Broken)
    }
}

/// A source of the connection changed: its MaxConcurrency, transport credit,
/// health, or work outliving its handouts.
impl<C: Send + Sync + 'static, ID: Send + Sync + 'static> ChangeListener
    for StoredConnection<C, ID>
{
    fn changed(&self, change: Change) {
        // Pairs with the read before asking about outliving work: once it ends,
        // the connection is asked again.
        self.changes.fetch_add(1, Ordering::Release);
        if self.active.load(Ordering::Relaxed) == 0 {
            // Such as the end of work outliving the handouts: the idle clock
            // starts now. A trim asks.
            self.last_idle.set_now();
            if self.count_idle() {
                self.trim_later();
            }
        }
        fence(Ordering::SeqCst);
        let wake = match change {
            Change::Freed => WaitQueue::wake_one,
            // How much capacity changed is unknown: every waiter of the lane looks.
            Change::Other => WaitQueue::wake_all,
        };
        self.freed(wake, true);
        if self.waiting.load(Ordering::Relaxed) != 0
            && self.is_broken()
            && !self.broken_told.swap(true, Ordering::Relaxed)
        {
            // Only a look takes a broken connection out and frees its slots:
            // let every waiting checkout look, whatever it waits for, once.
            self.notify.notify_waiters();
        }
    }
}

/// [`StoredConnection::relist_fn`]: lock the storage the connection belongs to
/// and list the connection again, if it is still stored and has room.
///
/// Free function since the handout's `Drop` impl cannot carry the `ConnID`
/// bounds that hashing needs; connections capture this at creation.
pub(super) fn relist_stored<C, ID: ConnID>(conn: &Arc<StoredConnection<C, ID>>) {
    let Some(storage) = conn.storage.upgrade() else {
        return;
    };
    if let Some(bucket) = storage.lock().by_id.get_mut(&conn.id) {
        bucket.list(conn);
    }
}

/// [`StoredConnection::trim_fn`]: close the least recently used idle
/// connections beyond the pool's idle limits, of the connection's id first,
/// then in total.
pub(super) fn trim_idle<C, ID: ConnID>(conn: &Arc<StoredConnection<C, ID>>) {
    if let (Some(limits), Some(storage)) = (&conn.idle_limits, conn.storage.upgrade()) {
        trim(&storage, limits, &conn.waiting, Some(&conn.id));
    }
}

/// [`TrimAll`]: as [`trim_idle`], for every id.
pub(super) fn trim_all<C, ID: ConnID>(
    storage: &Weak<Mutex<Storage<C, ID>>>,
    limits: &IdleLimits,
    waiting: &AtomicUsize,
) {
    if let Some(storage) = storage.upgrade() {
        trim(&storage, limits, waiting, None);
    }
}

/// Close the least recently used idle connections beyond the limits, of `own`
/// (else of any id) first, then in total. Picks from atomics under the storage
/// lock, asks the pick's admission without it.
fn trim<C, ID: ConnID>(
    storage: &Mutex<Storage<C, ID>>,
    limits: &IdleLimits,
    waiting: &AtomicUsize,
    own: Option<&ID>,
) {
    let mut busy: SmallVec<[u64; 2]> = SmallVec::new();
    // Waiting checkouts take idle connections: none of them is extra then.
    while waiting.load(Ordering::Relaxed) == 0 {
        let over_total = limits
            .total
            .is_some_and(|max| limits.idle.load(Ordering::Relaxed) > max.get());
        let extra = {
            let storage = storage.lock();
            let over = |bucket: &&IdBucket<C, ID>| {
                limits.per_id.is_some_and(|max| {
                    let idle = bucket.lanes().flat_map(|lane| &lane.conns);
                    idle.filter(|conn| conn.maybe_idle() && !busy.contains(&conn.seq))
                        .count()
                        > max.get()
                })
            };
            let bucket = match own {
                Some(id) => storage.by_id.get(id).filter(over),
                None => storage.by_id.values().find(over),
            };
            match bucket {
                Some(bucket) => least_recently_idle(bucket.lanes(), &busy),
                None if over_total => {
                    least_recently_idle(storage.by_id.values().flat_map(IdBucket::lanes), &busy)
                }
                None => None,
            }
        };
        let Some(extra) = extra else {
            return;
        };
        if extra.retire_if(StoredConnection::is_idle).is_none() {
            busy.push(extra.seq);
            continue;
        }
        trace!(id = ?extra.id, "multiplex pool: closing an idle connection over the idle limits");
        let stored = unstore(&mut storage.lock(), &extra);
        drop((stored, extra));
    }
}

/// The connection of `lanes` idle the longest, from atomics, but not `busy`.
fn least_recently_idle<'a, C: 'a, ID: 'a>(
    lanes: impl Iterator<Item = &'a Lane<C, ID>>,
    busy: &[u64],
) -> Option<Arc<StoredConnection<C, ID>>> {
    lanes
        .flat_map(|lane| &lane.conns)
        .filter(|conn| conn.maybe_idle() && !busy.contains(&conn.seq))
        .min_by_key(|conn| conn.last_idle.as_nanos())
        .cloned()
}

/// A cheap handle to a shared connection in a [`MultiplexPool`].
///
/// It implements [`Service`] by forwarding to the inner connection and counts as
/// one of the connection's in-flight streams for its lifetime, the stream is
/// released on drop.
pub struct MultiplexedConnection<C, ID> {
    pub(super) inner: Arc<StoredConnection<C, ID>>,
    pub(super) admission: Option<ConnectionAdmissionLease>,
}

impl<C, ID> Drop for MultiplexedConnection<C, ID> {
    fn drop(&mut self) {
        // Return unused transport credit before waking pool-capacity waiters.
        self.admission.take();
        let last = self.inner.active.fetch_sub(1, Ordering::Release) == 1;
        if last {
            self.inner.last_idle.set_now();
        }
        // Pairs with the fences of a checkout unlisting a full connection and
        // of a waiter queuing: of either and this release, one sees the other.
        fence(Ordering::SeqCst);
        // Make the spare stream slot visible to checkouts before waking any
        // waiter that will look for it.
        self.inner.relist();
        // One released handout is one unit of capacity: for the first waiter
        // of its lane without a wake, else an eviction chance if now idle.
        // Work outliving the handout is announced by the admission's change.
        self.inner.freed(WaitQueue::wake_one, false);
        if last && self.inner.idle_limits.is_some() && self.inner.is_idle() {
            self.inner.count_idle();
            (self.inner.trim_fn)(&self.inner);
        }
    }
}

impl<C: ExtensionsRef, ID: ConnID> MultiplexedConnection<C, ID> {
    /// File the shared connection under new reuse requirements, such as an
    /// identity it authenticated after it was established.
    ///
    /// Also publishes `reuse` on the connection. Pools otherwise keep the
    /// requirements the connection was added with. A connection the pool has
    /// already dropped stays dropped. Checkouts that have not been admitted
    /// yet no longer get a stream under the old requirements; streams already
    /// admitted keep theirs, so rekey while this handout is the only one.
    pub fn rekey(&self, reuse: ConnectionReuse) {
        let conn = &self.inner;
        let lane = LaneKey::of_connection(Some(&reuse)).filter(|_| conn.id.is_reusable());
        conn.conn.extensions().insert(reuse);
        let Some(storage) = conn.storage.upgrade() else {
            return;
        };
        let mut storage = storage.lock();
        // Candidates selected under the old lane can no longer be admitted.
        let retired = {
            let slot = conn.pool_slot.lock();
            conn.lane_gen.fetch_add(1, Ordering::Release);
            slot.retired
        };
        if let Some(bucket) = storage.by_id.get_mut(&conn.id) {
            bucket.remove(conn);
            if bucket.is_empty() {
                storage.by_id.remove(&conn.id);
            }
        }
        let Some(lane) = lane else {
            return;
        };
        if retired {
            return;
        }
        storage
            .by_id
            .entry(conn.id.clone())
            .or_insert_with(|| IdBucket::new(now_monotonic_nanos()))
            .insert(conn, lane);
        drop(storage);
        // Requests of the new lane may be waiting for it.
        conn.notify.notify_waiters();
    }
}

impl<C: ExtensionsRef, ID> ExtensionsRef for MultiplexedConnection<C, ID> {
    fn extensions(&self) -> &Extensions {
        self.inner.conn.extensions()
    }
}

impl<Input, C, ID> Service<Input> for MultiplexedConnection<C, ID>
where
    C: Service<Input> + ExtensionsRef,
    ID: Send + Sync + 'static,
    Input: ExtensionsMut + Send + 'static,
{
    type Output = C::Output;
    type Error = C::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(admission) = &self.admission {
            admission.bind(input.extensions_mut());
        }

        self.inner.conn.serve(input).await
    }
}

impl<C, ID> Debug for MultiplexedConnection<C, ID>
where
    ID: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexedConnection")
            .field("id", &self.inner.id)
            .field("active_streams", &self.inner.active.load(Ordering::Relaxed))
            .finish()
    }
}
