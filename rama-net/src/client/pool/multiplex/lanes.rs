//! Buckets of an id, their reuse lanes, and selection among a lane's connections.

use super::*;

/// Connections of the request's lanes copied out of storage, in creation order,
/// each with the lane generation it was selected under, so selection and
/// waiter registration run without holding the storage lock.
pub(super) type Snapshot<C, ID> = SmallVec<[(Arc<StoredConnection<C, ID>>, u64); 4]>;

/// The lanes a request can be served from: the lane of its key in each class
/// of its id, then the unrestricted lane.
pub(super) struct RequestLanes {
    /// The classes the keys were derived with, `None` if the id had none.
    pub(super) classes: Option<Arc<[ReuseClass]>>,
    /// The key derived with each of `classes`, in order.
    pub(super) keys: SmallVec<[Option<ReuseKey>; 1]>,
}

impl RequestLanes {
    /// Derive the request's keys from its id's `classes`, outside pool locks.
    pub(super) fn derive(classes: Option<Arc<[ReuseClass]>>, input: &Extensions) -> Self {
        let keys = classes
            .iter()
            .flat_map(|classes| classes.iter())
            .map(|class| class.request_key(input))
            .collect();
        Self { classes, keys }
    }

    /// Lanes of a request that can only use connections without requirements.
    pub(super) fn unrestricted() -> Self {
        Self {
            classes: None,
            keys: SmallVec::new(),
        }
    }
}

/// A request's lanes in one bucket, see [`IdBucket::request_lanes_mut`].
pub(super) type RequestLanesMut<'a, C, ID> = SmallVec<[&'a mut Lane<C, ID>; 2]>;

/// The connections of one id filed under one [`LaneKey`]: each of them can
/// serve every request of the lane, so selection needs no compatibility check.
///
/// `conns` is every connection in creation order. `open` is an index over it:
/// the connections which have a free stream slot, ordered by creation, so a
/// checkout picks its connection in O(1) instead of looking at every one.
///
/// `open` is a hint, not a copy of the truth. A live capacity change (an h2
/// SETTINGS raise, transport credit returning) is only seen by a checkout that
/// reads the connection, and a release can race an unlisting. So it can hold
/// entries that turn out full, which selection unlists as it meets them, and
/// it can miss a connection with room. A checkout that finds nothing in `open`
/// therefore takes the exact path, which reads every connection and lists the
/// ones the hint missed.
pub(super) struct Lane<C, ID> {
    pub(super) conns: Vec<Arc<StoredConnection<C, ID>>>,
    pub(super) open: BTreeMap<u64, Arc<StoredConnection<C, ID>>>,
    pub(super) waiters: Arc<WaitQueue>,
}

impl<C, ID> Lane<C, ID> {
    pub(super) fn new() -> Self {
        Self {
            conns: Vec::new(),
            open: BTreeMap::new(),
            waiters: Arc::default(),
        }
    }

    /// Where `conn` is stored in this lane.
    pub(super) fn position(&self, conn: &StoredConnection<C, ID>) -> Option<usize> {
        let pos = self.conns.partition_point(|stored| stored.seq < conn.seq);
        self.conns
            .get(pos)
            .is_some_and(|stored| stored.seq == conn.seq)
            .then_some(pos)
    }

    /// Store `conn`, keeping creation order even if concurrent creations
    /// publish out of order, and list it if it can take more than the
    /// establishing stream.
    pub(super) fn insert(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        let pos = self.conns.partition_point(|stored| stored.seq < conn.seq);
        self.conns.insert(pos, conn.clone());
        conn.file_idle();
        *conn.lane_waiters.lock() = Some(self.waiters.clone());
        self.list(conn);
    }

    /// List `conn` as having room, if it is stored, unlisted and has room.
    pub(super) fn list(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        if conn.listed.load(Ordering::Relaxed)
            || !conn.has_capacity(conn.stream_cap)
            || self.position(conn).is_none()
        {
            return;
        }
        conn.listed.store(true, Ordering::Relaxed);
        self.open.insert(conn.seq, conn.clone());
    }

    pub(super) fn unlist(&mut self, seq: u64) -> Option<Arc<StoredConnection<C, ID>>> {
        let conn = self.open.remove(&seq)?;
        conn.listed.store(false, Ordering::Relaxed);
        Some(conn)
    }

    /// Keep only the connections `keep` accepts.
    pub(super) fn retain(&mut self, keep: &mut impl FnMut(&Arc<StoredConnection<C, ID>>) -> bool) {
        let Self { conns, open, .. } = self;
        conns.retain(|conn| {
            if keep(conn) {
                return true;
            }
            if open.remove(&conn.seq).is_some() {
                conn.listed.store(false, Ordering::Relaxed);
            }
            conn.unfile_idle();
            *conn.lane.lock() = None;
            *conn.lane_waiters.lock() = None;
            conn.filed.store(false, Ordering::Relaxed);
            false
        });
    }

    /// Remove the connection at `pos` from the lane, and from `open`.
    /// The caller takes the connection's lane.
    pub(super) fn remove_at(&mut self, pos: usize) -> Arc<StoredConnection<C, ID>> {
        let conn = self.conns.remove(pos);
        self.unlist(conn.seq);
        conn.unfile_idle();
        *conn.lane_waiters.lock() = None;
        conn.filed.store(false, Ordering::Relaxed);
        conn
    }

    /// The listed connection the selection strategy prefers, skipping
    /// `skip`; round robin continues after `rr_after`. Entries without room
    /// are unlisted on the way.
    pub(super) fn pick(
        &mut self,
        selection: MuxSelection,
        cap: usize,
        skip: &[u64],
        rr_after: Option<u64>,
    ) -> Option<Pick> {
        let mut full: SmallVec<[u64; 2]> = SmallVec::new();
        let usable =
            |seq: u64, conn: &Arc<StoredConnection<C, ID>>, full: &mut SmallVec<[u64; 2]>| {
                if skip.contains(&seq) {
                    return false;
                }
                if conn.has_capacity(cap) {
                    return true;
                }
                full.push(seq);
                false
            };
        let pick = |(seq, conn): (&u64, &Arc<StoredConnection<C, ID>>), wrapped| Pick {
            seq: *seq,
            active: conn.active.load(Ordering::Relaxed),
            wrapped,
        };
        let chosen = match selection {
            MuxSelection::FirstAvailable => self
                .open
                .iter()
                .find(|(seq, conn)| usable(**seq, conn, &mut full))
                .map(|entry| pick(entry, false)),
            MuxSelection::LeastLoaded => {
                // Ties go to the earliest connection. A connection with no
                // streams cannot be beaten, which ends the scan at once for
                // exclusive connections however many are listed.
                let mut best: Option<Pick> = None;
                for entry in &self.open {
                    if !usable(*entry.0, entry.1, &mut full) {
                        continue;
                    }
                    let candidate = pick(entry, false);
                    if best.is_none_or(|best| candidate.active < best.active) {
                        best = Some(candidate);
                        if candidate.active == 0 {
                            break;
                        }
                    }
                }
                best
            }
            MuxSelection::RoundRobin => {
                // Continue after the connection chosen last, then wrap around.
                let start = rr_after.map_or(0, |seq| seq.saturating_add(1));
                self.open
                    .range(start..)
                    .find(|(seq, conn)| usable(**seq, conn, &mut full))
                    .map(|entry| pick(entry, false))
                    .or_else(|| {
                        self.open
                            .range(..start)
                            .find(|(seq, conn)| usable(**seq, conn, &mut full))
                            .map(|entry| pick(entry, true))
                    })
            }
        };
        if !full.is_empty() {
            let unlisted: SmallVec<[_; 2]> = full
                .into_iter()
                .filter_map(|seq| self.unlist(seq))
                .collect();
            // Pairs with the fence of a release: of it and this unlisting, one
            // sees the other, so room freed meanwhile stays listed.
            fence(Ordering::SeqCst);
            for conn in &unlisted {
                self.list(conn);
            }
        }
        chosen
    }

    /// Claim the picked connection `seq` for one checkout.
    ///
    /// A connection this checkout is about to fill is unlisted, which makes
    /// the claim exclusive, so concurrent checkouts spread over distinct
    /// exclusive connections instead of racing for one; the release relists
    /// it. Any other connection stays listed for concurrent users.
    pub(super) fn take(&mut self, seq: u64, cap: usize) -> Option<Arc<StoredConnection<C, ID>>> {
        let conn = self.open.get(&seq)?;
        // Read after the pick, this checkout's own stream not counted yet.
        if conn.active.load(Ordering::Relaxed) + 1 >= conn.effective_capacity(cap) {
            self.unlist(seq)
        } else {
            Some(conn.clone())
        }
    }
}

/// A connection claimed for one checkout, with the lane generation it was
/// claimed under: admission refuses it once it was rekeyed since.
pub(super) struct Claimed<C, ID> {
    pub(super) conn: Arc<StoredConnection<C, ID>>,
    pub(super) lane_gen: u64,
}

impl<C, ID> Claimed<C, ID> {
    /// Read under the storage lock that found `conn` in its lane.
    pub(super) fn new(conn: Arc<StoredConnection<C, ID>>) -> Self {
        let lane_gen = conn.lane_gen.load(Ordering::Acquire);
        Self { conn, lane_gen }
    }
}

/// A lane's preferred connection, compared across the request's lanes.
#[derive(Clone, Copy)]
pub(super) struct Pick {
    pub(super) seq: u64,
    pub(super) active: usize,
    /// Round robin found it only after wrapping around.
    pub(super) wrapped: bool,
}

impl Pick {
    /// Whether the strategy prefers this pick over `other`, as if both lanes
    /// were one index in creation order.
    pub(super) fn beats(self, other: Self, selection: MuxSelection) -> bool {
        match selection {
            MuxSelection::FirstAvailable => self.seq < other.seq,
            MuxSelection::LeastLoaded => (self.active, self.seq) < (other.active, other.seq),
            MuxSelection::RoundRobin => (self.wrapped, self.seq) < (other.wrapped, other.seq),
        }
    }
}

/// All connections of one id, filed by lane.
///
/// A checkout derives its key in each of the bucket's classes, the distinct
/// reuse classifiers among its connections, so its cost does not grow with
/// the number of lanes or connections.
pub(super) struct IdBucket<C, ID> {
    /// Connections without requirements: any request of the id may use them.
    pub(super) unrestricted: Lane<C, ID>,
    /// Connections with requirements, per classifier, by key.
    pub(super) keyed: Vec<ClassLanes<C, ID>>,
    /// The classes of `keyed`, in its order. Replaced, never mutated, so a
    /// checkout copies it out of the lock with one reference count.
    pub(super) classes: Arc<[ReuseClass]>,
    /// The `seq` last chosen by [`MuxSelection::RoundRobin`], across lanes.
    pub(super) rr_after: Option<u64>,
    /// Nanoseconds (see [`now_monotonic_nanos`]) when the next full sweep is due.
    pub(super) next_sweep: u64,
}

/// The lanes of one classifier.
pub(super) struct ClassLanes<C, ID> {
    pub(super) classifier: ReuseKey,
    pub(super) lanes: HashMap<ReuseKey, Lane<C, ID>>,
}

/// The lane a bucket has, when it has exactly one.
pub(super) enum OnlyLane {
    Unrestricted,
    Keyed(ReuseKey),
}

impl<C, ID> IdBucket<C, ID> {
    pub(super) fn new(next_sweep: u64) -> Self {
        Self {
            unrestricted: Lane::new(),
            keyed: Vec::new(),
            classes: Arc::new([]),
            rr_after: None,
            next_sweep,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.unrestricted.conns.is_empty() && self.keyed.is_empty()
    }

    pub(super) fn lanes(&self) -> impl Iterator<Item = &Lane<C, ID>> {
        std::iter::once(&self.unrestricted)
            .chain(self.keyed.iter().flat_map(|class| class.lanes.values()))
    }

    #[cfg(test)]
    pub(super) fn conns(&self) -> impl Iterator<Item = &Arc<StoredConnection<C, ID>>> {
        self.lanes().flat_map(|lane| &lane.conns)
    }

    /// The classes, `None` when the bucket has unrestricted connections only.
    pub(super) fn classes(&self) -> Option<Arc<[ReuseClass]>> {
        (!self.classes.is_empty()).then(|| self.classes.clone())
    }

    /// Claim a connection of the bucket's lane for one checkout, if the bucket
    /// has exactly one lane: a request's lanes can only contain that one.
    pub(super) fn claim_only(
        &mut self,
        selection: MuxSelection,
        cap: usize,
        waiting: Option<&Waiting>,
    ) -> Option<(OnlyLane, Option<Claimed<C, ID>>)> {
        let Self {
            unrestricted,
            keyed,
            rr_after,
            ..
        } = self;
        let (only, lane) = match keyed.as_mut_slice() {
            [] if !unrestricted.conns.is_empty() => (OnlyLane::Unrestricted, unrestricted),
            [class] if unrestricted.conns.is_empty() && class.lanes.len() == 1 => {
                let (key, lane) = class.lanes.iter_mut().next()?;
                (OnlyLane::Keyed(key.clone()), lane)
            }
            _ => return None,
        };
        let admitted = lane
            .waiters
            .admits(waiting.and_then(|waiting| waiting.waiter_in(&lane.waiters)));
        let claimed = admitted
            .then(|| lane.pick(selection, cap, &[], *rr_after))
            .flatten()
            .and_then(|pick| {
                if matches!(selection, MuxSelection::RoundRobin) {
                    *rr_after = Some(pick.seq);
                }
                lane.take(pick.seq, cap)
            })
            .map(Claimed::new);
        Some((only, claimed))
    }

    /// Claim the connection the selection strategy prefers across all of the
    /// request's lanes, as if they were one index in creation order.
    pub(super) fn claim(
        &mut self,
        request: &RequestLanes,
        selection: MuxSelection,
        cap: usize,
        skip: &[u64],
        waiting: Option<&Waiting>,
    ) -> Option<Claimed<C, ID>> {
        let rr_after = self.rr_after;
        let mut lanes = self.request_lanes_mut(request);
        let mut best: Option<(usize, Pick)> = None;
        for (index, lane) in lanes.iter_mut().enumerate() {
            if !lane
                .waiters
                .admits(waiting.and_then(|waiting| waiting.waiter_in(&lane.waiters)))
            {
                continue;
            }
            let Some(pick) = lane.pick(selection, cap, skip, rr_after) else {
                continue;
            };
            if best.is_none_or(|(_, best)| pick.beats(best, selection)) {
                best = Some((index, pick));
            }
        }
        let (index, pick) = best?;
        let claimed = lanes[index].take(pick.seq, cap).map(Claimed::new);
        drop(lanes);
        if matches!(selection, MuxSelection::RoundRobin) {
            self.rr_after = Some(pick.seq);
        }
        claimed
    }

    pub(super) fn class_mut(&mut self, classifier: &ReuseKey) -> Option<&mut ClassLanes<C, ID>> {
        self.keyed
            .iter_mut()
            .find(|class| &class.classifier == classifier)
    }

    pub(super) fn lane_mut(&mut self, lane: &LaneKey) -> Option<&mut Lane<C, ID>> {
        match lane {
            LaneKey::Unrestricted => Some(&mut self.unrestricted),
            LaneKey::Keyed(keyed) => self
                .class_mut(keyed.class.classifier())?
                .lanes
                .get_mut(&keyed.key),
        }
    }

    /// The request's lanes the bucket has connections in: the lane of its key
    /// in each class, then the unrestricted lane. A request has one key per
    /// class, so these are distinct lanes, each looked up once.
    pub(super) fn request_lanes_mut<'a>(
        &'a mut self,
        request: &RequestLanes,
    ) -> RequestLanesMut<'a, C, ID> {
        // Keys derived from this very snapshot sit at the same index.
        let aligned = request
            .classes
            .as_ref()
            .is_some_and(|classes| Arc::ptr_eq(classes, &self.classes));
        let classes = request.classes.as_deref().unwrap_or_default();
        let mut lanes = RequestLanesMut::new();
        for (index, class) in self.keyed.iter_mut().enumerate() {
            let derived = if aligned {
                Some(index)
            } else {
                classes
                    .iter()
                    .position(|derived| derived.classifier() == &class.classifier)
            };
            if let Some(key) = derived
                .and_then(|derived| request.keys.get(derived))
                .and_then(Option::as_ref)
                && let Some(lane) = class.lanes.get_mut(key)
            {
                lanes.push(lane);
            }
        }
        if !self.unrestricted.conns.is_empty() {
            lanes.push(&mut self.unrestricted);
        }
        lanes
    }

    /// Store `conn` in `lane`.
    pub(super) fn insert(&mut self, conn: &Arc<StoredConnection<C, ID>>, lane: LaneKey) {
        *conn.lane.lock() = Some(lane.clone());
        conn.filed.store(true, Ordering::Relaxed);
        let LaneKey::Keyed(keyed) = lane else {
            self.unrestricted.insert(conn);
            return;
        };
        let KeyedLane { class, key } = *keyed;
        let known = self
            .keyed
            .iter()
            .position(|known| &known.classifier == class.classifier());
        let index = known.unwrap_or_else(|| {
            self.keyed.push(ClassLanes {
                classifier: class.classifier().clone(),
                lanes: HashMap::new(),
            });
            self.classes = self.classes.iter().cloned().chain([class]).collect();
            self.keyed.len() - 1
        });
        self.keyed[index]
            .lanes
            .entry(key)
            .or_insert_with(Lane::new)
            .insert(conn);
    }

    /// List `conn` in its lane as having room, if it is stored and has room.
    pub(super) fn list(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        let lane = conn.lane.lock();
        if let Some(stored) = lane.as_ref().and_then(|lane| self.lane_mut(lane)) {
            stored.list(conn);
        }
    }

    /// Take `conn` out of the bucket, if it is stored in it.
    pub(super) fn remove(
        &mut self,
        conn: &StoredConnection<C, ID>,
    ) -> Option<Arc<StoredConnection<C, ID>>> {
        let mut filed = conn.lane.lock();
        let lane = filed.as_ref()?;
        let stored = self.lane_mut(lane)?;
        let removed = stored.remove_at(stored.position(conn)?);
        if let Some(LaneKey::Keyed(keyed)) = filed.take() {
            drop(filed);
            self.drop_lane_if_empty(keyed.class.classifier(), &keyed.key);
        }
        Some(removed)
    }

    pub(super) fn drop_lane_if_empty(&mut self, classifier: &ReuseKey, key: &ReuseKey) {
        let Some(index) = self
            .keyed
            .iter()
            .position(|class| &class.classifier == classifier)
        else {
            return;
        };
        let lanes = &mut self.keyed[index].lanes;
        if lanes.get(key).is_some_and(|lane| lane.conns.is_empty()) {
            lanes.remove(key);
        }
        if lanes.is_empty() {
            self.remove_class(index);
        }
    }

    pub(super) fn remove_class(&mut self, index: usize) {
        self.keyed.remove(index);
        self.classes = self
            .classes
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, class)| class.clone())
            .collect();
    }

    /// Keep only the connections `keep` accepts, dropping emptied lanes.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Arc<StoredConnection<C, ID>>) -> bool) {
        self.unrestricted.retain(&mut keep);
        let mut index = 0;
        while index < self.keyed.len() {
            let lanes = &mut self.keyed[index].lanes;
            lanes.retain(|_, lane| {
                lane.retain(&mut keep);
                !lane.conns.is_empty()
            });
            if lanes.is_empty() {
                self.remove_class(index);
            } else {
                index += 1;
            }
        }
    }

    /// The bucket's only lane, for tests of single-lane buckets.
    #[cfg(test)]
    pub(super) fn only_lane(&self) -> &Lane<C, ID> {
        let mut lanes = self.lanes().filter(|lane| !lane.conns.is_empty());
        let lane = lanes.next().expect("a lane");
        assert!(lanes.next().is_none(), "expected a single lane");
        lane
    }
}

/// Select a connection from `same_id` (all sharing `id`) that still has capacity
/// and admit a stream on it (see [`StoredConnection::try_create_multiplexed`]),
/// returning a ready handout. Admission locks only the chosen connection's slot.
pub(super) fn select_and_admit<C: ExtensionsRef, ID: PartialEq + Debug>(
    same_id: &[(Arc<StoredConnection<C, ID>>, u64)],
    id: &ID,
    selection: MuxSelection,
    rr_cursor: &AtomicUsize,
    cap: usize,
    input: &Extensions,
) -> Option<MultiplexedConnection<C, ID>> {
    debug_assert!(same_id.iter().all(|(conn, _)| &conn.id == id), "{id:?}");
    let has_capacity = |(conn, _): &(Arc<StoredConnection<C, ID>>, u64)| {
        conn.active.load(Ordering::Relaxed) < conn.effective_capacity(cap)
    };
    let preferred = match selection {
        MuxSelection::FirstAvailable => None,
        MuxSelection::LeastLoaded => same_id
            .iter()
            .enumerate()
            .filter(|(_, entry)| has_capacity(entry))
            .min_by_key(|(_, (conn, _))| conn.active.load(Ordering::Relaxed))
            .map(|(index, _)| index),
        MuxSelection::RoundRobin => {
            let count = same_id.iter().filter(|entry| has_capacity(entry)).count();
            if count == 0 {
                return None;
            }
            let position = rr_cursor.fetch_add(1, Ordering::Relaxed) % count;
            same_id
                .iter()
                .enumerate()
                .filter(|(_, entry)| has_capacity(entry))
                .nth(position)
                .map(|(index, _)| index)
        }
    };
    // Try the preferred candidate once, then the others without allocating an
    // ordering buffer. A resource reservation is never taken for a full slot.
    for index in preferred
        .into_iter()
        .chain((0..same_id.len()).filter(|index| Some(*index) != preferred))
    {
        let entry = &same_id[index];
        if has_capacity(entry)
            && let Some(handout) = entry.0.try_create_multiplexed(entry.1, cap, input)
        {
            return Some(handout);
        }
    }
    None
}
