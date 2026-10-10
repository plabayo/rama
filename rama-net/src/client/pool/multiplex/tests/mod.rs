use super::*;

use crate::client::pool::{
    ConnectionAdmissionPolicy, ConnectionReusePolicy, LruDropPool, PooledConnector,
};

use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection,
};

use rama_core::error::BoxErrorExt as _;

use rama_core::{ServiceInput, service::service_fn};

use rama_utils::reactive::ChangeSignal;

use std::assert_matches;

use std::{
    convert::Infallible,
    pin::Pin,
    sync::{LazyLock, Weak, atomic::AtomicBool},
    task::Poll,
};

mod admission;
mod checkout;
mod coalescing;
mod eviction;
mod fairness;
mod lanes;
mod limits;
mod listing;
mod waiting;

static EMPTY_INPUT: LazyLock<Extensions> = LazyLock::new(Extensions::new);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TestId(u32);

impl ConnID for TestId {
    fn is_reusable(&self) -> bool {
        self.0 != u32::MAX
    }
}

#[derive(Debug)]
struct Conn {
    serial: usize,
    extensions: Extensions,
}

impl ExtensionsRef for Conn {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Service<ServiceInput<()>> for Conn {
    type Output = usize;
    type Error = Infallible;

    async fn serve(&self, _: ServiceInput<()>) -> Result<Self::Output, Self::Error> {
        Ok(self.serial)
    }
}

impl Service<Extensions> for Conn {
    type Output = Extensions;
    type Error = Infallible;

    async fn serve(&self, input: Extensions) -> Result<Self::Output, Self::Error> {
        Ok(input)
    }
}

#[derive(Debug)]
struct AdmissionState {
    limit: AtomicUsize,
    reserved: AtomicUsize,
    failed: AtomicBool,
    in_use: AtomicBool,
    /// How often the pool asked about outliving work.
    asked: AtomicUsize,
    changed: ChangeSignal,
    storage: Weak<Mutex<Storage<Conn, TestId>>>,
}

impl AdmissionState {
    fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::SeqCst);
        self.changed.notify(Change::Other);
    }

    fn set_in_use(&self, in_use: bool) {
        self.in_use.store(in_use, Ordering::SeqCst);
        self.changed.notify(Change::Other);
    }
}

#[derive(Debug)]
struct FakeAdmission(Arc<AdmissionState>);

#[derive(Debug)]
struct Reservation(Arc<AdmissionState>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.reserved.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify(Change::Freed);
    }
}

#[derive(Debug, Extension)]
struct ReservationToken(Weak<Reservation>);

impl ConnectionAdmissionPolicy for FakeAdmission {
    fn try_acquire(
        &self,
        _input: &Extensions,
    ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        if let Some(storage) = self.0.storage.upgrade() {
            assert!(
                storage.try_lock_for(Duration::from_secs(1)).is_some(),
                "resource provider called under storage lock"
            );
        }
        if self.0.failed.load(Ordering::SeqCst) {
            return Err(BoxError::from_static_str("admission failed"));
        }
        if self
            .0
            .reserved
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |reserved| {
                (reserved < self.0.limit.load(Ordering::SeqCst)).then_some(reserved + 1)
            })
            .is_err()
        {
            return Ok(None);
        }
        let reservation = Arc::new(Reservation(self.0.clone()));
        let binding = ReservationToken(Arc::downgrade(&reservation));
        Ok(Some(ConnectionAdmissionLease::new(reservation, binding)))
    }

    fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.changed.subscribe(listener);
    }

    fn in_use(&self) -> bool {
        if let Some(storage) = self.0.storage.upgrade() {
            assert!(
                storage.try_lock_for(Duration::from_secs(1)).is_some(),
                "outliving work asked about under the storage lock"
            );
        }
        self.0.asked.fetch_add(1, Ordering::SeqCst);
        self.0.in_use.load(Ordering::SeqCst)
    }
}

/// The binding of the leases of test admissions that track no reservation.
#[derive(Debug, Extension)]
struct AskToken;

fn admission_connection(
    pool: &MultiplexPool<Conn, TestId>,
    limit: usize,
) -> (Conn, Arc<AdmissionState>) {
    let state = Arc::new(AdmissionState {
        limit: AtomicUsize::new(limit),
        reserved: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        in_use: AtomicBool::new(false),
        asked: AtomicUsize::new(0),
        changed: ChangeSignal::new(),
        storage: Arc::downgrade(&pool.storage),
    });
    let conn = Conn {
        serial: 1,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(FakeAdmission(state.clone())));
    (conn, state)
}

async fn new_slot(pool: &MultiplexPool<Conn, TestId>) -> MultiplexSlot {
    match pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap() {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => panic!("expected an empty pool"),
    }
}

#[derive(Default)]
struct TestConnector {
    created: AtomicUsize,
    max_concurrency: Option<usize>,
}

impl<Input> Service<Input> for TestConnector
where
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<Conn, Input>;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let serial = self.created.fetch_add(1, Ordering::Relaxed);
        let conn = Conn {
            serial,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        if let Some(mc) = self.max_concurrency {
            conn.extensions.insert(MaxConcurrency::new(mc));
        }
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// Like [`TestConnector`] but takes `delay` to establish each connection,
/// so tests can park waiters while a connection is being created.
struct SlowConnector {
    created: AtomicUsize,
    delay: Duration,
}

impl<Input> Service<Input> for SlowConnector
where
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<Conn, Input>;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        tokio::time::sleep(self.delay).await;
        let serial = self.created.fetch_add(1, Ordering::Relaxed);
        let conn = Conn {
            serial,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        Ok(EstablishedClientConnection { input, conn })
    }
}

fn id_fn(input: &ServiceInput<u32>) -> Result<TestId, BoxError> {
    Ok(TestId(input.input))
}

type MuxConnector = PooledConnector<
    TestConnector,
    MultiplexPool<Conn, TestId>,
    fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
>;

fn connector_with(
    pool: MultiplexPool<Conn, TestId>,
    max_concurrency: Option<usize>,
) -> MuxConnector {
    let connector = TestConnector {
        created: AtomicUsize::new(0),
        max_concurrency,
    };
    PooledConnector::new(
        connector,
        pool,
        id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    )
}

fn connector(pool: MultiplexPool<Conn, TestId>) -> MuxConnector {
    // No MaxConcurrency advertised means "no limit"
    connector_with(pool, None)
}

async fn connect(
    svc: &MuxConnector,
    id: u32,
) -> EstablishedClientConnection<MultiplexedConnection<Conn, TestId>, ServiceInput<u32>> {
    svc.connect(ServiceInput::new(id)).await.unwrap()
}

fn created(svc: &MuxConnector) -> usize {
    svc.inner.created.load(Ordering::Relaxed)
}

/// Add a connection publishing the requirements `reuse` builds, as a
/// connector would, to an empty `pool`.
async fn create_with_reuse(
    pool: &MultiplexPool<Conn, TestId>,
    reuse: impl FnOnce(&Conn) -> ConnectionReuse,
) -> MultiplexedConnection<Conn, TestId> {
    let ConnectionResult::CreatePermit(permit) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("expected an empty pool");
    };
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(reuse(&conn));
    pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap()
}

/// The key a request wants from connections keyed by [`KeyPolicy`].
#[derive(Debug, Clone, Copy, Extension)]
struct Want(u8);

#[derive(Debug)]
struct KeyPolicy {
    key: Option<u8>,
    class: u8,
}

impl ConnectionReusePolicy for KeyPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::from_bits::<Self>(self.class.into())
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<Want>(self.key?.into()))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<Want>(
            input.get_ref::<Want>()?.0.into(),
        ))
    }
}

fn keyed(class: u8, key: u8) -> ConnectionReuse {
    ConnectionReuse::new(KeyPolicy {
        key: Some(key),
        class,
    })
}

fn want(key: u8) -> Extensions {
    let input = Extensions::new();
    input.insert(Want(key));
    input
}

/// Add a connection publishing `reuse` (none: unrestricted) under `id`.
async fn add(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
    reuse: Option<ConnectionReuse>,
) -> MultiplexedConnection<Conn, TestId> {
    let permit = pool.test_slot();
    let conn = Conn {
        serial: pool.next_seq.load(Ordering::Relaxed) as usize,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    if let Some(reuse) = reuse {
        conn.extensions.insert(reuse);
    }
    pool.create(TestId(id), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap()
}

type Checkout<'a> = tokio_test::task::Spawn<
    Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ConnectionResult<MultiplexedConnection<Conn, TestId>, MultiplexSlot>,
                        BoxError,
                    >,
                > + Send
                + 'a,
        >,
    >,
>;

/// A checkout of `input`, polled once so it queues if it has to wait.
fn queue<'a>(pool: &'a MultiplexPool<Conn, TestId>, input: &'a Extensions) -> Checkout<'a> {
    let mut checkout = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), input, None))
        as Pin<Box<dyn Future<Output = _> + Send + 'a>>);
    assert!(checkout.poll().is_pending(), "the pool is saturated");
    checkout
}

fn handout(checkout: &mut Checkout<'_>) -> MultiplexedConnection<Conn, TestId> {
    match checkout.poll() {
        Poll::Ready(Ok(ConnectionResult::Connection(conn))) => conn,
        other => panic!("expected a handout, got {other:?}"),
    }
}

/// One exclusive connection, held, in a pool that cannot dial another.
async fn saturated() -> (
    MultiplexPool<Conn, TestId>,
    MultiplexedConnection<Conn, TestId>,
) {
    let pool = MultiplexPool::evicting(1, 1);
    let held = add(&pool, 0, None).await;
    (pool, held)
}

/// Once nothing is in flight each lane's `open` index lists exactly the
/// stored connections that have room, each once, and every stored
/// connection knows its lane.
fn assert_open_matches_capacity(pool: &MultiplexPool<Conn, TestId>) {
    let storage = pool.storage.lock();
    let idle = pool.waiting.load(Ordering::Relaxed) == 0;
    if idle {
        assert!(pool.slot_waiters.is_empty(), "no checkout waits for a slot");
    }
    for bucket in storage.by_id.values() {
        assert!(!bucket.is_empty());
        if idle {
            for lane in bucket.lanes() {
                assert!(lane.waiters.is_empty(), "no checkout waits in a lane");
            }
        }
        let lanes = std::iter::once((LaneKey::Unrestricted, &bucket.unrestricted)).chain(
            bucket
                .keyed
                .iter()
                .zip(bucket.classes.iter())
                .flat_map(|(lanes, class)| {
                    lanes.lanes.iter().map(|(key, lane)| {
                        (
                            LaneKey::Keyed(Box::new(KeyedLane {
                                class: class.clone(),
                                key: key.clone(),
                            })),
                            lane,
                        )
                    })
                }),
        );
        for (key, lane) in lanes {
            assert!(key == LaneKey::Unrestricted || !lane.conns.is_empty());
            for conn in &lane.conns {
                assert_eq!(conn.lane.lock().as_ref(), Some(&key));
                let listed = lane.open.contains_key(&conn.seq);
                assert_eq!(listed, conn.listed.load(Ordering::Relaxed), "{}", conn.seq);
                assert_eq!(
                    listed,
                    conn.has_capacity(pool.max_concurrent_streams),
                    "connection {} is listed iff it has room",
                    conn.seq
                );
            }
            assert!(lane.conns.windows(2).all(|w| w[0].seq < w[1].seq));
            assert!(
                lane.open
                    .keys()
                    .all(|seq| lane.conns.iter().any(|conn| conn.seq == *seq))
            );
        }
        assert_eq!(bucket.classes.len(), bucket.keyed.len());
        for (class, lanes) in bucket.classes.iter().zip(&bucket.keyed) {
            assert_eq!(class.classifier(), &lanes.classifier);
            assert!(!lanes.lanes.is_empty());
        }
    }
}

/// A new exclusive connection for `id`, through the pool's own create permit.
async fn fresh(pool: &MultiplexPool<Conn, TestId>, id: u32) -> MultiplexedConnection<Conn, TestId> {
    let ConnectionResult::CreatePermit(slot) = pool
        .get_conn(&TestId(id), &EMPTY_INPUT, None)
        .await
        .unwrap()
    else {
        panic!("a create permit");
    };
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(ConnectionHealthWatcher::default());
    conn.extensions.insert(MaxConcurrency::new(1));
    pool.create(TestId(id), conn, slot, &EMPTY_INPUT)
        .await
        .unwrap()
}

/// A new exclusive connection of `id` filed under `key`, through the pool's
/// own create permit.
async fn fresh_keyed(
    pool: &MultiplexPool<Conn, TestId>,
    id: u32,
    key: u8,
) -> MultiplexedConnection<Conn, TestId> {
    let input = want(key);
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(id), &input, None).await.unwrap()
    else {
        panic!("a create permit");
    };
    let conn = Conn {
        serial: key.into(),
        extensions: Extensions::new(),
    };
    conn.extensions.insert(keyed(0, key));
    conn.extensions.insert(MaxConcurrency::new(1));
    conn.extensions.insert(ConnectionHealthWatcher::default());
    pool.create(TestId(id), conn, slot, &input).await.unwrap()
}

/// A checkout of `id` wanting `key`, polled once so it queues.
fn queue_keyed<'a>(
    pool: &'a MultiplexPool<Conn, TestId>,
    id: u32,
    input: &'a Extensions,
) -> Checkout<'a> {
    let mut checkout =
        tokio_test::task::spawn(Box::pin(
            async move { pool.get_conn(&TestId(id), input, None).await },
        ) as Pin<Box<dyn Future<Output = _> + Send + 'a>>);
    assert!(checkout.poll().is_pending(), "the pool is saturated");
    checkout
}

/// A pool of `total` exclusive connections at most.
fn exclusive(total: usize, policy: SaturationPolicy) -> MultiplexPool<Conn, TestId> {
    MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(total).unwrap())
        .with_saturation_policy(policy)
}

fn checkout(pool: &MultiplexPool<Conn, TestId>, id: u32) -> Checkout<'_> {
    tokio_test::task::spawn(Box::pin(
        async move { pool.get_conn(&TestId(id), &EMPTY_INPUT, None).await },
    ) as Pin<Box<dyn Future<Output = _> + Send + '_>>)
}

async fn serial_of(handout: &MultiplexedConnection<Conn, TestId>) -> usize {
    handout.serve(ServiceInput::new(())).await.unwrap()
}
