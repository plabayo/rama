#![expect(
    clippy::unwrap_used,
    clippy::unreachable,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{black_box, counter::ItemsCount};
use rama::{
    ServiceInput,
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef as _},
    net::{
        client::pool::{
            ConnID, ConnectionAdmission, ConnectionAdmissionLease, ConnectionAdmissionPolicy,
            ConnectionResult, ConnectionReuse, ConnectionReusePolicy, LruDropPool, MultiplexPool,
            MuxSelection, Pool, ReuseKey, SaturationPolicy,
        },
        conn::MaxConcurrency,
    },
    utils::reactive::{Change, ChangeListener, ChangeSignal},
};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

mod bench_alloc;

/// A pool of at most `streams` per connection and `total` connections, with
/// the default saturation policy.
fn limited<ID: ConnID>(streams: usize, total: usize) -> MultiplexPool<ServiceInput<()>, ID> {
    MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(streams).unwrap())
        .with_max_connections_total(NonZeroUsize::new(total).unwrap())
}

/// A pool of at most `streams` per connection and `total` connections that
/// evicts an idle connection whenever a checkout needs a slot.
fn evicting<ID: ConnID>(streams: usize, total: usize) -> MultiplexPool<ServiceInput<()>, ID> {
    MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(streams).unwrap())
        .with_max_connections_total(NonZeroUsize::new(total).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BenchId(u8);

impl ConnID for BenchId {}

/// String-keyed id, shaped like the authority-based ids a proxy pools on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct HostId(String);

impl ConnID for HostId {}

impl HostId {
    fn nth(n: usize) -> Self {
        Self(format!("host-{n}.example.com:443"))
    }
}

fn main() {
    divan::main();
}

static EMPTY_INPUT: LazyLock<Extensions> = LazyLock::new(Extensions::new);

const RESIDENT_IDS: &[usize] = &[1, 256, 4096];

/// A pool holding one idle connection for each of `resident` distinct ids.
async fn pool_with_resident_ids(resident: usize) -> Arc<MultiplexPool<ServiceInput<()>, HostId>> {
    let pool = Arc::new(evicting::<HostId>(usize::MAX, resident));
    for n in 0..resident {
        let id = HostId::nth(n);
        let permit = match pool.get_conn(&id, &EMPTY_INPUT, None).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => unreachable!("this id has no connection yet"),
        };
        drop(
            pool.create(id, ServiceInput::new(()), permit, &Extensions::new())
                .await
                .unwrap(),
        );
    }
    pool
}

async fn hit_resident_id(pool: &MultiplexPool<ServiceInput<()>, HostId>, id: &HostId) {
    let handout = match pool.get_conn(id, &EMPTY_INPUT, None).await.unwrap() {
        ConnectionResult::Connection(handout) => handout,
        ConnectionResult::CreatePermit(_) => unreachable!("the id has an idle connection"),
    };
    black_box(handout);
}

async fn miss_evicts_lru(pool: &MultiplexPool<ServiceInput<()>, HostId>, id: HostId) {
    let permit = match pool.get_conn(&id, &EMPTY_INPUT, None).await.unwrap() {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => unreachable!("a fresh id has no connection"),
    };
    drop(
        pool.create(id, ServiceInput::new(()), permit, &Extensions::new())
            .await
            .unwrap(),
    );
}

/// Pool hit on one id while many other ids are resident: must not scale with
/// the pool size.
#[divan::bench(args = RESIDENT_IDS, sample_count = 100)]
fn multiplex_hit_with_resident_ids(bencher: divan::Bencher, resident: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = runtime.block_on(pool_with_resident_ids(resident));
    let id = HostId::nth(resident / 2);
    bencher.bench_local(|| runtime.block_on(hit_resident_id(&pool, &id)));
}

/// Pool miss for a new id on a full pool: the LRU eviction slow path, which
/// scans every resident connection.
#[divan::bench(args = RESIDENT_IDS, sample_count = 100)]
fn multiplex_miss_evicts_lru(bencher: divan::Bencher, resident: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = runtime.block_on(pool_with_resident_ids(resident));
    let mut next = resident;
    bencher.bench_local(|| {
        next += 1;
        runtime.block_on(miss_evicts_lru(&pool, HostId::nth(next)))
    });
}

/// Until every one of `waiters` tasks was polled once, so all of them wait in
/// the pool: a scheduler tick polls only so many tasks before yielding back.
async fn park_all(started: &AtomicUsize, waiters: usize) {
    while started.load(Ordering::Relaxed) < waiters {
        tokio::task::yield_now().await;
    }
}

async fn hand_off_one_stream_at_a_time(waiters: usize) {
    let pool = Arc::new(limited::<BenchId>(1, 1));
    let permit = match pool
        .get_conn(&BenchId(0), &EMPTY_INPUT, None)
        .await
        .unwrap()
    {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => unreachable!("a fresh pool is empty"),
    };
    let connection = ServiceInput::new(());
    connection.extensions().insert(MaxConcurrency::new(1));
    let held = pool
        .create(BenchId(0), connection, permit, &Extensions::new())
        .await
        .unwrap();

    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(waiters);
    for _ in 0..waiters {
        let pool = Arc::clone(&pool);
        let started = Arc::clone(&started);
        tasks.push(tokio::spawn(async move {
            started.fetch_add(1, Ordering::Relaxed);
            let handout = match pool
                .get_conn(&BenchId(0), &EMPTY_INPUT, None)
                .await
                .unwrap()
            {
                ConnectionResult::Connection(handout) => handout,
                ConnectionResult::CreatePermit(_) => {
                    unreachable!("the sole connection remains in the pool")
                }
            };
            black_box(handout);
        }));
    }
    park_all(&started, waiters).await;
    drop(held);
    for task in tasks {
        task.await.unwrap();
    }
}

async fn hand_off_streams_for_two_ids(waiters_per_id: usize) {
    let pool = Arc::new(limited::<BenchId>(2, 2));

    let mut anchors = Vec::with_capacity(2);
    let mut releases = Vec::with_capacity(2);
    for id in 0..2 {
        let id = BenchId(id);
        let permit = match pool.get_conn(&id, &EMPTY_INPUT, None).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => unreachable!("this ID has no connection yet"),
        };
        let connection = ServiceInput::new(());
        connection.extensions().insert(MaxConcurrency::new(2));
        anchors.push(
            pool.create(id.clone(), connection, permit, &Extensions::new())
                .await
                .unwrap(),
        );
        releases.push(
            match pool.get_conn(&id, &EMPTY_INPUT, None).await.unwrap() {
                ConnectionResult::Connection(handout) => handout,
                ConnectionResult::CreatePermit(_) => {
                    unreachable!("the connection has spare capacity")
                }
            },
        );
    }

    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(waiters_per_id * 2);
    for _ in 0..waiters_per_id {
        // Register the IDs in the opposite order of their storage so a global
        // wake-up cannot rely on coincidental waiter/connection ordering.
        for id in [BenchId(1), BenchId(0)] {
            let pool = Arc::clone(&pool);
            let started = Arc::clone(&started);
            tasks.push(tokio::spawn(async move {
                started.fetch_add(1, Ordering::Relaxed);
                let handout = match pool.get_conn(&id, &EMPTY_INPUT, None).await.unwrap() {
                    ConnectionResult::Connection(handout) => handout,
                    ConnectionResult::CreatePermit(_) => {
                        unreachable!("both pool slots remain occupied")
                    }
                };
                black_box(handout);
            }));
        }
    }
    park_all(&started, waiters_per_id * 2).await;
    drop(releases);
    for task in tasks {
        task.await.unwrap();
    }
    drop(anchors);
}

/// Measures FIFO waiter progress on one saturated multiplexed connection.
#[divan::bench(args = [1_usize, 8, 64], sample_count = 50)]
fn multiplex_waiter_handoff(bencher: divan::Bencher, waiters: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    bencher
        .counter(ItemsCount::new(waiters))
        .bench_local(|| runtime.block_on(hand_off_one_stream_at_a_time(waiters)));
}

/// Measures targeted stream handoff with incompatible waiters parked on a
/// second saturated connection ID.
#[divan::bench(args = [1_usize, 8, 64], sample_count = 50)]
fn multiplex_two_id_waiter_handoff(bencher: divan::Bencher, waiters_per_id: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    bencher
        .counter(ItemsCount::new(waiters_per_id * 2))
        .bench_local(|| runtime.block_on(hand_off_streams_for_two_ids(waiters_per_id)));
}

#[derive(Debug)]
struct EstablishedPolicy;

impl ConnectionReusePolicy for EstablishedPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<MaxConcurrency>(4))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let limit = input.get_ref::<MaxConcurrency>()?;
        Some(ReuseKey::from_bits::<MaxConcurrency>(limit.get() as u128))
    }
}

/// First-compatible checkout with independently published per-connection policy
/// metadata. Increasing idle connections must not add allocation or policy scans.
#[divan::bench(args = [1_usize, 16, 128], sample_count = 100)]
fn exclusive_policy_hit(bencher: divan::Bencher, resident: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = LruDropPool::<ServiceInput<()>, BenchId>::try_new(resident, resident)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let input = Extensions::new();
    input.insert(MaxConcurrency::new(4));
    runtime.block_on(async {
        let mut held = Vec::with_capacity(resident);
        for _ in 0..resident {
            let ConnectionResult::CreatePermit(permit) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("all previous connections are still leased");
            };
            let conn = ServiceInput::new(());
            conn.extensions()
                .insert(ConnectionReuse::new(EstablishedPolicy));
            held.push(
                pool.create(BenchId(0), conn, permit, &Extensions::new())
                    .await
                    .unwrap(),
            );
        }
        drop(held);
    });
    bencher.bench_local(|| {
        runtime.block_on(async {
            let ConnectionResult::Connection(conn) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("all resident policies are compatible");
            };
            black_box(conn);
        })
    });
}

fn bench_multiplex_same_id(bencher: divan::Bencher, resident: usize, with_policy: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = evicting::<BenchId>(1, resident);
    let input = Extensions::new();
    input.insert(MaxConcurrency::new(4));
    runtime.block_on(async {
        let mut held = Vec::with_capacity(resident);
        for _ in 0..resident {
            let ConnectionResult::CreatePermit(permit) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("all previous connections are at capacity");
            };
            let conn = ServiceInput::new(());
            if with_policy {
                conn.extensions()
                    .insert(ConnectionReuse::new(EstablishedPolicy));
            }
            held.push(
                pool.create(BenchId(0), conn, permit, &Extensions::new())
                    .await
                    .unwrap(),
            );
        }
        drop(held);
    });
    bencher.bench_local(|| {
        runtime.block_on(async {
            let ConnectionResult::Connection(conn) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("resident connections have capacity");
            };
            black_box(conn);
        })
    });
}

#[divan::bench(args = [1_usize, 16, 128, 1024], sample_count = 100)]
fn multiplex_policy_hit(bencher: divan::Bencher, resident: usize) {
    bench_multiplex_same_id(bencher, resident, true);
}

#[divan::bench(args = [1_usize, 16, 128, 1024], sample_count = 100)]
fn multiplex_plain_hit(bencher: divan::Bencher, resident: usize) {
    bench_multiplex_same_id(bencher, resident, false);
}

/// Concurrent checkout of one id served by many resident, mostly idle,
/// exclusive (capacity one) connections, the shape of an HTTP/1 origin behind a
/// forward proxy after a load burst. Each thread repeatedly checks out and
/// releases a connection, so the pool's lock and per-checkout work are the only
/// shared cost.
fn bench_multiplex_contended_checkout(
    bencher: divan::Bencher,
    threads: usize,
    resident: usize,
    selection: MuxSelection,
) {
    const CHECKOUTS_PER_THREAD: usize = 2_000;

    let pool = Arc::new(evicting::<BenchId>(1, resident).with_selection(selection));
    let setup = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    setup.block_on(async {
        let mut held = Vec::with_capacity(resident);
        for _ in 0..resident {
            let ConnectionResult::CreatePermit(permit) = pool
                .get_conn(&BenchId(0), &EMPTY_INPUT, None)
                .await
                .unwrap()
            else {
                unreachable!("all previous connections are at capacity");
            };
            held.push(
                pool.create(
                    BenchId(0),
                    ServiceInput::new(()),
                    permit,
                    &Extensions::new(),
                )
                .await
                .unwrap(),
            );
        }
        drop(held);
    });

    bencher
        .counter(ItemsCount::new(threads * CHECKOUTS_PER_THREAD))
        .bench_local(|| {
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    let pool = &pool;
                    scope.spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .build()
                            .unwrap();
                        runtime.block_on(async {
                            for _ in 0..CHECKOUTS_PER_THREAD {
                                let ConnectionResult::Connection(conn) = pool
                                    .get_conn(&BenchId(0), &EMPTY_INPUT, None)
                                    .await
                                    .unwrap()
                                else {
                                    unreachable!("resident connections are idle");
                                };
                                black_box(conn);
                            }
                        });
                    });
                }
            });
        });
}

#[divan::bench(args = [(1_usize, 64_usize), (4, 64), (4, 1024), (8, 1024)], sample_count = 20)]
fn multiplex_contended_checkout_least_loaded(
    bencher: divan::Bencher,
    (threads, resident): (usize, usize),
) {
    bench_multiplex_contended_checkout(bencher, threads, resident, MuxSelection::LeastLoaded);
}

#[divan::bench(args = [(4_usize, 1024_usize)], sample_count = 20)]
fn multiplex_contended_checkout_round_robin(
    bencher: divan::Bencher,
    (threads, resident): (usize, usize),
) {
    bench_multiplex_contended_checkout(bencher, threads, resident, MuxSelection::RoundRobin);
}

/// The reuse class a request asks for, like a TLS profile under one origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
struct Class(usize);

/// Reusable only by requests of the class the connection was established for.
#[derive(Debug)]
struct ClassPolicy(Class);

impl ConnectionReusePolicy for ClassPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<Class>(self.0.0 as u128))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let class = input.get_ref::<Class>()?;
        Some(ReuseKey::from_bits::<Class>(class.0 as u128))
    }
}

/// Checkout on one id whose `resident` idle exclusive connections are spread
/// over `classes` incompatible reuse classes, the shape of one origin behind a
/// MITM proxy that emulates several client TLS profiles. The request asks for
/// the class of the newest connections.
#[divan::bench(
    args = [(64_usize, 1_usize), (64, 8), (1024, 8), (1024, 64)],
    sample_count = 100
)]
fn multiplex_mixed_class_hit(bencher: divan::Bencher, (resident, classes): (usize, usize)) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = evicting::<BenchId>(1, resident);
    runtime.block_on(async {
        let mut held = Vec::with_capacity(resident);
        for n in 0..resident {
            let class = Class(n % classes);
            let input = Extensions::new();
            input.insert(class);
            let ConnectionResult::CreatePermit(permit) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("all previous connections are leased");
            };
            let conn = ServiceInput::new(());
            conn.extensions()
                .insert(ConnectionReuse::new(ClassPolicy(class)));
            held.push(pool.create(BenchId(0), conn, permit, &input).await.unwrap());
        }
        drop(held);
    });
    let input = Extensions::new();
    input.insert(Class(classes - 1));
    bencher.bench_local(|| {
        runtime.block_on(async {
            let ConnectionResult::Connection(conn) =
                pool.get_conn(&BenchId(0), &input, None).await.unwrap()
            else {
                unreachable!("an idle connection of the class is resident");
            };
            black_box(conn);
        })
    });
}

/// Transport credit like an h2/h3 connection's: `limit` concurrent requests,
/// returned when a lease drops.
#[derive(Debug)]
struct Credit {
    available: AtomicUsize,
    returned: ChangeSignal,
}

#[derive(Debug, Clone, Extension)]
struct CreditBinding;

struct CreditLease(Arc<Credit>);

impl Drop for CreditLease {
    fn drop(&mut self) {
        self.0.available.fetch_add(1, Ordering::AcqRel);
        self.0.returned.notify(Change::Freed);
    }
}

#[derive(Debug)]
struct CreditAdmission(Arc<Credit>);

impl ConnectionAdmissionPolicy for CreditAdmission {
    fn try_acquire(
        &self,
        _input: &Extensions,
    ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        let mut available = self.0.available.load(Ordering::Acquire);
        loop {
            if available == 0 {
                return Ok(None);
            }
            match self.0.available.compare_exchange(
                available,
                available - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Some(ConnectionAdmissionLease::new(
                        Arc::new(CreditLease(self.0.clone())),
                        CreditBinding,
                    )));
                }
                Err(now) => available = now,
            }
        }
    }

    fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.returned.subscribe(listener);
    }

    fn in_use(&self) -> bool {
        false
    }
}

/// A connection like the connectors publish: exclusive (h1) or multiplexed
/// with transport credit (h2/h3).
fn connection(streams: usize) -> ServiceInput<()> {
    let conn = ServiceInput::new(());
    conn.extensions().insert(MaxConcurrency::new(streams));
    if streams > 1 {
        conn.extensions()
            .insert(ConnectionAdmission::new(CreditAdmission(Arc::new(
                Credit {
                    available: AtomicUsize::new(streams),
                    returned: ChangeSignal::new(),
                },
            ))));
    }
    conn
}

/// `clients` tasks on a multi-thread runtime each do `rounds` checkouts over
/// `ids` ids, holding every handout across `hold` yields, against a pool of
/// `max_total` connections of `streams` streams each. Saturated whenever the
/// clients outnumber the streams: the wait path is what is measured.
fn bench_saturated(
    bencher: divan::Bencher,
    clients: usize,
    ids: usize,
    max_total: usize,
    streams: usize,
    hold: usize,
    policy: SaturationPolicy,
) {
    const ROUNDS: usize = 64;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_time()
        .build()
        .unwrap();
    bencher
        .counter(ItemsCount::new(clients * ROUNDS))
        .bench_local(|| {
            runtime.block_on(async {
                let pool = Arc::new(
                    MultiplexPool::<ServiceInput<()>, BenchId>::new()
                        .with_max_connections_total(NonZeroUsize::new(max_total).unwrap())
                        .with_saturation_policy(policy),
                );
                let mut tasks = Vec::with_capacity(clients);
                for client in 0..clients {
                    let pool = pool.clone();
                    #[expect(clippy::cast_possible_truncation, reason = "bench ids are small")]
                    let id = BenchId((client % ids) as u8);
                    tasks.push(tokio::spawn(async move {
                        for _ in 0..ROUNDS {
                            let handout = match pool
                                .get_conn(&id, &EMPTY_INPUT, None)
                                .await
                                .unwrap()
                            {
                                ConnectionResult::Connection(handout) => handout,
                                ConnectionResult::CreatePermit(permit) => pool
                                    .create(id.clone(), connection(streams), permit, &EMPTY_INPUT)
                                    .await
                                    .unwrap(),
                            };
                            for _ in 0..hold {
                                tokio::task::yield_now().await;
                            }
                            black_box(handout);
                        }
                    }));
                }
                for task in tasks {
                    task.await.unwrap();
                }
            })
        });
}

/// Exclusive (h1) connections, more clients than the pool holds: the shape of
/// a forward proxy at `EasyHttpWebClient`'s default `max_total` of 50.
#[divan::bench(
    args = [(256_usize, 1_usize), (256, 4), (256, 16), (1024, 4)],
    sample_count = 10
)]
fn multiplex_saturated_exclusive(bencher: divan::Bencher, (clients, ids): (usize, usize)) {
    bench_saturated(bencher, clients, ids, 50, 1, 2, SaturationPolicy::default());
}

/// As [`multiplex_saturated_exclusive`], closing another id's idle connection
/// whenever a checkout needs a slot: the evict-and-dial churn the default avoids.
#[divan::bench(args = [(256_usize, 1_usize), (256, 4)], sample_count = 10)]
fn multiplex_saturated_exclusive_evict_idle(
    bencher: divan::Bencher,
    (clients, ids): (usize, usize),
) {
    bench_saturated(bencher, clients, ids, 50, 1, 2, SaturationPolicy::EvictIdle);
}

/// Multiplexed connections with transport credit (h2/h3 shaped), saturated:
/// 4 connections of 16 streams for 256 clients.
#[divan::bench(args = [1_usize, 4], sample_count = 10)]
fn multiplex_saturated_credit(bencher: divan::Bencher, ids: usize) {
    bench_saturated(bencher, 256, ids, 4, 16, 2, SaturationPolicy::default());
}
