#![expect(
    clippy::unwrap_used,
    clippy::unreachable,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{AllocProfiler, black_box, counter::ItemsCount};
use rama::{
    ServiceInput,
    extensions::{Extensions, ExtensionsRef as _},
    net::{
        client::pool::{
            ConnID, ConnectionResult, ConnectionReuse, ConnectionReusePolicy, LruDropPool,
            MultiplexPool, Pool,
        },
        conn::MaxConcurrency,
    },
};
use std::{
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

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
    let pool = Arc::new(MultiplexPool::<ServiceInput<()>, HostId>::new(
        NonZeroUsize::new(usize::MAX).unwrap(),
        NonZeroUsize::new(resident).unwrap(),
    ));
    for n in 0..resident {
        let id = HostId::nth(n);
        let permit = match pool.get_conn(&id, &EMPTY_INPUT).await.unwrap() {
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
    let handout = match pool.get_conn(id, &EMPTY_INPUT).await.unwrap() {
        ConnectionResult::Connection(handout) => handout,
        ConnectionResult::CreatePermit(_) => unreachable!("the id has an idle connection"),
    };
    black_box(handout);
}

async fn miss_evicts_lru(pool: &MultiplexPool<ServiceInput<()>, HostId>, id: HostId) {
    let permit = match pool.get_conn(&id, &EMPTY_INPUT).await.unwrap() {
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

async fn hand_off_one_stream_at_a_time(waiters: usize) {
    let pool = Arc::new(MultiplexPool::<ServiceInput<()>, BenchId>::new(
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(1).unwrap(),
    ));
    let permit = match pool.get_conn(&BenchId(0), &EMPTY_INPUT).await.unwrap() {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => unreachable!("a fresh pool is empty"),
    };
    let connection = ServiceInput::new(());
    connection.extensions().insert(MaxConcurrency::new(1));
    let held = pool
        .create(BenchId(0), connection, permit, &Extensions::new())
        .await
        .unwrap();

    let mut tasks = Vec::with_capacity(waiters);
    for _ in 0..waiters {
        let pool = Arc::clone(&pool);
        tasks.push(tokio::spawn(async move {
            let handout = match pool.get_conn(&BenchId(0), &EMPTY_INPUT).await.unwrap() {
                ConnectionResult::Connection(handout) => handout,
                ConnectionResult::CreatePermit(_) => {
                    unreachable!("the sole connection remains in the pool")
                }
            };
            black_box(handout);
        }));
    }
    tokio::task::yield_now().await;
    drop(held);
    for task in tasks {
        task.await.unwrap();
    }
}

async fn hand_off_streams_for_two_ids(waiters_per_id: usize) {
    let pool = Arc::new(MultiplexPool::<ServiceInput<()>, BenchId>::new(
        NonZeroUsize::new(2).unwrap(),
        NonZeroUsize::new(2).unwrap(),
    ));

    let mut anchors = Vec::with_capacity(2);
    let mut releases = Vec::with_capacity(2);
    for id in 0..2 {
        let id = BenchId(id);
        let permit = match pool.get_conn(&id, &EMPTY_INPUT).await.unwrap() {
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
        releases.push(match pool.get_conn(&id, &EMPTY_INPUT).await.unwrap() {
            ConnectionResult::Connection(handout) => handout,
            ConnectionResult::CreatePermit(_) => {
                unreachable!("the connection has spare capacity")
            }
        });
    }

    let mut tasks = Vec::with_capacity(waiters_per_id * 2);
    for _ in 0..waiters_per_id {
        // Register the IDs in the opposite order of their storage so a global
        // wake-up cannot rely on coincidental waiter/connection ordering.
        for id in [BenchId(1), BenchId(0)] {
            let pool = Arc::clone(&pool);
            tasks.push(tokio::spawn(async move {
                let handout = match pool.get_conn(&id, &EMPTY_INPUT).await.unwrap() {
                    ConnectionResult::Connection(handout) => handout,
                    ConnectionResult::CreatePermit(_) => {
                        unreachable!("both pool slots remain occupied")
                    }
                };
                black_box(handout);
            }));
        }
    }
    tokio::task::yield_now().await;
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
        .build()
        .unwrap();
    bencher
        .counter(ItemsCount::new(waiters_per_id * 2))
        .bench_local(|| runtime.block_on(hand_off_streams_for_two_ids(waiters_per_id)));
}

#[derive(Debug)]
struct EstablishedPolicy;

impl ConnectionReusePolicy for EstablishedPolicy {
    fn matches(&self, input: &Extensions) -> bool {
        input
            .get_ref::<MaxConcurrency>()
            .is_some_and(|limit| limit.get() == 4)
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
                pool.get_conn(&BenchId(0), &input).await.unwrap()
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
                pool.get_conn(&BenchId(0), &input).await.unwrap()
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
    let pool = MultiplexPool::<ServiceInput<()>, BenchId>::try_new(1, resident).unwrap();
    let input = Extensions::new();
    input.insert(MaxConcurrency::new(4));
    runtime.block_on(async {
        let mut held = Vec::with_capacity(resident);
        for _ in 0..resident {
            let ConnectionResult::CreatePermit(permit) =
                pool.get_conn(&BenchId(0), &input).await.unwrap()
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
                pool.get_conn(&BenchId(0), &input).await.unwrap()
            else {
                unreachable!("resident connections have capacity");
            };
            black_box(conn);
        })
    });
}

#[divan::bench(args = [1_usize, 16, 128], sample_count = 100)]
fn multiplex_policy_hit(bencher: divan::Bencher, resident: usize) {
    bench_multiplex_same_id(bencher, resident, true);
}

#[divan::bench(args = [1_usize, 16, 128], sample_count = 100)]
fn multiplex_plain_hit(bencher: divan::Bencher, resident: usize) {
    bench_multiplex_same_id(bencher, resident, false);
}
