#![expect(
    clippy::unwrap_used,
    clippy::unreachable,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{AllocProfiler, black_box, counter::ItemsCount};
use rama::{
    ServiceInput,
    extensions::ExtensionsRef as _,
    net::{
        client::pool::{ConnID, ConnectionResult, MultiplexPool, Pool},
        conn::MaxConcurrency,
    },
};
use std::{num::NonZeroUsize, sync::Arc};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

#[derive(Clone, Debug, PartialEq)]
struct BenchId(u8);

impl ConnID for BenchId {}

fn main() {
    divan::main();
}

async fn hand_off_one_stream_at_a_time(waiters: usize) {
    let pool = Arc::new(MultiplexPool::<ServiceInput<()>, BenchId>::new(
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(1).unwrap(),
    ));
    let permit = match pool.get_conn(&BenchId(0)).await.unwrap() {
        ConnectionResult::CreatePermit(permit) => permit,
        ConnectionResult::Connection(_) => unreachable!("a fresh pool is empty"),
    };
    let connection = ServiceInput::new(());
    connection.extensions().insert(MaxConcurrency::new(1));
    let held = pool.create(BenchId(0), connection, permit).await;

    let mut tasks = Vec::with_capacity(waiters);
    for _ in 0..waiters {
        let pool = Arc::clone(&pool);
        tasks.push(tokio::spawn(async move {
            let handout = match pool.get_conn(&BenchId(0)).await.unwrap() {
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
        let permit = match pool.get_conn(&id).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => unreachable!("this ID has no connection yet"),
        };
        let connection = ServiceInput::new(());
        connection.extensions().insert(MaxConcurrency::new(2));
        anchors.push(pool.create(id.clone(), connection, permit).await);
        releases.push(match pool.get_conn(&id).await.unwrap() {
            ConnectionResult::Connection(handout) => handout,
            ConnectionResult::CreatePermit(_) => unreachable!("the connection has spare capacity"),
        });
    }

    let mut tasks = Vec::with_capacity(waiters_per_id * 2);
    for _ in 0..waiters_per_id {
        // Register the IDs in the opposite order of their storage so a global
        // wake-up cannot rely on coincidental waiter/connection ordering.
        for id in [BenchId(1), BenchId(0)] {
            let pool = Arc::clone(&pool);
            tasks.push(tokio::spawn(async move {
                let handout = match pool.get_conn(&id).await.unwrap() {
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
