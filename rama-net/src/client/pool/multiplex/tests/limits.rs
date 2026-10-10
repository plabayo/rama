//! Connection limits and the saturation policy.

use super::*;

#[tokio::test]
async fn an_unlimited_pool_adds_connections_as_needed() {
    let pool = MultiplexPool::new();
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(fresh(&pool, 0).await);
    }
    assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 64);
    drop(held);
    let Ok(ConnectionResult::Connection(_)) = pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
    else {
        panic!("an idle connection is reused");
    };
}

fn per_id(max: usize) -> MultiplexPool<Conn, TestId> {
    MultiplexPool::new().with_max_connections_per_id(NonZeroUsize::new(max).unwrap())
}

#[tokio::test]
async fn a_per_id_limit_holds_back_only_that_id() {
    let pool = per_id(1);
    let held = fresh(&pool, 0).await;
    let mut same = queue(&pool, &EMPTY_INPUT);
    let other = fresh(&pool, 1).await;
    drop(held);
    assert!(same.is_woken(), "the id's own connection serves it");
    drop((handout(&mut same), other));
    assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_closed_connection_frees_its_id_slot_for_a_waiter() {
    let pool = per_id(1);
    let held = fresh(&pool, 0).await;
    let mut waiter = queue(&pool, &EMPTY_INPUT);
    held.inner
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    drop(held);
    assert!(waiter.is_woken());
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = waiter.poll() else {
        panic!("the broken connection's slot goes to the waiter");
    };
    assert!(slot.id.is_some(), "the permit carries the id's slot");
    let mut next = queue(&pool, &EMPTY_INPUT);
    drop(slot);
    assert!(next.is_woken(), "an unused permit frees the slot again");
    assert!(matches!(
        next.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn per_id_slots_of_ids_without_connections_are_forgotten() {
    let pool = per_id(1);
    for id in 0..256 {
        drop(fresh(&pool, id).await);
        pool.storage.lock().by_id.clear();
    }
    let kept = pool.storage.lock().id_slots.len();
    assert!(
        kept < 256,
        "slots of ids nothing holds are dropped ({kept} kept)"
    );
}

/// A pool of two exclusive connections: id 0's sits idle, id 1's is held.
async fn full_pool(
    policy: SaturationPolicy,
) -> (
    MultiplexPool<Conn, TestId>,
    MultiplexedConnection<Conn, TestId>,
) {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(policy);
    drop(add(&pool, 0, None).await);
    let busy = add(&pool, 1, None).await;
    (pool, busy)
}

#[tokio::test]
async fn the_wait_policy_never_evicts() {
    let (pool, busy) = full_pool(SaturationPolicy::Wait).await;
    let mut cold = checkout(&pool, 2);
    assert!(cold.poll().is_pending(), "id 0's idle connection stays");
    drop(busy);
    if cold.is_woken() {
        assert!(cold.poll().is_pending(), "still no eviction");
    }
    assert_eq!(pool.storage.lock().by_id.len(), 2);
}

#[tokio::test]
async fn evict_idle_when_cold_evicts_only_for_a_cold_checkout() {
    let (pool, busy) = full_pool(SaturationPolicy::EvictIdleWhenCold).await;
    let mut warm = checkout(&pool, 1);
    assert!(
        warm.poll().is_pending(),
        "id 1 waits for its own connection"
    );
    let mut cold = checkout(&pool, 2);
    assert!(
        matches!(
            cold.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "a warm waiter never holds back a cold checkout"
    );
    drop(busy);
    assert!(warm.is_woken());
    let Poll::Ready(Ok(ConnectionResult::Connection(_))) = warm.poll() else {
        panic!("id 1's own connection serves it");
    };
}

#[tokio::test(start_paused = true)]
async fn evict_idle_after_evicts_once_the_checkout_waited() {
    let after = Duration::from_millis(100);
    let (pool, busy) = full_pool(SaturationPolicy::EvictIdleAfter(after)).await;
    let mut warm = checkout(&pool, 1);
    assert!(
        warm.poll().is_pending(),
        "id 1 waits for its own connection first"
    );
    tokio::time::advance(after / 2).await;
    assert!(!warm.is_woken());
    tokio::time::advance(after).await;
    assert!(warm.is_woken(), "its patience ran out");
    assert!(matches!(
        warm.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    assert!(
        !pool.storage.lock().by_id.contains_key(&TestId(0)),
        "id 0's idle connection went"
    );
    drop(busy);
}

#[tokio::test]
async fn the_default_policy_evicts_for_a_cold_checkout_at_once() {
    let (pool, busy) = full_pool(SaturationPolicy::default()).await;
    assert!(matches!(
        checkout(&pool, 2).poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
    drop(busy);
}

/// A pool of one connection per id, holding a key 1 connection of id 0.
async fn keyed_per_id_pool() -> (
    MultiplexPool<Conn, TestId>,
    MultiplexedConnection<Conn, TestId>,
) {
    let pool = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle);
    let input = want(1);
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(0), &input, None).await.unwrap()
    else {
        panic!("a create permit");
    };
    let conn = Conn {
        serial: 0,
        extensions: Extensions::new(),
    };
    conn.extensions.insert(keyed(0, 1));
    conn.extensions.insert(ConnectionHealthWatcher::default());
    let held = pool.create(TestId(0), conn, slot, &input).await.unwrap();
    (pool, held)
}

#[tokio::test]
async fn an_idle_connection_of_another_key_gives_up_its_id_slot() {
    let (pool, held) = keyed_per_id_pool().await;
    drop(held);
    let input = want(2);
    let mut other_key = tokio_test::task::spawn(pool.get_conn(&TestId(0), &input, None));
    assert!(
        matches!(
            other_key.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ),
        "an idle connection nobody can use does not keep its id's only slot"
    );
}

#[tokio::test]
async fn a_broken_connection_of_another_key_wakes_a_checkout_at_its_id_limit() {
    let (pool, held) = keyed_per_id_pool().await;
    let health = held
        .extensions()
        .get_arc::<ConnectionHealthWatcher>()
        .unwrap();
    let input = want(2);
    let mut other_key = queue(&pool, &input);
    health.mark_broken();
    assert!(other_key.is_woken());
    drop(held);
    assert!(matches!(
        other_key.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

fn per_id_total(total: usize, policy: SaturationPolicy) -> MultiplexPool<Conn, TestId> {
    MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(total).unwrap())
        .with_saturation_policy(policy)
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
}

#[tokio::test]
async fn a_checkout_at_its_id_limit_evicts_no_other_id() {
    let pool = per_id_total(2, SaturationPolicy::EvictIdle);
    let busy = fresh(&pool, 0).await;
    drop(fresh(&pool, 1).await);
    let mut same = checkout(&pool, 0);
    assert!(same.poll().is_pending(), "id 0 is at its limit");
    assert!(
        pool.storage.lock().by_id.contains_key(&TestId(1)),
        "a total slot is of no use to a checkout without an id slot"
    );
    drop((same, busy));
}

#[tokio::test]
async fn a_taken_id_slot_is_kept_across_looks() {
    let pool = per_id_total(1, SaturationPolicy::EvictIdle);
    let busy = fresh(&pool, 0).await;
    let mut first = checkout(&pool, 1);
    assert!(first.poll().is_pending());
    let mut second = checkout(&pool, 1);
    assert!(second.poll().is_pending());
    // A look for another reason.
    pool.notify.notify_waiters();
    assert!(first.poll().is_pending());
    assert!(second.poll().is_pending());
    drop(busy);
    assert!(
        first.is_woken()
            && matches!(
                first.poll(),
                Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
            ),
        "the older checkout kept its id slot and its place for the total slot"
    );
    drop(second);
}

#[tokio::test]
async fn forgetting_unused_id_limits_never_forgets_a_held_one() {
    let pool = MultiplexPool::new().with_max_connections_per_id(NonZeroUsize::new(1).unwrap());
    let keep = fresh(&pool, 0).await;
    for id in 1..300 {
        drop(fresh(&pool, id).await);
        pool.storage.lock().by_id.retain(|id, _| *id == TestId(0));
    }
    let mut second = checkout(&pool, 0);
    assert!(
        second.poll().is_pending(),
        "id 0 is at its limit of one connection"
    );
    drop((second, keep));
}

#[tokio::test]
async fn a_checkout_that_may_no_longer_evict_leaves_the_slot_queue() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(3).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdleWhenCold);
    let a0 = add(&pool, 0, None).await;
    let b = add(&pool, 2, None).await;
    let permit = pool.test_slot();
    // Both cold: they queue for eviction chances, w first.
    let mut w = checkout(&pool, 1);
    assert!(w.poll().is_pending());
    let mut y = checkout(&pool, 3);
    assert!(y.poll().is_pending());
    assert_eq!(pool.slot_waiters.len(), 2);
    // Id 1 gets a (busy) connection: w is warm now and waits for it.
    let conn = Conn {
        serial: 9,
        extensions: Extensions::new(),
    };
    let c1 = pool
        .create(TestId(1), conn, permit, &EMPTY_INPUT)
        .await
        .unwrap();
    assert!(w.is_woken());
    assert!(w.poll().is_pending(), "warm: no eviction");
    drop(a0);
    assert!(
        y.is_woken() && matches!(y.poll(), Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))),
        "the cold checkout evicts the idle connection"
    );
    drop((w, b, c1));
}

#[tokio::test]
async fn a_slot_through_the_semaphore_comes_with_the_id_slot() {
    let pool = per_id_total(1, SaturationPolicy::Wait);
    let busy = fresh(&pool, 0).await;
    let mut first = checkout(&pool, 1);
    assert!(first.poll().is_pending());
    // The busy connection breaks and goes: its slot passes the semaphore.
    busy.inner
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    pool.storage.lock().by_id.clear();
    drop(busy);
    assert!(first.is_woken());
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = first.poll() else {
        panic!("the freed slot goes to the waiter");
    };
    assert!(slot.id.is_some(), "the create permit carries the id's slot");
    let mut second = checkout(&pool, 1);
    assert!(second.poll().is_pending(), "id 1 is at its limit");
    drop((slot, second));
}

#[tokio::test]
async fn releasing_a_connection_of_another_key_wakes_a_checkout_at_its_id_limit() {
    let (pool, held) = keyed_per_id_pool().await;
    let input = want(2);
    let mut other_key = queue(&pool, &input);
    drop(held);
    assert!(
        other_key.is_woken(),
        "the idle connection nobody else waits for is a chance to replace it"
    );
    assert!(matches!(
        other_key.poll(),
        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
    ));
}

#[tokio::test]
async fn a_checkout_the_policy_keeps_from_evicting_never_replaces_within_its_id() {
    // Wait never evicts; a warm checkout waits for its own connection.
    for (policy, own_key) in [
        (SaturationPolicy::Wait, 3),
        (SaturationPolicy::EvictIdleWhenCold, 2),
    ] {
        let pool = per_id(2).with_saturation_policy(policy);
        drop(fresh_keyed(&pool, 0, 1).await);
        let busy = fresh_keyed(&pool, 0, own_key).await;
        let input = want(2);
        let waiting = queue_keyed(&pool, 0, &input);
        drop((waiting, busy));
    }
}

#[tokio::test]
async fn a_replacement_takes_over_the_total_slot_too() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::EvictIdle);
    drop(fresh_keyed(&pool, 0, 1).await);
    let busy = fresh(&pool, 1).await;
    let input = want(2);
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(0), &input, None).await.unwrap()
    else {
        panic!("it replaces the idle connection of the other key");
    };
    assert!(slot.total.is_some() && slot.id.is_some());
    assert_eq!(pool.free_slots(), 0, "the total limit holds");
    drop((slot, busy));
}

#[tokio::test(start_paused = true)]
async fn a_warm_checkout_at_its_id_limit_replaces_once_its_patience_ran_out() {
    let after = Duration::from_millis(100);
    let pool = per_id(2).with_saturation_policy(SaturationPolicy::EvictIdleAfter(after));
    drop(fresh_keyed(&pool, 0, 1).await);
    let busy = fresh_keyed(&pool, 0, 2).await;
    let input = want(2);
    let mut warm = queue_keyed(&pool, 0, &input);
    tokio::time::advance(after).await;
    assert!(warm.is_woken(), "its patience ran out");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = warm.poll() else {
        panic!("it replaces the idle connection of the other key");
    };
    drop((slot, busy));
}

#[tokio::test]
async fn forgetting_unused_id_limits_never_forgets_one_a_create_permit_holds() {
    let pool = per_id(1);
    let ConnectionResult::CreatePermit(slot) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap()
    else {
        panic!("a create permit");
    };
    for id in 1..300 {
        drop(fresh(&pool, id).await);
        pool.storage.lock().by_id.clear();
    }
    let mut second = checkout(&pool, 0);
    assert!(
        second.poll().is_pending(),
        "the create permit holds id 0's only slot"
    );
    drop((second, slot));
}

#[tokio::test(start_paused = true)]
async fn a_checkout_waiting_at_a_limit_is_woken_once_an_idle_connection_expires() {
    let timeout = Duration::from_millis(30);
    let total = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_idle_timeout(timeout);
    let per_id = MultiplexPool::new()
        .with_max_connections_per_id(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_idle_timeout(timeout);
    // Nothing else wakes a checkout that may not evict: of another id, or key.
    for (pool, id) in [(total, 1), (per_id, 0)] {
        drop(fresh_keyed(&pool, 0, 1).await);
        let input = want(2);
        let mut waiting = queue_keyed(&pool, id, &input);
        tokio::time::sleep(timeout).await;
        assert!(waiting.is_woken(), "the idle connection expired");
        let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = waiting.poll() else {
            panic!("its slot is free once it expired")
        };
        drop(slot);
    }
}

#[tokio::test(start_paused = true)]
async fn a_connection_going_idle_while_a_checkout_waits_wakes_it_once_expired() {
    let timeout = Duration::from_millis(30);
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(1).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_idle_timeout(timeout);
    let held = fresh(&pool, 0).await;
    let mut waiting = checkout(&pool, 1);
    assert!(waiting.poll().is_pending());
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(held);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(waiting.is_woken(), "it looks again within the timeout");
    assert!(waiting.poll().is_pending(), "idle for 20ms of 30ms");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(waiting.is_woken(), "and once that connection expires");
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = waiting.poll() else {
        panic!("its slot is free once it expired")
    };
    drop(slot);
}

/// Exclusive connections of `ids`, released oldest first, a millisecond apart.
async fn idle_in_order(pool: &MultiplexPool<Conn, TestId>, ids: &[u32]) {
    let mut held = Vec::new();
    for id in ids {
        held.push(fresh(pool, *id).await);
    }
    for conn in held {
        drop(conn);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
}

/// The ids and serials of the stored connections, in creation order.
fn stored(pool: &MultiplexPool<Conn, TestId>) -> Vec<(u32, u64)> {
    let storage = pool.storage.lock();
    let mut stored: Vec<_> = storage
        .by_id
        .values()
        .flat_map(|bucket| bucket.conns())
        .map(|conn| (conn.id.0, conn.seq))
        .collect();
    stored.sort_unstable_by_key(|(_, seq)| *seq);
    stored
}

#[tokio::test(start_paused = true)]
async fn idle_connections_over_the_per_id_limit_close_least_recently_used_first() {
    let pool = MultiplexPool::new().with_max_idle_per_id(NonZeroUsize::new(2).unwrap());
    idle_in_order(&pool, &[0, 0, 0, 0, 1, 1]).await;
    assert_eq!(stored(&pool), [(0, 2), (0, 3), (1, 4), (1, 5)]);
}

#[tokio::test(start_paused = true)]
async fn idle_connections_over_the_total_limit_close_across_ids() {
    let pool = MultiplexPool::new().with_max_idle_total(NonZeroUsize::new(2).unwrap());
    idle_in_order(&pool, &[0, 1, 2, 3]).await;
    assert_eq!(stored(&pool), [(2, 2), (3, 3)]);
    // A reused connection is no longer idle: two more fit.
    let Ok(ConnectionResult::Connection(reused)) =
        pool.get_conn(&TestId(2), &EMPTY_INPUT, None).await
    else {
        panic!("its idle connection is reused");
    };
    drop(reused);
    assert_eq!(stored(&pool).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn idle_limits_close_nothing_while_checkouts_wait() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_max_idle_total(NonZeroUsize::new(1).unwrap());
    let held = [fresh(&pool, 0).await, fresh(&pool, 1).await];
    let mut waiting = checkout(&pool, 2);
    assert!(waiting.poll().is_pending());
    drop(held);
    assert_eq!(
        stored(&pool).len(),
        2,
        "what is idle now may serve a waiter"
    );
    drop(waiting);
    assert_eq!(stored(&pool).len(), 1, "trimmed once the last waiter left");
}

#[tokio::test(start_paused = true)]
async fn a_connection_in_use_is_not_counted_idle() {
    let pool = MultiplexPool::new().with_max_idle_total(NonZeroUsize::new(1).unwrap());
    drop(fresh(&pool, 0).await);
    let Ok(ConnectionResult::Connection(reused)) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
    else {
        panic!("its idle connection is reused");
    };
    drop(fresh(&pool, 1).await);
    assert_eq!(stored(&pool).len(), 2, "one is in use, one idle");
    drop(reused);
}

#[tokio::test(start_paused = true)]
async fn a_connection_that_is_not_stored_is_not_counted_idle() {
    let pool = MultiplexPool::new().with_max_idle_total(NonZeroUsize::new(1).unwrap());
    // Never stored, then stored and taken out while in use.
    drop(fresh(&pool, u32::MAX).await);
    let broken = fresh(&pool, 1).await;
    broken
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    let mut swept = Swept::default();
    pool.sweep_all(&mut pool.storage.lock(), &mut swept);
    pool.settle(swept);
    drop(broken);
    drop(fresh(&pool, 0).await);
    let Ok(ConnectionResult::Connection(reused)) =
        pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
    else {
        panic!("the only idle connection stays within the limit");
    };
    drop(reused);
}

#[tokio::test(start_paused = true)]
async fn a_checkout_at_its_id_limit_is_woken_at_the_first_expiry_its_ids_sweep_saw() {
    let timeout = Duration::from_millis(30);
    let pool = per_id(1)
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_idle_timeout(timeout);
    drop(fresh_keyed(&pool, 0, 1).await);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let input = want(2);
    let mut waiting = queue_keyed(&pool, 0, &input);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        waiting.is_woken(),
        "the idle connection expires 30ms after it went idle, not after the look"
    );
    let Poll::Ready(Ok(ConnectionResult::CreatePermit(slot))) = waiting.poll() else {
        panic!("its slot is free once it expired")
    };
    drop(slot);
}

/// A pool keeping one idle connection, of 8 at most.
fn keeping_one() -> MultiplexPool<Conn, TestId> {
    MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_max_idle_total(NonZeroUsize::new(1).unwrap())
}

/// A connection of `id` whose handout is gone while work outlives it.
async fn outlived(pool: &MultiplexPool<Conn, TestId>, id: u32) -> Arc<AdmissionState> {
    let (conn, state) = admission_connection(pool, 4);
    let handout = pool
        .create(TestId(id), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    state.set_in_use(true);
    drop(handout);
    state
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[test]
fn work_ending_on_a_thread_without_a_runtime_is_trimmed_on_the_pools() {
    let runtime = current_thread();
    let pool = keeping_one();
    let states = runtime.block_on(async {
        [
            outlived(&pool, 0).await,
            outlived(&pool, 1).await,
            outlived(&pool, 2).await,
        ]
    });
    std::thread::spawn(move || {
        for state in states {
            state.set_in_use(false);
        }
    })
    .join()
    .unwrap();
    runtime.block_on(settle());
    assert_eq!(
        pool.storage.lock().by_id.len(),
        1,
        "one idle connection kept"
    );
}

#[test]
fn a_trim_whose_runtime_went_away_leaves_trims_to_the_next() {
    let pool = keeping_one();
    let runtime = current_thread();
    runtime.block_on(async {
        let [first, second] = [outlived(&pool, 0).await, outlived(&pool, 1).await];
        first.set_in_use(false);
        second.set_in_use(false);
    });
    // The trim's task never ran.
    drop(runtime);
    current_thread().block_on(async {
        outlived(&pool, 2).await.set_in_use(false);
        settle().await;
    });
    assert_eq!(
        pool.storage.lock().by_id.len(),
        1,
        "one idle connection kept"
    );
}

#[test]
fn a_trim_asked_for_while_one_runs_is_left_to_it() {
    let limits = IdleLimits::<TestId>::new(None, NonZeroUsize::new(1)).unwrap();
    limits.ask(Some(&TestId(0)));
    let hold = limits.hold().expect("nobody trims");
    for _ in 0..2 {
        assert!(
            limits.hold().is_none(),
            "one trimmer at a time, however many try"
        );
    }
    assert!(limits.take().ids.contains(&TestId(0)));
    // Asked as the trimmer finishes its last look, before it lets go.
    limits.ask(Some(&TestId(2)));
    drop(hold);
    assert!(!limits.nothing_asked(), "it looks again");
    let hold = limits.hold().expect("let go");
    assert!(limits.take().ids.contains(&TestId(2)));
    drop(hold);
    assert!(limits.nothing_asked());
    limits.ask(None);
    assert!(limits.take().all);
}

#[test]
fn a_trimmer_unwinding_lets_go() {
    let limits = IdleLimits::<TestId>::new(None, NonZeroUsize::new(1)).unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _hold = limits.hold();
        panic!("an admission panicked");
    }));
    assert!(unwound.is_err());
    assert!(limits.hold().is_some(), "the next asker trims");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_connections_going_idle_at_once_keep_exactly_the_limit() {
    for _ in 0..20 {
        let pool = keeping_one();
        let mut states = Vec::new();
        for id in 0..6 {
            states.push(outlived(&pool, id).await);
        }
        let ends: Vec<_> = states
            .into_iter()
            .map(|state| tokio::spawn(async move { state.set_in_use(false) }))
            .collect();
        for end in ends {
            end.await.unwrap();
        }
        for _ in 0..100 {
            if pool.storage.lock().by_id.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            pool.storage.lock().by_id.len(),
            1,
            "neither over nor under the limit"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_change_of_a_busy_connection_does_not_count_it_idle() {
    let pool = keeping_one();
    drop(fresh(&pool, 0).await);
    tokio::time::advance(Duration::from_millis(1)).await;
    let tunnel = outlived(&pool, 1).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    // Another of its streams ends while its work goes on.
    tunnel.changed.notify(Change::Freed);
    settle().await;
    assert_eq!(stored(&pool).len(), 2, "one idle, one busy");
    tunnel.set_in_use(false);
    settle().await;
    assert_eq!(stored(&pool), [(1, 1)], "the least recently idle closes");
}

/// The binding of [`AdmittingOnAsk`]'s leases.
#[derive(Debug, Extension)]
struct AskToken;

/// An admission that runs `on_ask` once, as it is asked about outliving work.
struct AdmittingOnAsk(Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>);

impl std::fmt::Debug for AdmittingOnAsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmittingOnAsk")
    }
}

impl ConnectionAdmissionPolicy for AdmittingOnAsk {
    fn try_acquire(&self, _: &Extensions) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), AskToken)))
    }

    fn subscribe(&self, _: Weak<dyn ChangeListener>) {}

    fn in_use(&self) -> bool {
        let on_ask = self.0.lock().take();
        if let Some(on_ask) = on_ask {
            on_ask();
        }
        false
    }
}

#[tokio::test(start_paused = true)]
async fn a_stream_admitted_as_its_release_counts_it_keeps_it_uncounted() {
    let pool = keeping_one();
    drop(fresh(&pool, 1).await);
    tokio::time::advance(Duration::from_millis(1)).await;
    let on_ask = Arc::new(Mutex::new(None));
    let conn = Conn {
        serial: 7,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(AdmittingOnAsk(on_ask.clone())));
    let shared = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    let admitted = Arc::new(Mutex::new(None));
    {
        let (pool, admitted) = (pool.clone(), admitted.clone());
        // Between the release's idle check and its count.
        *on_ask.lock() = Some(Box::new(move || {
            let mut checkout = tokio_test::task::spawn(Box::pin(async move {
                pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
            }));
            let Poll::Ready(Ok(ConnectionResult::Connection(conn))) = checkout.poll() else {
                panic!("the shared connection admits it");
            };
            *admitted.lock() = Some(conn);
        }) as Box<dyn FnOnce() + Send>);
    }
    drop(shared);
    assert!(admitted.lock().is_some());
    assert_eq!(stored(&pool).len(), 2, "the busy one is not counted idle");
    drop(admitted.lock().take());
}

#[tokio::test(start_paused = true)]
async fn a_connection_retired_by_another_is_not_counted_against_its_id() {
    let pool = MultiplexPool::new().with_max_idle_per_id(NonZeroUsize::new(3).unwrap());
    let [a, b, c, d] = [
        fresh(&pool, 0).await,
        fresh(&pool, 0).await,
        fresh(&pool, 0).await,
        fresh(&pool, 0).await,
    ];
    let c_stored = c.inner.clone();
    for conn in [a, b, c] {
        drop(conn);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    // Another party retired it, and takes it out of storage next.
    drop(c_stored.retire_if(StoredConnection::is_idle).expect("idle"));
    drop(d);
    drop(unstore(&mut pool.storage.lock(), &c_stored));
    assert_eq!(stored(&pool).len(), 3, "three idle fit the limit of three");
}

#[tokio::test(start_paused = true)]
async fn an_idle_connection_taken_out_broken_is_no_longer_counted() {
    let pool = keeping_one();
    let gone = fresh(&pool, 0).await;
    let broken = gone.inner.clone();
    drop(gone);
    broken
        .conn
        .extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .unwrap()
        .mark_broken();
    // A look sweeps it out.
    drop(pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap());
    drop(broken);
    drop(fresh(&pool, 1).await);
    assert_eq!(stored(&pool), [(1, 1)], "the one idle connection fits");
}

#[tokio::test(start_paused = true)]
async fn outliving_work_ending_trims_over_the_per_id_limit() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_max_idle_per_id(NonZeroUsize::new(1).unwrap());
    let tunnels = [outlived(&pool, 0).await, outlived(&pool, 0).await];
    for tunnel in &tunnels {
        tunnel.set_in_use(false);
    }
    settle().await;
    assert_eq!(stored(&pool).len(), 1, "one idle connection of the id kept");
}

#[tokio::test(start_paused = true)]
async fn the_last_waiter_leaving_trims_over_the_per_id_limit() {
    let pool = MultiplexPool::new()
        .with_max_streams_per_connection(NonZeroUsize::new(1).unwrap())
        .with_max_connections_total(NonZeroUsize::new(2).unwrap())
        .with_saturation_policy(SaturationPolicy::Wait)
        .with_max_idle_per_id(NonZeroUsize::new(1).unwrap());
    let held = [fresh(&pool, 0).await, fresh(&pool, 0).await];
    let mut waiting = checkout(&pool, 1);
    assert!(waiting.poll().is_pending());
    drop(held);
    assert_eq!(
        stored(&pool).len(),
        2,
        "what is idle now may serve a waiter"
    );
    drop(waiting);
    assert_eq!(stored(&pool).len(), 1, "trimmed once the last waiter left");
}

#[tokio::test(start_paused = true)]
async fn a_counted_connection_found_busy_is_kept_and_not_counted() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_max_idle_per_id(NonZeroUsize::new(1).unwrap());
    let (conn, older) = admission_connection(&pool, 4);
    conn.extensions.insert(keyed(0, 1));
    let handout = pool
        .create(TestId(0), conn, pool.test_slot(), &want(1))
        .await
        .unwrap();
    drop(handout);
    tokio::time::advance(Duration::from_millis(1)).await;
    // Its work outlives it from now on, unannounced: still counted idle.
    older.in_use.store(true, Ordering::SeqCst);
    drop(fresh_keyed(&pool, 0, 2).await);
    assert_eq!(
        stored(&pool).len(),
        2,
        "the busy one is kept, the idle one fits"
    );
}

/// Two idle connections of `ids`, counted without a trim, in a pool limiting
/// idle connections with `limited`.
async fn two_counted_idle(
    limited: fn(MultiplexPool<Conn, TestId>) -> MultiplexPool<Conn, TestId>,
    ids: [u32; 2],
) -> (
    MultiplexPool<Conn, TestId>,
    [Arc<StoredConnection<Conn, TestId>>; 2],
) {
    let pool =
        limited(MultiplexPool::new().with_max_connections_total(NonZeroUsize::new(8).unwrap()));
    let mut stored = Vec::new();
    for id in ids {
        let (conn, state) = admission_connection(&pool, 4);
        let handout = pool
            .create(TestId(id), conn, pool.test_slot(), &EMPTY_INPUT)
            .await
            .unwrap();
        // Work outlives the handout: its release counts nothing.
        state.in_use.store(true, Ordering::SeqCst);
        let inner = handout.inner.clone();
        drop(handout);
        // It ends: a change of its source, without the listener's trim.
        state.in_use.store(false, Ordering::SeqCst);
        inner.changes.fetch_add(1, Ordering::Release);
        stored.push(inner);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    for conn in &stored {
        assert!(conn.count_if_idle(), "counted as a trim does");
    }
    (pool, stored.try_into().ok().unwrap())
}

#[tokio::test(start_paused = true)]
async fn a_trim_closes_nothing_another_brought_within_the_total_limit() {
    let (pool, [picked, other]) = two_counted_idle(
        |pool| pool.with_max_idle_total(NonZeroUsize::new(1).unwrap()),
        [0, 1],
    )
    .await;
    // The trim picked one while two were idle; another party then closed the other.
    drop(other.retire_if(StoredConnection::is_idle).expect("idle"));
    assert!(
        picked
            .retire_if(|conn| conn.is_idle() && conn.take_excess(Excess::Total))
            .is_none(),
        "within the limit at the commit: kept"
    );
    assert!(picked.is_counted_idle());
    drop(pool);
}

#[tokio::test(start_paused = true)]
async fn a_trim_closes_nothing_another_brought_within_the_per_id_limit() {
    let (pool, [picked, other]) = two_counted_idle(
        |pool| pool.with_max_idle_per_id(NonZeroUsize::new(1).unwrap()),
        [0, 0],
    )
    .await;
    drop(other.retire_if(StoredConnection::is_idle).expect("idle"));
    assert!(
        picked
            .retire_if(|conn| conn.is_idle() && conn.take_excess(Excess::PerId))
            .is_none(),
        "within the limit at the commit: kept"
    );
    assert!(picked.is_counted_idle());
    drop(pool);
}

#[test]
fn inline_trims_run_while_a_trim_task_waits_on_a_parked_runtime() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(16).unwrap())
        .with_max_idle_total(NonZeroUsize::new(1).unwrap());
    let parked = current_thread();
    parked.block_on(async {
        let tunnels = [outlived(&pool, 0).await, outlived(&pool, 1).await];
        // Their listeners schedule a trim on this runtime, which then parks.
        for tunnel in &tunnels {
            tunnel.set_in_use(false);
        }
    });
    current_thread().block_on(async {
        for id in 2..6 {
            drop(fresh(&pool, id).await);
        }
        settle().await;
    });
    assert_eq!(stored(&pool).len(), 1, "each release trimmed");
    parked.block_on(settle());
    assert_eq!(stored(&pool).len(), 1);
}

#[tokio::test]
async fn a_listener_asks_no_admission_with_idle_limits() {
    let pool = keeping_one();
    let tunnels = [outlived(&pool, 0).await, outlived(&pool, 1).await];
    tunnels[0].set_in_use(false);
    let asked = |tunnels: &[Arc<AdmissionState>; 2]| {
        tunnels
            .each_ref()
            .map(|tunnel| tunnel.asked.load(Ordering::SeqCst))
    };
    let before = asked(&tunnels);
    tunnels[1].set_in_use(false);
    assert_eq!(asked(&tunnels), before, "a listener asks no source");
    settle().await;
    assert_eq!(stored(&pool).len(), 1, "its task trimmed");
}

#[tokio::test(start_paused = true)]
async fn a_commit_on_a_connection_no_longer_counted_gives_its_unit_back() {
    let (pool, [picked, _other]) = two_counted_idle(
        |pool| pool.with_max_idle_total(NonZeroUsize::new(1).unwrap()),
        [0, 1],
    )
    .await;
    // Taken out of the counts by someone else, its unit on its way out.
    picked
        .idle_count
        .store(connection::UNCOUNTED, Ordering::Release);
    assert!(!picked.take_excess(Excess::Total));
    let limits = pool.idle_limits.as_ref().unwrap();
    assert_eq!(
        limits.idle.load(Ordering::Relaxed),
        2,
        "the unit it took, given back"
    );
}

#[tokio::test(start_paused = true)]
async fn a_commit_takes_its_unit_out_of_both_counts() {
    let (pool, [picked, _other]) = two_counted_idle(
        |pool| {
            pool.with_max_idle_per_id(NonZeroUsize::new(1).unwrap())
                .with_max_idle_total(NonZeroUsize::new(8).unwrap())
        },
        [0, 0],
    )
    .await;
    assert!(picked.take_excess(Excess::PerId));
    let limits = pool.idle_limits.as_ref().unwrap();
    assert_eq!(limits.idle.load(Ordering::Relaxed), 1, "the total too");
    assert_eq!(picked.id_idle.as_ref().unwrap().load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn a_per_id_commit_reads_its_ids_count() {
    let (_pool, [picked, _other]) = two_counted_idle(
        |pool| pool.with_max_idle_per_id(NonZeroUsize::new(1).unwrap()),
        [0, 1],
    )
    .await;
    assert!(
        !picked.take_excess(Excess::PerId),
        "one idle of its id: within the per-id limit"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connection_its_admission_retires_is_no_longer_counted() {
    let pool = keeping_one();
    let (conn, state) = admission_connection(&pool, 4);
    let handout = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    let stored = handout.inner.clone();
    drop(handout);
    let limits = pool.idle_limits.as_ref().unwrap();
    assert_eq!(limits.idle.load(Ordering::Relaxed), 1);
    state.failed.store(true, Ordering::SeqCst);
    let lane_gen = stored.lane_gen.load(Ordering::Acquire);
    assert!(
        stored
            .try_admit(lane_gen, usize::MAX, &EMPTY_INPUT)
            .is_none()
    );
    assert_eq!(
        limits.idle.load(Ordering::Relaxed),
        0,
        "retired: not counted"
    );
}

#[test]
fn a_count_a_connection_holds_is_never_forgotten() {
    let limits = IdleLimits::<TestId>::new(NonZeroUsize::new(1), None).unwrap();
    let held = limits.id_counter(&TestId(0)).unwrap();
    for id in 1..100 {
        drop(limits.id_counter(&TestId(id)));
    }
    assert!(Arc::ptr_eq(&held, &limits.id_counter(&TestId(0)).unwrap()));
}

#[tokio::test(start_paused = true)]
async fn an_idle_timeout_beyond_the_nanoseconds_of_a_u64_is_no_expiry() {
    let pool = MultiplexPool::new().with_idle_timeout(Duration::from_secs(18_446_744_074));
    drop(fresh(&pool, 0).await);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await.unwrap(),
            ConnectionResult::Connection(_)
        ),
        "still idle, not expired"
    );
}

#[test]
fn a_trim_task_queued_on_a_parked_runtime_holds_no_ask_of_another() {
    let pool = keeping_one();
    let parked = current_thread();
    parked.block_on(async {
        // Its listener schedules a trim on this runtime, which then parks.
        outlived(&pool, 0).await.set_in_use(false);
    });
    let live = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap();
    live.block_on(async {
        for id in 1..3 {
            outlived(&pool, id).await.set_in_use(false);
        }
        for _ in 0..200 {
            if stored(&pool).len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    assert_eq!(stored(&pool).len(), 1, "trimmed on the live runtime");
}

#[test]
fn asks_without_a_runtime_queue_one_task_on_the_pools() {
    let pool = keeping_one();
    let parked = current_thread();
    let tunnel = parked.block_on(outlived(&pool, 0));
    let limits = pool.idle_limits.as_ref().unwrap();
    let held = Arc::strong_count(limits);
    // From a plain thread: the tasks go to the parked runtime of the newest connection.
    std::thread::spawn(move || {
        for _ in 0..200 {
            tunnel.changed.notify(Change::Freed);
        }
    })
    .join()
    .unwrap();
    assert!(
        Arc::strong_count(limits) <= held + 1,
        "one task on its way, not one per ask"
    );
    drop(parked);
}

/// An admission whose answer about outliving work is the one from before
/// `on_ask` runs: a stream comes and goes while it is asked.
struct UpgradingOnAsk {
    on_ask: Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>,
    in_use: Arc<AtomicBool>,
}

impl std::fmt::Debug for UpgradingOnAsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpgradingOnAsk")
    }
}

impl ConnectionAdmissionPolicy for UpgradingOnAsk {
    fn try_acquire(&self, _: &Extensions) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), AskToken)))
    }

    fn subscribe(&self, _: Weak<dyn ChangeListener>) {}

    fn in_use(&self) -> bool {
        let answer = self.in_use.load(Ordering::SeqCst);
        let on_ask = self.on_ask.lock().take();
        if let Some(on_ask) = on_ask {
            on_ask();
        }
        answer
    }
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_came_and_went_as_its_release_asked_keeps_it_uncounted() {
    let pool = keeping_one();
    drop(fresh(&pool, 1).await);
    tokio::time::advance(Duration::from_millis(1)).await;
    let (on_ask, in_use) = (Arc::new(Mutex::new(None)), Arc::new(AtomicBool::new(false)));
    let conn = Conn {
        serial: 7,
        extensions: Extensions::new(),
    };
    conn.extensions
        .insert(ConnectionAdmission::new(UpgradingOnAsk {
            on_ask: on_ask.clone(),
            in_use: in_use.clone(),
        }));
    let shared = pool
        .create(TestId(0), conn, pool.test_slot(), &EMPTY_INPUT)
        .await
        .unwrap();
    {
        let pool = pool.clone();
        // Between the release's answer and its count: a stream whose work
        // outlives it (an upgrade), released.
        *on_ask.lock() = Some(Box::new(move || {
            let mut checkout = tokio_test::task::spawn(Box::pin(async move {
                pool.get_conn(&TestId(0), &EMPTY_INPUT, None).await
            }));
            let Poll::Ready(Ok(ConnectionResult::Connection(upgraded))) = checkout.poll() else {
                panic!("the shared connection admits it");
            };
            in_use.store(true, Ordering::SeqCst);
            drop(upgraded);
        }) as Box<dyn FnOnce() + Send>);
    }
    drop(shared);
    assert_eq!(stored(&pool).len(), 2, "the busy one is not counted idle");
}

#[tokio::test(start_paused = true)]
async fn a_connection_rekeyed_with_a_stream_takes_no_unit_with_it() {
    let pool = MultiplexPool::new()
        .with_max_connections_total(NonZeroUsize::new(8).unwrap())
        .with_max_idle_total(NonZeroUsize::new(8).unwrap());
    let handout = add(&pool, 0, Some(keyed(0, 1))).await;
    handout.rekey(keyed(0, 2));
    drop(handout);
    let limits = pool.idle_limits.as_ref().unwrap();
    assert_eq!(limits.idle.load(Ordering::Relaxed), 1, "counted once idle");
}

#[tokio::test(start_paused = true)]
async fn a_retired_connection_is_not_filed_again_by_a_rekey() {
    let pool = MultiplexPool::new().with_max_connections_total(NonZeroUsize::new(8).unwrap());
    let handout = add(&pool, 0, Some(keyed(0, 1))).await;
    handout.inner.retire();
    handout.rekey(keyed(0, 2));
    assert!(stored(&pool).is_empty(), "on its way out");
}
