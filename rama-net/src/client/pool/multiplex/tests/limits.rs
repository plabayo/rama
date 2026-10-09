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
    let Ok(ConnectionResult::Connection(_)) = pool.get_conn(&TestId(0), &EMPTY_INPUT).await else {
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
    let ConnectionResult::CreatePermit(slot) = pool.get_conn(&TestId(0), &input).await.unwrap()
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
    let mut other_key = tokio_test::task::spawn(pool.get_conn(&TestId(0), &input));
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
    let ConnectionResult::CreatePermit(slot) = pool.get_conn(&TestId(0), &input).await.unwrap()
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
        pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
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
